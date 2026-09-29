local nmap = require "nmap"
local stdnse = require "stdnse"
local math = require "math"
local table = require "table"

description = [[
Detects MADCAT (Mass Attack Detection Connection Acceptance Tool) TCP sensors.

MADCAT DNATs every TCP port to a single listener that accepts the connection,
never sends data, and drops it with a RST once the peer has been idle for
tcp_connection_timeout seconds (the listening socket sets SO_LINGER {1,0}).
Receiving data restarts that idle timer.

The script checks for exactly that behaviour:
  1. Random high ports are open (DNAT catch-all).
  2. On several ports the server stays silent and resets the connection
     after the same idle time.
  3. Sending data after a delay shifts the reset by that delay.

Expect the script to take about 2 x tcp_connection_timeout + delay seconds.
]]

---
-- @usage
-- nmap -Pn -sn --script madcat-detect <target>
-- nmap -Pn -sn --script madcat-detect --script-args madcat-detect.maxwait=120 <target>
--
-- @args madcat-detect.ports     Number of random high ports to probe (default 3).
-- @args madcat-detect.maxwait   Seconds to wait for the server to close an idle
--                               connection (default 60).
-- @args madcat-detect.delay     Seconds to wait before sending data in the
--                               timer-reset check (default 3).
-- @args madcat-detect.tolerance Allowed deviation between measurements in
--                               seconds (default 0.5).
--
-- @output
-- Host script results:
-- | madcat-detect:
-- |   verdict: likely MADCAT
-- |   all random ports open: 3/3 (41733, 58112, 27945)
-- |   silent idle reset after: 5.01s, 5.01s, 5.01s
-- |   inferred tcp_connection_timeout: 5s
-- |_  reset after sending data at 3s: 8.03s (expected 8.01s)

author = "Tim Winkler"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

hostrule = function(host) return true end

local function arg(name, default)
  return tonumber(stdnse.get_script_args(SCRIPT_NAME .. "." .. name)) or default
end

-- Connect, optionally send data after `delay` seconds, and wait for the
-- server to close. Returns a table describing how and when it closed.
local function probe(host, port, maxwait, delay)
  local r = { port = port }
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then
    r.open = false
    r.err = err
    return r
  end
  r.open = true
  local t0 = nmap.clock_ms()

  if delay then
    -- Wait `delay` seconds; a close in this window already disqualifies.
    sock:set_timeout(delay * 1000)
    local st, data = sock:receive()
    if st or data ~= "TIMEOUT" then
      r.early = true
      r.data = st and data or nil
      r.err = not st and data or nil
      r.elapsed = (nmap.clock_ms() - t0) / 1000
      sock:close()
      return r
    end
    sock:send("GET / HTTP/1.0\r\n\r\n")
  end

  local remaining = maxwait * 1000 - (nmap.clock_ms() - t0)
  sock:set_timeout(math.max(remaining, 1000))
  local st, data = sock:receive()
  r.elapsed = (nmap.clock_ms() - t0) / 1000
  if st then
    r.data = data
  else
    r.err = data
  end
  sock:close()
  return r
end

-- A MADCAT close: no data, and ended by the server (RST shows up as an error
-- other than TIMEOUT; a FIN shows up as EOF).
local function silent_reset(r)
  return r.open and not r.data and r.err and r.err ~= "TIMEOUT" and r.err ~= "EOF"
end

local function fmt(r)
  if not r.open then return "closed" end
  if r.data then return ("sent data (%d bytes)"):format(#r.data) end
  if r.err == "TIMEOUT" then return "no close" end
  return ("%.2fs%s"):format(r.elapsed, r.err == "EOF" and " (FIN)" or "")
end

action = function(host)
  local nports = arg("ports", 3)
  local maxwait = arg("maxwait", 60)
  local delay = arg("delay", 3)
  local tol = arg("tolerance", 0.5)

  local ports, seen = {}, {}
  while #ports < nports + 1 do
    local p = math.random(20000, 65000)
    if not seen[p] then
      seen[p] = true
      ports[#ports + 1] = p
    end
  end

  -- Run all probes in parallel: idle probes on the first `nports` ports,
  -- the send-after-delay probe on the last one.
  local results = {}
  local condvar = nmap.condvar(results)
  local threads = {}
  for i, p in ipairs(ports) do
    local d = (i == #ports) and delay or nil
    local co = stdnse.new_thread(function()
      results[i] = probe(host, p, maxwait + (d or 0), d)
      condvar "signal"
    end)
    threads[co] = true
  end
  repeat
    for co in pairs(threads) do
      if coroutine.status(co) == "dead" then threads[co] = nil end
    end
    if next(threads) then condvar "wait" end
  until not next(threads)

  local idle, shifted = {}, results[#ports]
  for i = 1, nports do idle[i] = results[i] end

  local out = stdnse.output_table()
  local open, open_list, times = 0, {}, {}
  for _, r in ipairs(results) do
    if r.open then
      open = open + 1
      open_list[#open_list + 1] = tostring(r.port)
    end
  end
  for _, r in ipairs(idle) do times[#times + 1] = fmt(r) end

  -- All idle probes must be silent resets with (nearly) the same timing.
  local consistent, tmin, tmax = true, math.huge, 0
  for _, r in ipairs(idle) do
    if not silent_reset(r) then
      consistent = false
    else
      tmin = math.min(tmin, r.elapsed)
      tmax = math.max(tmax, r.elapsed)
    end
  end
  consistent = consistent and (tmax - tmin) <= tol

  local shift_ok = false
  local expected
  if consistent and silent_reset(shifted) and not shifted.early then
    expected = tmin + delay
    shift_ok = math.abs(shifted.elapsed - expected) <= tol
  end

  if open == 0 then
    return nil -- nothing to say about hosts without the catch-all
  end

  if open == #ports and consistent and shift_ok then
    out.verdict = "likely MADCAT"
  elseif open == #ports and consistent then
    out.verdict = "possible MADCAT (idle reset matches, timer-reset check failed)"
  elseif open == #ports then
    out.verdict = "all ports open, but not MADCAT-like idle behaviour"
  else
    out.verdict = "not MADCAT"
  end
  out["all random ports open"] = ("%d/%d (%s)"):format(open, #ports, table.concat(open_list, ", "))
  out["silent idle reset after"] = table.concat(times, ", ")
  if consistent then
    out["inferred tcp_connection_timeout"] = ("%ds"):format(math.floor(tmin + 0.5))
  end
  local shifted_desc = shifted.early and "closed before data was sent" or fmt(shifted)
  if expected then
    shifted_desc = ("%s (expected %.2fs)"):format(shifted_desc, expected)
  end
  out[("reset after sending data at %ds"):format(delay)] = shifted_desc
  return out
end
