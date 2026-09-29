# TODO – Improvement Proposals

Collected while reviewing the code base and testing the TCP sensor inside the devcontainer (2026-09-29).
Items are grouped by theme and roughly ordered by priority within each group.
Status markers: `[ ]` open, `[x]` done.

## 0. Security

- [ ] **Privilege drop keeps supplementary group root (verified at runtime).**
  The C sensors call `setgid()` + `setuid()` but never `setgroups()`, so after the drop the sniffer and
  listener run as `Uid: 999` but still with `Groups: 0` (checked via `/proc/<pid>/status`). Processes that
  parse attacker-controlled packets keep root-group file access. Call `setgroups(0, NULL)` (or
  `initgroups()`) before `setgid()`. The Python processes already do `os.setgroups([])`.
  Code: `drop_root_privs` in [lib/tcp_ip_port_mon.helper.c](lib/tcp_ip_port_mon.helper.c), inline drops in
  [bin/udp_ip_port_mon.c](bin/udp_ip_port_mon.c) and [bin/icmp_mon.c](bin/icmp_mon.c), and raw_mon.

- [ ] **Deduplicate the privilege-drop code.**
  There are at least three copies (TCP helper, UDP and ICMP mains). Move a single, correct implementation
  into [lib/madcat.helper.c](lib/madcat.helper.c) and use it everywhere.

## 1. Robustness / Correctness

- [ ] **TCP sensor stalls when nobody reads its FIFOs.**
  Observed: without a reader on `/tmp/connect_json.tpm` / `/tmp/header_json.tpm`, the sensor stopped
  accepting connections after ~500 flows and left ~385 hung processes. In production this means the
  sensor goes silent whenever `tcp_ip_port_mon_postprocessor.py` dies.
  Root cause not confirmed (no ptrace in the container); most likely blocking `fprintf` on a full pipe.
  Options: open FIFOs `O_NONBLOCK` and drop/count events on `EAGAIN`; have the watchdog detect a
  missing reader; supervise the postprocessor (systemd `Requires=`/`BindsTo=`).
  Code: [bin/tcp_ip_port_mon.c](bin/tcp_ip_port_mon.c) (FIFO setup), [lib/tcp_ip_port_mon.worker.c](lib/tcp_ip_port_mon.worker.c) (output).

- [ ] **Watchdog "deadlock breaker" never fires.**
  It only posts the semaphore when `sem_getvalue` is negative, which Linux never returns (the code's own
  comment says so). The effective protection is the 1 s `sem_timedwait` timeout. Either remove the dead
  code or replace it with a working mechanism.
  Code: [bin/tcp_ip_port_mon.c](bin/tcp_ip_port_mon.c) (watchdog loop, semaphore section).

- [ ] **FIFO paths are defined twice.**
  C hardcodes `HEADER_FIFO` / `CONNECT_FIFO` in [include/tcp_ip_port_mon.helper.h](include/tcp_ip_port_mon.helper.h);
  the postprocessor reads `header_fifo` / `connection_fifo` from `config.lua`. Changing only the config
  silently breaks the pipeline. Make the C side read the same config keys (keeping the defines as defaults).

- [ ] **`json_dict("false")` resets instead of reading the global JSON dict.**
  The string literal `"false"` converts to `bool true`, so `json_dict` frees and recreates the global dict,
  and the following `dict_free` then leaves the static pointer dangling. Harmless today only because the
  process exits right after. Should be `dict_free(json_dict(false))`.
  Code: [bin/tcp_ip_port_mon.c:379](bin/tcp_ip_port_mon.c#L379), [lib/icmp_mon.helper.c:72](lib/icmp_mon.helper.c#L72).
  Compiling with `-Wall -Wextra` in CI would help catch this class of error.

- [ ] **Possible stall in postprocessor with conntrack enabled (to investigate).**
  `output_syn_scans` waits on `ct_syn_dict_evt` while holding `syn_dict_lock`, which blocks
  `build_syn_dict` (and therefore the header FIFO reader) until the conntrack thread updates.
  Code: [bin/tcp_ip_port_mon_postprocessor.py](bin/tcp_ip_port_mon_postprocessor.py) (`output_syn_scans`).

- [ ] **Inconsistent fields between proxied and non-proxied UDP connections.**
  In the proxied branch `start`/`end` are filled with the Unix timestamp string (copied with
  `strlen(log_time)` as length) and `first_dgram_len` is the payload length; in the non-proxied branch
  `start`/`end` are the human-readable time and `first_dgram_len` is the full packet length.
  Code: [lib/udp_ip_port_mon.worker.c](lib/udp_ip_port_mon.worker.c).

- [ ] **Listen backlog of 5 is low for a mass-scan sensor.**
  `listen(listenfd, 5)` in [bin/tcp_ip_port_mon.c](bin/tcp_ip_port_mon.c). Raise it (e.g. `SOMAXCONN`)
  or make it configurable.

- [ ] **Unchecked allocations and hard exits in the UDP worker.**
  `strncpy(malloc(...), ...)` patterns never check `malloc`; socket creation failure calls `exit(1)`
  from inside the worker. See [lib/udp_ip_port_mon.worker.c](lib/udp_ip_port_mon.worker.c).

## 2. Performance

- [ ] **Postprocessor join is O(connections × SYNs) while holding both locks.**
  `output_accepted_con` loops over every SYN key for every connection. The exact-match case can be a
  direct dict lookup (`syn_dict.get(conid)`); only the best-guess path needs a scan (and could use a
  secondary index on `src_ip_destport`).
  Code: [bin/tcp_ip_port_mon_postprocessor.py](bin/tcp_ip_port_mon_postprocessor.py) (`output_accepted_con`).

- [ ] **Enrichment processor spawns one thread per event.**
  Unbounded thread count under load and no ordering guarantee. Use a bounded worker pool
  (`concurrent.futures.ThreadPoolExecutor`) or a queue with a fixed number of workers.
  Code: [bin/enrichment_processor.py](bin/enrichment_processor.py) (`enrich`).

- [ ] **TCP worker busy-polls with `usleep(50000)`.**
  Replace the non-blocking `recv` + sleep loop with `poll()` and a timeout. Lower CPU/latency, and
  removes the 50 ms timing quantization (see section 3).
  Code: [lib/tcp_ip_port_mon.worker.c](lib/tcp_ip_port_mon.worker.c).

## 3. Detectability (sensor fingerprint)

A working detector exists: [tools/nmap/madcat-detect.nse](tools/nmap/madcat-detect.nse). It relies on
all of the following; each item below weakens one part of the signature. Use the script as a
regression check after changes.

- [ ] **RST instead of FIN on idle close.**
  The listening socket sets `SO_LINGER {1,0}`, which accepted sockets inherit, so every idle close is a
  RST. Make it configurable and default to a normal FIN close.
- [ ] **Fixed idle timeout.**
  Every connection closes after exactly `tcp_connection_timeout` (+ ≤50 ms). Add configurable jitter.
- [ ] **Completely silent on every port.**
  Optionally send plausible banners on well-known ports (SSH, SMTP, FTP, …) – also aligns with the
  README's v2 goal of "higher interaction".
- [ ] **Uniform behaviour across all 65534 ports.**
  Consider leaving a random subset of ports closed (per-sensor, stable over time) so a random-port probe
  does not always hit an open port.

## 4. Testing

- [ ] **Unit tests for the packet parsers.**
  Current tests only cover `dict_c` and a few helpers ([tests/](tests/)). Add tests with crafted packets for
  `analyze_ip_header` / `analyze_tcp_header` / UDP / ICMP parsers, including malformed and truncated input.
- [ ] **Fuzz the parsers, not just `dict_c`.**
  [fuzzing/fuzz_example.cpp](fuzzing/fuzz_example.cpp) only exercises `dict_update`. The parsers handle
  attacker-controlled bytes and are the more valuable fuzz target.
- [ ] **Tests for the postprocessor join logic.**
  Feed recorded header/connection JSON and assert `flow` / `no_syn` / `syn_scan` output, including
  timing edge cases and best-guess mode.
- [ ] **End-to-end smoke test in the devcontainer.**
  Script that brings up the full pipeline (local config on `lo`, `OUTPUT` DNAT rule, all processes),
  runs `nmap -sS` and `nc`, and checks `madcat.log` for `syn_scan` and `flow` events.
  Could run `madcat-detect.nse` as part of it.

## 5. Tooling / Dev environment

- [ ] **Merge the devcontainer** (`feature/devcontainer` branch).
- [ ] **Add `SYS_PTRACE` to the devcontainer `runArgs`** so `gdb -p` / `strace -p` work on hung processes
  (was needed while debugging the FIFO stall).
- [ ] **Container-local run script + config** (`lo` interface, `OUTPUT` NAT chain, `madcat` user,
  `/data` dirs) so the sensors can be started and scanned without editing `etc/madcat/config.lua`.
- [ ] **Commit and document [tools/nmap/madcat-detect.nse](tools/nmap/madcat-detect.nse).**

## 6. Repository hygiene

- [ ] **Remove the `v2_Development -> .` self-symlink.**
  Causes infinite recursion / duplicate results in tools that walk the tree (grep, find, indexers,
  Docker `COPY`).
- [ ] **Move `usr/bin/filebeat.aarch64.7z` out of git** (large binary blob; fetch at install time or use
  Git LFS / release assets).
