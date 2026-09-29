# MADCAT – Implementation Plan

Target: turn MADCAT from an Internet mass-attack sensor into a **deception platform for internal networks**,
after first fixing the issues collected in [TODO.md](../TODO.md).

On an internal network no legitimate user has a reason to talk to a decoy, so **every contact is a
high-confidence alert**. That shifts priorities compared with the Internet sensor: believability and
alert quality matter more than volume.

## Branching (git flow)

- `main` – releases, `develop` – integration, `feature/<topic>` – one branch per work package below,
  branched from `develop` and merged back with `--no-ff`.
- `origin` = fork (TimWinkler/MADCAT_v2), `upstream` = BSI-Bund/MADCAT_v2. Nothing is pushed without review.
- Commit style per [CONTRIBUTING.md](../CONTRIBUTING.md): subject ≤ 72 chars, K&R C with 4-space indent, PEP 8.
- Defaults that change behaviour of the existing Internet sensor stay upstream-compatible; new behaviour
  is opt-in via `config.lua` (so the improvement branches remain upstreamable).

## Phase 0 – Foundation

| Branch | Content |
|---|---|
| `feature/devcontainer` | (exists) add `SYS_PTRACE` so `gdb -p` / `strace -p` work; merge into `develop` |
| `feature/roadmap` | this plan, `TODO.md`, `tools/nmap/madcat-detect.nse` |

## Phase 1 – Improvements (from TODO.md)

| Branch | Work items | Verification |
|---|---|---|
| `feature/security-hardening` | single `drop_privileges()` in `madcat.helper.c` that calls `setgroups()` before `setgid()`/`setuid()`, used by all four sensors; fix `json_dict("false")` | `Groups:` line in `/proc/<pid>/status` of running sensors |
| `feature/robustness` | FIFO writes with timeout (no more stall when the postprocessor is gone), FIFO paths read from config, remove dead watchdog semaphore code, `SOMAXCONN` backlog, checked allocations + consistent fields in UDP worker, postprocessor conntrack wait without holding `syn_dict_lock` | reproduce the stall scenario (no FIFO reader) – sensor must keep accepting |
| `feature/performance` | TCP worker uses `poll()` instead of 50 ms sleep loop; postprocessor exact match via dict lookup (logic extracted into a testable function); enrichment uses a bounded worker pool | unit tests + load test with `nmap -sT -p-` |
| `feature/stealth` | configurable close mode (`tcp_close_mode = "rst"`/`"fin"`, default `rst` = today) and timeout jitter (`tcp_connection_timeout_jitter`) | `madcat-detect.nse` no longer matches with `fin` + jitter |
| `feature/tests` | gtest for TCP/UDP/ICMP parsers with crafted packets, libFuzzer target for the parsers, pytest for the postprocessor join, e2e smoke test (`tests/e2e/smoke.sh`), GitHub Actions workflow | `ctest`, `pytest`, smoke test in devcontainer |
| `feature/repo-hygiene` | remove `v2_Development -> .` self-symlink | – |

Not done without a decision from the maintainer: removing `usr/bin/filebeat.aarch64.7z` (part of upstream packaging).

## Phase 2 – Deception extension

### Architecture

```
            decoy IPs (aliases/macvlan)                            internal network
                    │
  iptables: DNAT only persona ports ──► catch-all listener (tcp_ip_port_mon)
  (other ports: kernel RST = "closed")          │ accept, SO_ORIGINAL_DST, buffer first bytes
                    │                           │
   pcap sniffer still sees every SYN            ▼  unix socket, JSON request
   (syn_scan events on closed ports)     madcat-orchestrator (Python)
                                           ├─ persona registry  (etc/madcat/deception.toml)
                                           ├─ decision engine    (per-source state, budgets, rules)
                                           ├─ instance manager   (pools, TTL, per-attacker instances)
                                           │    ├─ ProcessBackend  (local processes; dev/test)
                                           │    └─ DockerBackend   (production, network-isolated)
                                           └─ event emitter  ──► /tmp/logs.erm (enrichment) / JSONL
                                                │
             worker: connect backend, replay buffered bytes, relay both ways (poll)
                                                │
                            fake services (deception/services/*):
                              http  – intranet login portal      (stdlib)
                              ftp   – file drop with bait files   (pyftpdlib)
                              ssh   – fake Linux shell             (asyncssh)
                              smb   – file share with bait docs   (impacket)
                              ─ every auth attempt / command → JSON event
                              ─ honeytoken credentials → "honeytoken_used" alert

  traffic simulator (fake users): business-hours schedule, logs into decoys with
  honeytoken creds over plaintext protocols, DNS lookups of decoy names
```

### Design decisions

- **Python for the control plane and services.** Fast iteration, mature protocol libraries (impacket,
  asyncssh, pyftpdlib); the C sensor stays the fast, minimal data plane.
- **Closed ports are real closed ports.** Only ports in a decoy's persona are DNATed; everything else gets a
  kernel RST. This removes the "all ports open" fingerprint while the sniffer still logs every SYN.
- **Splice in the existing TCP worker.** The worker already holds the connection and buffers payload. With
  `deception_socket` configured it asks the orchestrator for a backend right after `accept()`, connects,
  replays the buffered bytes and relays in both directions. No answer / budget exhausted → today's silent
  behaviour (fail-safe, never worse than current MADCAT).
- **Per-attacker instances.** Instance key = (source IP, decoy IP, service). An attacker always sees the same
  fake host state; different attackers never see each other. Idle instances expire after a TTL.
- **Latency.** Server-speaks-first protocols (SSH, FTP) need a banner within ~1 s: the instance manager keeps
  a pre-warmed pool per service and adds constant artificial delay so first and later connections look alike.
- **Budgets.** Global and per-source instance limits; above them the orchestrator answers `hold`.
- **Honeytokens.** Credentials and bait files defined in `deception.toml`; services report every auth
  attempt; a match on a honeytoken produces a `honeytoken_used` event naming the token (= where it was placed).
- **Events.** One JSON line per event, same style as the sensors (`origin`, `timestamp`, `event_type`,
  `src_ip`, …, plus a `DECEPTION` object). Written to the enrichment FIFO so the existing pipeline carries them.

### Milestones

| Branch | Milestone | Done when |
|---|---|---|
| `feature/deception-personas` | M1: `deception.toml` schema (decoys, personas, services, honeytokens, budgets); generator for IP aliases + iptables rules; TCP sensor on multiple decoy IPs (`hostaddress = "0.0.0.0"` + persona DNAT) | nmap of a decoy shows exactly its persona ports; sniffer logs SYNs to closed ports |
| `feature/deception-orchestrator` | M2: orchestrator daemon (unix socket API, decision engine, instance manager, ProcessBackend, pools, budgets, events); splice + relay in the C worker | `curl` through a decoy port reaches the spawned HTTP service; flow event carries `DECEPTION` info |
| `feature/deception-services` | M3: http, ftp, ssh, smb fake services with bait content, auth event reporting, honeytoken detection; adaptive rule (e.g. SSH login succeeds after N attempts or with honeytoken) | e2e: login with honeytoken creds on each service yields `honeytoken_used` |
| `feature/deception-traffic` | M4: traffic simulator with fake users (schedule, plaintext logins with honeytoken creds, DNS lookups) | simulator traffic visible in tcpdump; its own events tagged `simulated` and not alerted |
| `feature/deception-docker` | M5: DockerBackend (internal network, no egress, read-only rootfs, per-session teardown), devcontainer docker-outside-of-docker for testing | spawn and teardown via Docker on a Docker host |
| later | M6: correlation across decoys (attacker timeline), MITRE ATT&CK tagging, SIEM/syslog alert output, central fleet management, UDP/ICMP personas (DNS, NetBIOS/LLMNR responders) | – |

Phases 0–1 and milestones M1–M4 are implemented in this iteration; M5 and M6 follow.

### Risks

- **Containment:** fake services must never have a route into the production network. The ProcessBackend
  binds services to `127.0.0.1` only; production use requires the DockerBackend with an isolated network.
- **Resource exhaustion:** every connection can trigger a spawn → budgets and fallback to `hold`.
- **Simulated traffic** must be tagged and must not trigger production alerting.
- **Legal/organisational:** deploying decoys and bait credentials inside a corporate network needs sign-off
  (works council / data protection, SOC runbook for alerts).
