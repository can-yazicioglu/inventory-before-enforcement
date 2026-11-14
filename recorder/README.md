# Recorder

A small Linux box (Raspberry Pi 5 with two extra Ethernet ports, or any amd64 or arm64 machine)
that listens on switch mirror ports and writes anonymised connection records. It is designed for
sites where the researchers must never hold raw network data: a clinic, a hospital department.

```
mirror port A ──► eth1 ──► Zeek ──► raw logs in RAM ──┐
                                                       ├─► hourly anonymiser ──► anonymised records (disk)
mirror port B ──► eth2 ──► Zeek ──► raw logs in RAM ──┘         │
                                                                 └─► raw logs deleted
key stick (stays on site): HMAC key, arm file, device labels, files with real addresses
```

## What is recorded

One JSON line per connection (Zeek `conn.log`), reduced to these fields:

| Field | Meaning |
|---|---|
| `ts`, `dur` | start time (whole seconds, UTC) and duration |
| `proto`, `ipp` | transport name and IP protocol number |
| `op`, `rp` | originator port and responder port |
| `o`, `r` | originator and responder. A local device is a pseudonym (`d` + 10 characters, from its MAC address). A remote host is the word `wan`. A group address is a fixed word such as `mcast:mdns` or `bcast` |
| `os`, `rs` | scope of each side: `lan`, `wan`, `mcast`, `bcast` |
| `est` | the responder took part (TCP handshake answered, or any responder packet) |
| `st`, `hist`, `svc` | Zeek connection state, history letters and detected service name |
| `ob`, `rb`, `opk`, `rpk` | payload bytes and packets in each direction |
| `vlan`, `if`, `ib` | VLAN tag, capture port number, and which side was identified by IP because the frame came through a router |
| `wc` | for a remote host: coarse service type (`dns`, `time`, `os_update`, `remote_access`, `vendor_cloud`, `other`, `unknown`, ...) |
| `wh`, `wn`, `wd` | only if the site's written permission covers it (`wan_tokens`): one-way tokens of the remote address, its /24 (or /48) and its registrable domain |

Next to the records the recorder writes `devices.json` (pseudonym to type, brand, model, group,
visibility, from the IT officer's table), `coverage.jsonl` (one line per hour: capture reports,
packets seen and dropped, link state) and `status.json`.

## What is never recorded

Packet contents, URLs, e-mail, file names, user names, host names, MAC addresses, local IP
addresses, remote IP addresses, domain names. DNS answers and TLS server names are read in RAM only,
to map a remote address to a service type, and are discarded.

## Safeguards

| Safeguard | How it is enforced | Test |
|---|---|---|
| Raw logs never reach the disk | Zeek writes to a tmpfs directory, disk swap is switched off and reported if found on | `test_swap_detection`, `live_veth.py` |
| Raw logs are deleted every hour | deletion happens whether or not the hour could be written | `test_full_run`, `e2e.py` |
| Pseudonyms cannot be reversed by the researchers | HMAC-SHA256 with a 256-bit key created on the device at the site. The key exists only on a USB stick that stays there | `test_pseudonym_is_stable_and_keyed`, `test_init_key_never_overwrites` |
| The site can stop the recording at any time | pulling the key stick stops capture within the hour and empties RAM | `test_missing_key_or_unset_clock_stops`, `live_veth.py` |
| Nothing identifying leaves in the records | every record passes a field whitelist, every file passes a scan for IPv4, IPv6 and MAC address shapes. A batch that fails is not written | `test_leak_check_and_scan`, `e2e.py` |
| Free text cannot leak through device labels | type, group and visibility come from a fixed vocabulary. Brand and model are limited to 40 plain characters and scanned | `test_full_run` |
| Recording cannot start before ethics approval | capture needs an arm file that names the approval. Without it nothing is captured and RAM is kept empty | `test_not_armed_writes_nothing_and_keeps_nothing` |
| Recording cannot run longer than permitted | permanent stop after `max_recording_days` (default 112). Records of a later day are dropped, not written | `test_limit_is_exact_and_permanent` |
| The recorder cannot disturb the network | capture interfaces have no address, no ARP and no IPv6, and an nftables egress rule drops every outgoing frame. The capture service does not start if the rule cannot be loaded | `egress_block.py` |

## Results of the tests on real traffic

Run on 14 November 2026 with Zeek 8.0.4 built from source on an amd64 test machine (2 cores).
Capture: the benign part of CICIoMT2024 (1,935,680 packets, 22.1 hours, 25 source MAC addresses).

`tests/e2e.py` (30 replayed days, see the top-level README):

| Check | Result |
|---|---|
| Zeek writes only the five expected logs | pass |
| Every raw record written or counted, one capture port | 425,640 written, 0 dropped (14,188 per day, 30 days) |
| Every raw record written or counted, two capture ports | 425,640 written, 425,640 duplicates removed |
| Two ports give exactly the records of one port | pass |
| Raw logs deleted after every run | pass |
| Device pseudonyms match MAC addresses one to one | 24 pseudonyms, 24 MAC addresses, 1 gateway learned |
| No address, name or key in the output | 142 files searched for 977 raw strings (addresses, MAC addresses, DNS names, TLS names) and for address shapes: no hit |
| Without permission for tokens, remote hosts carry a service type only | pass |
| Flow types of the analysis equal an independent computation | 5,760 device-day-types, no difference |
| No new flow type after the first day | pass at all five levels |
| GT-C stops at T = 10 for ε = 0.3 and at T = 7 for ε = 1.0 | all 27 devices, all five levels |
| No alert day in the 14 days after enforcement | pass |

`tests/live_veth.py` (two virtual capture ports, live Zeek, replay with tcpreplay):

| Check | Result |
|---|---|
| Replay at 50 Mbit/s (33,234 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Replay at 200 Mbit/s (132,934 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Replay at about 800 Mbit/s (826 and 784 Mbit/s reached, over 520,000 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Rotation, anonymisation, duplicates across ports | 24,548 records written, 24,545 duplicates removed, only open logs left in RAM |
| Capture killed in the middle of a log | the open log (4,020 records) was rotated at restart and anonymised on the next run |
| Key removed | recording stopped, RAM emptied, capture not allowed to start again |

`tests/egress_block.py`: without the rule 20 of 20 raw frames left the interface, with the rule 0 of 20.

These runs show that the chain is correct. They do not show what a given board can sustain. Loss
and throughput on the Raspberry Pi 5 are measured before the device is shipped (see `docs/site-setup.md`).

## Switch configuration

Mirror **incoming traffic on every port** of each switch (including the links to other switches and
to the firewall) to the port the recorder is plugged into. Every frame enters a switch exactly once,
so this gives one copy of every frame and both directions of every conversation. Example for an
HP 2530 with the recorder on port 24 (syntax of the ArubaOS-Switch 16.05 manual, check the manual of
the installed firmware):

```
mirror 1 port 24
interface 1-23 monitor all in mirror 1
```

One recorder port per switch. A connection that crosses two mirrored switches is seen twice and the
anonymiser removes the second copy. If a switch can only mirror both directions, use that: frames
are then duplicated, flow presence is unaffected, packet and byte counts are not reliable.
Devices behind an unmanaged switch are seen only when they talk through the managed switch. Label
them `partial` in the device table.

## Installation

```bash
sudo ./install.sh eth1 eth2        # the capture interfaces, never the one you are logged in through
sudo reboot
```

Then, at the site:

1. Plug in a FAT32 USB stick labelled `IBE-KEY`. The recorder creates its key on it within the hour.
2. Plug in an exFAT disk labelled `IBE-DATA`. A second copy of the data is kept on the system disk.
3. Connect the mirror ports. Nothing is captured yet.
4. After ethics approval, put a file `armed.json` on the key stick: `{"approval_ref": "<date and number>"}`. Capture starts within the hour.
5. After a few days, copy `devices_observed.csv` from the key stick, fill in type, brand, model, group, visibility and switch for each row, and save it on the stick as `devices.csv`. The file holds real addresses and never leaves the stick. Only the labels are exported, attached to pseudonyms.
6. To hand over data, copy the folder `anon` from the data disk. It holds no address and no name.

Optional files on the key stick: `site.json` (`{"gateway_macs": [...], "local_nets": [...]}`) and
`service_rules.csv` (`domain,category` lines for vendor domains the built-in rules do not know).
`unclassified_domains.json` lists, for the IT officer only, the domains of unlabelled remote services.

The status light: heartbeat while recording, steady when ready but not armed, fast blink when stopped.
`status.json` on the key stick and the data disk says why.

## Commands

```
python3 -m ibe_recorder status | run | preflight | init-key | arm --approval-ref REF | disarm
python3 -m ibe_recorder extend --days N --approval-ref REF      # after a written extension by the site
python3 -m ibe_recorder export --dest DIR                       # copy with SHA-256 checksums
```

## Known limits

- A device behind a router is identified by its IP address, not its MAC address (`ib` marks these records). Address changes then look like new devices.
- A remote address is mapped to a domain through DNS answers and TLS server names seen in the last 24 hours. A connection without either gets the service type `unknown` or a port-based type.
- Up to one hour of data is lost at a power failure, because raw logs live in RAM.
- Timestamps depend on the device clock. Fit the clock battery. A clock that jumps backwards is reported in `status.json` and `coverage.jsonl`.
- The hourly batch is processed in memory. Measured on the test machine: 0.38 GB for 99,316 records, 1.79 GB for 496,580, 3.55 GB for 993,160, at about 13,000 records per second. A site with more than about a million connections per hour needs a shorter rotation interval.
