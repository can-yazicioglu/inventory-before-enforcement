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
| `est` | the responder took part. TCP: it sent a SYN-ACK, an acknowledgement, data or a FIN (a reset alone is a refusal). Other protocols: it sent a packet |
| `st`, `hist`, `svc` | Zeek connection state, history letters and detected service name |
| `ob`, `rb`, `opk`, `rpk` | payload bytes and packets in each direction |
| `vlan`, `if`, `ib` | VLAN tag, capture port number, and which side was identified by IP because the frame came through a router |
| `wc` | for a remote host: coarse service type (`dns`, `time`, `os_update`, `remote_access`, `vendor_cloud`, `other`, `unknown`, ...) |
| `wh`, `wn`, `wd` | only if the site's written permission covers it (`wan_tokens`): one-way tokens of the remote address, its /24 (or /48) and its registrable domain |
| `open` | present and true on an hourly report about a connection that is still open (see below). Then `ts` is the time of the last packet, `dur` the age of the connection, and the byte and packet counts cover the time since the previous report |

Next to the records the recorder writes `devices.json` (pseudonym to type, brand, model, group,
visibility, from the IT officer's table), `coverage.jsonl` (one line per hour: capture reports,
packets seen and dropped, link state, a fingerprint of the key in use) and `status.json`.

## What is never recorded

Packet contents, URLs, e-mail, file names, user names, host names, MAC addresses, local IP
addresses, remote IP addresses, domain names. DNS answers and TLS server names are read in RAM only,
to map a remote address to a service type. The map of remote addresses to names is kept in RAM for
at most a day. Names of local addresses (the site's own host names) are not kept at all.

## How connections are tracked

A connection log says which flow types a device has only if three things are handled on purpose.
`tests/scenarios.py` has one hand-made case for each and fails without them.

1. **Connections that stay open.** Zeek writes a record when a connection ends, stamped with its start. A connection that lasts for days would count on its first day only, or never if it was open before the recording started. The recorder also writes a report for every connection that is still open, once for every hour in which it carried packets (`open`).
2. **Silence.** By default Zeek forgets a silent TCP connection after 5 minutes and a silent UDP flow after 1 minute, and starts a new record when packets resume, with whoever speaks first as the originator. The recorder keeps a silent TCP connection for one day and a silent UDP flow for 2 minutes.
3. **Handshake not seen.** A TCP record with neither the opening SYN nor the answering SYN-ACK in its history was picked up in the middle of a conversation. The record is written as Zeek saw it. The analysis reads the history, does not trust the originator of such a record and infers the roles from the ports (`analysis/adapt_recorder.py`).

On the test capture below these three changes removed four flow types that were artefacts, out of
192 (two servers that seemed to open connections to client ports, one device credited with a
connection in which it had sent no packet, one keep-alive stream cut into pieces).

## Safeguards

| Safeguard | How it is enforced | Test |
|---|---|---|
| Raw logs never reach the disk | Zeek writes to a RAM disk. The recorder does not record unless the directory is a RAM disk and no swap can move memory to a disk (a swap file or partition, or compressed swap with a backing device, which is the default of current Raspberry Pi OS). The installer switches all swap off, keeps the system journal in RAM and forbids memory dumps of the capture process | `test_raw_logs_must_be_in_ram`, `test_swap_to_disk_stops_the_recording`, `test_installer.py`, `live_veth.py` |
| Raw logs are deleted every hour | each run deletes every log it read, whether or not the hour could be written, also when the run itself fails. If the job fails or hangs, a separate unit (`ibe-failsafe.service`) stops capture and empties the RAM disk | `test_full_run`, `test_failed_run_still_deletes_raw_logs`, `test_last_resort_when_the_run_itself_fails`, `e2e.py`. The separate unit is checked on the device (site setup, test 14) |
| No log is deleted unread | a log that Zeek completes while a run is busy is kept for the next run | `test_log_completed_during_a_run_is_kept_for_the_next_run`, `live_veth.py` |
| Pseudonyms cannot be reversed by the researchers | HMAC-SHA256 with a 256-bit key created on the device at the site. The key exists only on a USB stick that stays there | `test_pseudonym_is_stable_and_keyed`, `test_init_key_never_overwrites`, `test_key_cannot_be_created_without_a_stick` |
| The site can stop the recording at any time | pulling the key stick stops capture within the hour and empties RAM | `test_missing_key_or_unset_clock_stops`, `live_veth.py` |
| Nothing identifying leaves in the records | every record passes a field whitelist, every file passes a scan for IPv4, IPv6 and MAC address shapes. A batch that fails is not written | `test_leak_check_and_scan`, `test_random_records_never_leak_or_crash`, `test_scan_text_shapes`, `e2e.py` |
| Free text cannot leak through device labels | type, group and visibility come from a fixed vocabulary. Brand and model are limited to 40 plain characters and scanned | `test_full_run` |
| Recording cannot start before ethics approval | capture needs an arm file that names the approval. Without it nothing is captured and RAM is kept empty | `test_not_armed_writes_nothing_and_keeps_nothing`, `test_command_line` |
| Recording cannot run longer than permitted | permanent stop after `max_recording_days` (default 112). Records of a later day are dropped, not written | `test_limit_is_exact_and_permanent` |
| Data in transit is unreadable to third parties | every anonymised file is also encrypted for the researchers' OpenPGP public key into the folder `export`. The private key never comes near the device | `test_export_is_encrypted_for_the_researcher` |
| The recorder cannot disturb the network | capture interfaces have no address, no ARP and no IPv6, and an nftables egress rule drops every outgoing frame. The capture service does not start if the rule cannot be loaded | `egress_block.py` (with the rule file that `install.sh` writes) |
| A broken line or a broken setting cannot cause harm | a malformed raw line costs that line, not the hour. A wrong or unreadable configuration stops capture, empties RAM and says why | `test_broken_raw_lines_cost_one_record_not_the_hour`, `test_malformed_records_are_dropped_not_fatal`, `test_wrong_configuration_stops_cleanly` |
| A replaced key is noticed | `status.json` and `coverage.jsonl` carry a fingerprint of the key in use. A change is reported, because pseudonyms before and after do not match | `test_replaced_key_is_reported` |

## Results of the tests

Run on 19 November 2026 with Zeek 8.0.4 built from source on an amd64 test machine (2 cores).
The unit tests (49 for the recorder and its installer, 13 for the analysis side) pass on Python
3.11, 3.12 and 3.13.

`tests/scenarios.py` (a capture made by hand, 1,089 frames over 56 hours, fed to the anonymiser
hour by hour in 54 runs):

| Check | Result |
|---|---|
| Flow types of every device on every day equal the list written down beforehand | 43 device-day-types, none unexpected, none missing |
| A connection open for 50 hours, and one that never closes | present on each of their three days |
| A connection picked up in the middle, the server speaking first | counted as the client's connection to the service, not the reverse |
| 20 minutes of silence inside a connection | one record, roles unchanged |
| An answer after 90 seconds (UDP) | belongs to the question |
| Refused, unanswered and stray packets | nothing for the device that did not take part |
| Roles from the port rules for every record (sensitivity analysis) | the same flow types, except that equal ports on both sides are called symmetric |
| Two capture ports | the same records and flow types as one |
| Every frame doubled, as when a switch mirrors both directions | the same flow types. Packet counts double |
| Every raw record written or counted, raw logs deleted after every run, no address in the output | pass |

`tests/e2e.py` on real traffic, replayed as 30 identical days. Capture: the benign part of
CICIoMT2024 (1,935,680 packets, 22.1 hours, 25 source MAC addresses).

| Check | Result |
|---|---|
| Zeek writes only the six expected logs | pass |
| Every raw record written or counted, one capture port | 446,940 written, 0 dropped (per day 13,945 connection records and 953 hourly reports) |
| Every raw record written or counted, two capture ports | 446,940 written, 446,940 duplicates removed |
| Two ports give exactly the records of one port | pass |
| Raw logs deleted after every run | pass |
| Device pseudonyms match MAC addresses one to one | 24 pseudonyms, 24 MAC addresses, 1 gateway learned |
| No address, name or key in the output | 142 files searched for 977 raw strings (addresses, MAC addresses, DNS names, TLS names) and for address shapes: no hit |
| Without permission for tokens, remote hosts carry a service type only | pass |
| Flow types of the analysis equal an independent computation | 5,640 device-day-types, no difference |
| No new flow type after the first day | pass at all five levels |
| GT-C stops at T = 10 for ε = 0.3 and at T = 7 for ε = 1.0 | all 27 devices, all five levels |
| No alert day in the 14 days after enforcement | pass |

The same test on a scan (the OS scan capture of CICIoMT2024, 38,364 packets in 218 seconds, 30,975
connection records, 7,590 of them over the 30 days without a handshake): every check passes, 56,040
device-day-types equal the independent computation. Of 1,015 ports probed on the scanned devices
2 were answered, and only those became flow types of the scanned devices.

`tests/live_veth.py` (two virtual capture ports, live Zeek, replay with tcpreplay):

| Check | Result |
|---|---|
| Replay at 50 Mbit/s (33,234 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Replay at 200 Mbit/s (132,934 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Replay at about 770 Mbit/s (767 and 780 Mbit/s reached, over 510,000 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Rotation, anonymisation, duplicates across ports | 34,203 records written, 34,195 duplicates removed |
| Connections that stay open are reported while they are open | 10,022 reports (every 10 seconds in this test) |
| Logs completed while the anonymiser was busy | kept and read by the next run |
| Capture killed in the middle of a log | the open log was rotated at restart and anonymised on the next run |
| Key removed | recording stopped, RAM emptied, capture not allowed to start again |

`tests/egress_block.py`: without the rule 20 of 20 raw frames left the interface, with the rule 0 of 20.

`tests/batch_size.py`: one run takes 0.39 GB of memory for 104,293 records, 1.86 GB for 521,465 and
3.70 GB for 1,042,930, at about 12,000 records per second.

Zeek itself: 84 MB for the benign capture. During a made-up port scan of 1.5 million unanswered
connection attempts in 30 minutes it needs 289 MB (103 MB with Zeek's default settings), because
every connection is looked at once more after five minutes.

These runs show that the chain is correct. They do not show what a given board can sustain. Loss
and throughput on the Raspberry Pi 5 are measured before the device is shipped (see `docs/site-setup.md`).

Not run anywhere yet, because they need the device: the installer on a real system (it is tested
against a stand-in folder, `test_installer.py`), the systemd units (their syntax is checked with
`systemd-analyze verify`), the automount of the key stick and the data disk, the effect of the swap
and journal settings, the status light. They are tests 1 and 10 to 16 of `docs/site-setup.md`.

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
are then duplicated, flow types are unaffected (tested in `scenarios.py`), packet and byte counts
double. Devices behind an unmanaged switch are seen only when they talk through the managed switch.
Label them `partial` in the device table.

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
6. To hand over data, copy the folder `export` from the data disk and send it by any channel. It holds the same anonymised files, encrypted so that only the researchers can open them. The folder `anon` next to it is the readable form, kept so that the site can inspect what leaves.

Optional files on the key stick: `site.json` (`{"gateway_macs": [...], "local_nets": [...]}`) and
`service_rules.csv` (`domain,category` lines for vendor domains the built-in rules do not know).
`unclassified_domains.json` lists, for the IT officer only, the domains of unlabelled remote services.
A router between local networks that is not the way to the internet must be listed in `gateway_macs`,
otherwise every device behind it looks like one device.

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
- Timestamps depend on the device clock. Fit the clock battery. A clock that jumps backwards is reported in `status.json` and `coverage.jsonl`. Records stamped before November 2026 or more than a day ahead of the clock are dropped and counted.
- Presence is resolved to one hour: a connection shorter than an hour that crosses midnight counts on the day it starts.
- The MAC addresses of a connection are those of its first packet. If an address moves to another device while a silent connection is still tracked (up to a day), later packets are attributed to the first device.
- A unicast answer to a multicast or broadcast question (SSDP, WS-Discovery, LLMNR) is a flow of its own, opened by the answering device towards the asker's client port. Client ports from 32768 form one class, lower ones do not. The analysis is repeated with roles from the port rules to show how much this matters.
- For UDP the originator is the side that sent the first packet the recorder saw. After a restart of the capture, a flow in progress can therefore be turned around once.
- Duplicates across capture ports are removed within one hourly batch. A copy that falls into the next batch stays, which does not change the flow types.
- The hourly batch is processed in memory (see `batch_size.py` above). A site with more than about a million connections per hour needs a shorter rotation interval. If a run fails for lack of memory, capture is stopped, the RAM disk is emptied and capture starts again after the next run, so that hour and the one before it are lost.
