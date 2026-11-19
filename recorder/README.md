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
| `o`, `r` | originator and responder. A local device is a pseudonym (`d` + 10 characters, from its MAC address, or `i` + 10 characters from its IP address if only that is known). A remote host is the word `wan`. A group address is a fixed word such as `mcast:mdns` or `bcast` |
| `os`, `rs` | scope of each side: `lan`, `wan`, `mcast`, `bcast` |
| `est` | the responder took part. TCP: it sent a SYN-ACK, an acknowledgement, data or a FIN (a reset alone is a refusal). Other protocols: it sent a packet. In an hourly report: it sent a packet in that hour |
| `st`, `hist`, `svc` | Zeek connection state, history letters and detected service name |
| `ob`, `rb`, `opk`, `rpk` | payload bytes and packets in each direction |
| `vlan`, `if`, `ib` | VLAN tag, capture port number, and which side is named by its IP address (a device behind a router that no mirrored network shows) |
| `wc` | for a remote host: coarse service type (`dns`, `time`, `os_update`, `remote_access`, `vendor_cloud`, `other`, `unknown`, ...) |
| `wh`, `wn`, `wd` | only if the site's written permission covers it (`wan_tokens`): one-way tokens of the remote address, its /24 (or /48) and its registrable domain |
| `open` | present and true on an hourly report about a connection that is still open, and on the last report about one that just ended (see below). Then `ts` is the time of the last packet in that hour, `dur` the age of the connection, and the byte and packet counts cover the time since the previous report |

Next to the records the recorder writes `devices.json` (pseudonym to type, brand, model, group,
visibility, from the IT officer's table), `coverage.jsonl` (one line per hour: capture reports,
packets seen and dropped, link state, a fingerprint of the key in use) and `status.json`.

## What is never recorded

Packet contents, URLs, e-mail, file names, user names, host names, MAC addresses, local IP
addresses, remote IP addresses, domain names. DNS answers and TLS server names are read in RAM only,
to map a remote address to a service type. The map of remote addresses to names is kept in RAM for
at most a day. Names of local addresses (the site's own host names) are not kept at all.

To name a device that is reached through a router, the recorder notes which MAC address answers for
which local IP address (from ARP and IPv6 neighbour discovery). This table holds real addresses. It
exists in RAM and on the key stick only, like the list of routers, and stays at the site.

## How connections are tracked

A connection log says which flow types a device has only if the following are handled on purpose.
`tests/scenarios.py` has a hand-made case for each, with the expected flow types written down
beforehand, and fails without them.

1. **Connections that stay open.** Zeek writes a record when a connection ends, stamped with its start. A connection that lasts for days would count on its first day only, or never if it was open before the recording started. The recorder also writes a report at every full hour for every open connection that carried packets in that hour, and a last one when a connection ends in a later hour than it began (`open`). A report counts for a side only if that side sent a packet in that hour: keep-alive probes to a device that is switched off do not make that device active. The finished record of such a connection covers its whole life. It therefore counts only for its opener, at the start: a device that was switched off when a flow towards it began is not active on that day because it answered on the next.
2. **Silence.** By default Zeek forgets a silent TCP connection after 5 minutes and a silent UDP flow after 1 minute, and starts a new record when packets resume, with whoever speaks first as the originator. The recorder keeps a silent TCP connection for one day and a silent UDP flow for 2 minutes, also on the ports of Zeek's DNS analyzer, which has a timeout of its own (10 seconds).
3. **Opener not seen.** A TCP record with neither the opening SYN nor the answering SYN-ACK in its history was picked up in the middle of a conversation. A UDP record that Zeek turned around (`^` in the history) began with a packet from a service port: the answer to a question that went to a group address (LLMNR, mDNS) or was not captured. The record is written as Zeek saw it. The analysis does not trust the originator of such a record, infers the roles from the ports, and counts the record only for a side that sent a packet in it (`analysis/adapt_recorder.py`).
4. **One record, several devices.** A DHCP request goes from 0.0.0.0 to the broadcast address whichever device sends it. Zeek would keep one record for all devices that ask within two minutes, with the MAC address of the first. The recorder ends such a record at once, so every sender has its own.
5. **Devices behind a router.** A frame that reaches the capture port through a router carries the router's MAC address. The device is then named by the MAC address that answers for its IP address on the local link (ARP, IPv6 neighbour discovery), so a device in a second mirrored VLAN keeps one name. A MAC address counts as a router if it fronts 16 networks outside the site, or if it carries packets of two local addresses that belong to other MAC addresses. An address outside the local networks is remote from the first record on, unless the devices themselves place it on the local link.
6. **Protocols without ports.** There is no service port that says who serves whom. A ping that is not answered counts for the sender only. An ICMP error message (port unreachable and the like) is the refusal of a packet of somebody else, as a reset is for TCP, and gives the device that sends it no flow type.
7. **Tunnels.** Zeek opens tunnels (IPv4 or IPv6 in IPv4, GRE, and Teredo, AYIYA, VXLAN, Geneve and GTP in UDP) and logs the connections inside them under the inner addresses. The device that keeps the tunnel would have no record, and the inner addresses would look like devices. The recorder leaves tunnels closed: the tunnel is one flow of the device, and what is inside it is not looked at.

Effect on the test capture (the benign part of CICIoMT2024, one pass, primary level). With Zeek's
default timeouts 202 of 2,979 TCP records had no handshake. The audit of 19 November took the number
of pairs of device and flow type from 192 to 188, the two reviews after it to 168. 19 pairs
belonged to the router, which had been counted as a device under its IP address. 5 pairs were flow
types of devices that had sent no packet (4 ICMP messages that were not answered, 1 DNS answer whose
question is not in the capture). 4 pairs are new: the DHCP broadcast of devices that had been
hidden behind the first sender. 19 more pairs kept their meaning and changed their name, because
the router, and one device behind it, are now named by their MAC addresses. The second round of
reviews took the number to 160: the 8 pairs that disappeared were flow types of devices that had
only refused a datagram (all 55 ICMPv4 records of the capture are "port unreachable" messages).

## Safeguards

| Safeguard | How it is enforced | Test |
|---|---|---|
| Raw logs never reach the disk | Zeek writes to a RAM disk. The recorder does not record unless the directory is a RAM disk and no swap can move memory to a disk (a swap file or partition, or compressed swap with a backing device, which is the default of current Raspberry Pi OS). The installer switches all swap off, keeps the system journal in RAM, stops it from being passed on to a syslog service that writes to disk, and forbids memory dumps of the capture process | `test_raw_logs_must_be_in_ram`, `test_swap_to_disk_stops_the_recording`, `test_installer.py`, `live_veth.py` |
| Raw logs are deleted every hour | each run deletes every log it read, whether or not the hour could be written, also when the run itself fails. If the job fails or hangs, a separate unit (`ibe-failsafe.service`) stops capture and empties the RAM disk, also if stopping fails. Zeek completes a log when its own clock reaches the next full hour, and that clock never goes back: after the system clock is set back, capture is stopped once, its open logs are read and removed, and it starts again | `test_full_run`, `test_failed_run_still_deletes_raw_logs`, `test_last_resort_when_the_run_itself_fails`, `test_clock_set_back_while_capture_runs`, `test_failsafe_empties_the_ram_disk_whatever_stopping_says`, `e2e.py`. The separate unit is checked on the device (site setup, test 14) |
| No log is deleted unread | a log that Zeek completes while a run is busy is kept for the next run | `test_log_completed_during_a_run_is_kept_for_the_next_run`, `live_veth.py` |
| Pseudonyms cannot be reversed by the researchers | HMAC-SHA256 with a 256-bit key created on the device at the site. The key exists only on a USB stick that stays there. The key is created, and recording runs, only if the stick is really mounted: an empty folder on the system disk is refused. A key file that is cut short or filled with a few repeated characters is refused as well (fewer than 32 bytes, or fewer than 8 different byte values). Randomness itself cannot be tested: the key comes from the random source of the system | `test_pseudonym_is_stable_and_keyed`, `test_init_key_never_overwrites`, `test_key_cannot_be_created_without_a_stick`, `test_key_directory_must_be_the_stick`, `test_clock_without_battery_and_weak_key` |
| The site can stop the recording at any time | pulling the key stick stops capture within the hour and empties RAM. A stick that is plugged in but idle counts as present: the check is made by the recorder, which opens the folder, and not by a condition of the system manager, which would find the folder empty | `test_missing_key_or_unset_clock_stops`, `test_capture_unit_does_not_look_at_the_stick_itself`, `live_veth.py` |
| A remote host is never named without permission | a host is named by a token of its address only inside the local networks, which are the private ranges. The key stick can narrow that list and cannot widen it. A public range can be declared local only in the configuration, never one wider than the widest private range, and the status then says so | `test_local_networks_cannot_be_widened_from_the_stick`, `test_addresses_on_the_link_outside_the_local_networks_are_reported` |
| Nothing identifying leaves in the records | every record passes a field whitelist, every file passes a scan for IPv4, IPv6 and MAC address shapes. A batch that fails is not written | `test_leak_check_and_scan`, `test_random_records_never_leak_or_crash`, `test_scan_text_shapes`, `e2e.py` |
| Labels typed at the site cannot carry an address or a host name | type, group and visibility come from a fixed vocabulary, the switch is a code of up to three characters. Brand and model are limited to 40 plain characters and are refused if they have the shape of an IP address, a MAC address or a host name. A person's name or a room cannot be recognised by a pattern: the site reads `devices.json` before it hands the data over | `test_labels_typed_on_site`, `test_full_run` |
| Record fields cannot carry text | every field is a number in a range of its own or one of a list of words (protocol, connection state, history letters, Zeek service names, group labels, service types). A value outside the list is written empty. The status lists a device only once it sent a packet, up to a fixed number | `test_whitelist_names_values`, `test_whitelist_ranges_and_words`, `test_random_records_never_leak_or_crash`, `test_devices_seen_does_not_grow_with_addresses_that_were_only_tried` |
| Addresses learned from ARP stay at the site | the table of MAC and IP addresses and the list of routers are written to the key stick only | `test_neighbour_log_names_devices_behind_the_router`, `e2e.py` |
| Recording cannot start before ethics approval | capture needs an arm file that names the approval. Without it nothing is captured and RAM is kept empty | `test_not_armed_writes_nothing_and_keeps_nothing`, `test_command_line` |
| Recording cannot run longer than permitted | three limits, whichever comes first, each a permanent stop: `max_recording_days` days with records (default 112), 25 hourly batches per permitted day, and `max_calendar_days` (default 365) from the first day. Records of a later day are dropped, not written. The days are counted from every copy of the status (system disk, key stick, data disk), a batch is counted before it is written, and capture does not run if the count cannot be saved | `test_limit_is_exact_and_permanent`, `test_limit_by_the_calendar`, `test_day_count_survives_a_lost_state_file`, `test_batch_is_counted_before_it_is_written` |
| A wrong clock cannot stretch the recording | capture needs a hardware clock that has kept time (its battery). A clock that cannot be read counts as not set. Once the permitted days are counted, recording continues only on the latest of them, and the limit on hourly batches does not depend on the clock at all | `test_clock_without_battery_and_weak_key`, `test_hardware_clock_that_cannot_be_read`, `test_limit_holds_when_the_clock_is_set_back`, `test_limit_holds_when_the_clock_stands_still` |
| Data in transit is unreadable to third parties | every anonymised file is also encrypted for the researchers' OpenPGP public key into the folder `export`. The private key never comes near the device | `test_export_is_encrypted_for_the_researcher` |
| The recorder cannot disturb the network | capture interfaces have no address, no ARP and no IPv6, and an nftables egress rule drops every outgoing frame. The capture service does not start if the rule cannot be loaded | `egress_block.py` (with the rule file that `install.sh` writes) |
| A broken line or a broken setting cannot cause harm | a malformed raw line costs that line, not the hour. A missing, unreadable or wrong configuration stops capture, empties RAM and says why. That includes a setting that is misspelt or has the wrong type, which would otherwise leave the built-in value in force. A damaged file on the key stick or the data disk costs what it held, not the hour. A wrong folder for the raw logs cannot delete anything else: a folder that holds the key or the data is refused, and outside the folders of the capture ports only files that are named like Zeek logs and lie on a RAM disk are removed | `test_broken_raw_lines_cost_one_record_not_the_hour`, `test_malformed_records_are_dropped_not_fatal`, `test_wrong_configuration_stops_cleanly`, `test_settings_must_be_spelt_and_typed_right`, `test_more_damaged_files`, `test_wrong_raw_directory_does_not_empty_other_folders`, `test_command_line_traps` |
| No capture process runs unwatched | a capture folder that the configuration does not name is stopped and emptied. A log left by a capture process that is gone is read and removed. The installer refuses to enable capture ports that an existing configuration does not name | `test_capture_folder_outside_the_configuration_is_emptied`, `test_log_of_a_dead_capture_is_read_and_removed`, `test_installer.py` |
| A replaced key is noticed | `status.json` and `coverage.jsonl` carry a fingerprint of the key in use. A change is reported, because pseudonyms before and after do not match | `test_replaced_key_is_reported` |

## Results of the tests

Run on 19 November 2026 with Zeek 8.0.4 built from source on an amd64 test machine (2 cores).
The unit tests (86 for the recorder and its installer, 17 for the analysis side) pass on Python
3.11, 3.12 and 3.13.

`tests/scenarios.py` (a capture made by hand, 18,097 frames over 56 hours, fed to the anonymiser
hour by hour in 55 runs, the logs that Zeek writes when it stops included, and a second capture
that is silent around midnight):

| Check | Result |
|---|---|
| Flow types of every device on every day equal the list written down beforehand | 93 device-day-types, none unexpected, none missing |
| A connection open for 50 hours, and one that never closes | present on each of their three days |
| A connection picked up in the middle, the server speaking first | counted as the client's connection to the service, not the reverse |
| 20 minutes of silence inside a connection | one record, roles unchanged |
| An answer after 90 seconds (UDP) | belongs to the question |
| Refused, unanswered and stray packets | nothing for the device that did not take part |
| Midnight: 30 seconds across it, a connection closed 25 minutes after it between two reports, one packet 13 minutes before it and one 5 minutes after | each connection present on exactly the days on which it carried packets |
| Three devices that ask for an address within two minutes, on two days in different order | each has the DHCP broadcast type on both days |
| A ping every 30 seconds for two days, from the host with the higher address | present on each of the three days for both hosts |
| A ping that is not answered | a flow type only for the device that sent it |
| A datagram to a closed port, refused with an ICMP error message | no flow type for the refusing device |
| Three flows towards a device that is switched off on the first day and answers from the next (a datagram every minute, a ping, a server that sends from its service port) | the device is active from the day on which it sends, not before |
| A device that reaches the IPv6 internet through a relay (IPv6 in IPv4), one that keeps a GRE tunnel, one that sends VXLAN | the tunnel is the flow of the device. The addresses inside the tunnels are not devices |
| An answer that is the first packet after midnight, and the first of its sender since two days before | counts on the day it was sent, also with every frame doubled |
| 60 TCP flows that never got going (30 stray acknowledgements, 30 connection attempts from made-up addresses that the server answered), limit set to 20 | 20 are kept like a silent connection, 40 are ended after five minutes |
| The unicast answer to a name question sent to a group address | the answering device serves the port, the asker has no flow type from the answer |
| Keep-alive probes to a device that was switched off the day before | the device is not active on that day, the server is |
| Two VLANs joined by a router that is not listed and leads nowhere else, every frame captured twice | both devices keep their own names in both directions, also for an attempt that is not answered. The router is recognised and has one name |
| Roles from the port rules for every record (sensitivity analysis) | the same flow types, except that equal ports on both sides are called symmetric |
| Two capture ports | the same records and flow types as one |
| Every frame doubled, as when a switch mirrors both directions | the same flow types. Packet counts double |
| Every raw record written or counted, raw logs deleted after every run, no address in the output | pass |
| The same test with the recorder as it was before the first round of reviews | fails: 17 unexpected and 23 missing flow types |
| The same test with the recorder as it was before the second round | fails: 7 unexpected and 2 missing flow types, the answer after midnight and the limit on flows that never got going |

`tests/e2e.py` on real traffic, replayed as 30 identical days. Capture: the benign part of
CICIoMT2024 (1,935,680 packets, 22.1 hours).

| Check | Result |
|---|---|
| Zeek writes only the seven expected logs | pass |
| Every raw record written or counted, one capture port | 612,540 written, 0 dropped (per day 18,829 connection records and 1,589 hourly reports) |
| Every raw record written or counted, two capture ports | 612,540 written, 612,540 duplicates removed |
| Two ports give exactly the records of one port | pass |
| Raw logs deleted after every run | pass |
| Device pseudonyms match MAC addresses one to one | 25 pseudonyms, 25 MAC addresses, 1 router learned |
| No address, name or key in the output | 142 files searched for 974 raw strings (addresses, MAC addresses, DNS names, TLS names) and for address shapes: no hit |
| Files with real addresses exist on the key stick only | pass |
| Without permission for tokens, remote hosts carry a service type only | pass |
| Flow types of the analysis equal those of a second implementation of the same rules (plain Python, record by record, without the database) | 4,800 device-day-types, no difference |
| No new flow type after the first day | pass at all five levels |
| GT-C stops at T = 10 for ε = 0.3 and at T = 7 for ε = 1.0 | all 25 devices, all five levels |
| No alert day in the 14 days after enforcement | pass |

The same test on a scan (the OS scan capture of CICIoMT2024, 38,364 packets in 218 seconds, 30,992
connection records): every check passes, 55,950 device-day-types equal the second implementation.
The scanner tried 1,000 ports on each of two devices. One attempt was answered (port 22) and became
a flow type of the scanned device, the 1,999 others did not. The scanner itself has 1,827 flow
types, as it should. 135 rows a day come from TCP records whose handshake was not seen. Among them
are MQTT sessions that were already running when the capture started. They count as connections of
the clients to port 1883 of the two brokers, also the one in which the broker spoke first.

`tests/live_veth.py` (two virtual capture ports, live Zeek, replay with tcpreplay):

| Check | Result |
|---|---|
| Replay at 50 Mbit/s (33,234 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Replay at 200 Mbit/s (132,934 packets per second) | 1,935,680 of 1,935,680 packets seen on each port, none dropped |
| Replay as fast as the machine allows (735 to 841 Mbit/s reached in three runs, about half a million packets per second on each port) | all packets reached each port. Capture dropped between none and 2.9 percent of the packets of a port, depending on the run: two Zeek processes and two replay processes share two cores here |
| Rotation, anonymisation, duplicates across ports | 44,277 records written, 43,993 duplicates removed |
| Connections that stay open are reported while they are open | 29,796 reports (every 10 seconds in this test) |
| Every completed log a run finds is read and deleted, later ones are left for the next run | 76 logs read and deleted |
| Capture killed in the middle of a log | the open log (3,563 records) was rotated at restart and anonymised on the next run |
| Key removed | recording stopped, RAM emptied, capture not allowed to start again |

`tests/egress_block.py`: without the rule 20 of 20 raw frames left the interface, with the rule 0 of 20.

`tests/batch_size.py`: one run takes 0.50 GB of memory for 142,926 records, 2.43 GB for 714,630 and
4.84 GB for 1,429,260, at about 12,000 records per second.

Zeek itself: 86 MB for the benign capture. During a made-up port scan of 1.5 million unanswered
connection attempts in 30 minutes it needs 289 MB (95 MB with the connection log alone), because
every connection is looked at once more after five minutes. 200,000 stray ACK packets within a
minute take 1,167 MB at the peak, and 200,000 connection attempts from made-up addresses that a
server answers take 1,253 MB (1,080 MB with the connection log alone: about 5.5 kB per flow, as in
any Zeek). Five minutes later 50,000 of these flows are still kept and 150,000 are released.

These runs show that the chain is correct. They do not show what a given board can sustain. Loss
and throughput on the Raspberry Pi 5 are measured before the device is shipped (see `docs/site-setup.md`).

Not run anywhere yet, because they need the device: the installer on a real system (it is tested
against a stand-in folder, `test_installer.py`), the systemd units (their syntax is checked with
`systemd-analyze verify`), the automount of the key stick and the data disk, the effect of the swap
and journal settings, the status light, the hardware clock without its battery, the neighbour table
on a real network, an idle key stick, a clock that is set back. They are tests 1, 6 and 10 to 20 of
`docs/site-setup.md`. The systemd units were
run once under a real systemd manager in a container: the capture unit starts, a failed or
overrunning hourly job empties the RAM disk, and a refused start is not retried.

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

Optional files on the key stick: `site.json` (`{"gateway_macs": [...], "local_nets": [...]}`, where
`local_nets` can only narrow the private ranges: a network outside them is set in the configuration
before the device is shipped, see `docs/site-setup.md`) and
`service_rules.csv` (`domain,category` lines for vendor domains the built-in rules do not know, with
one of the built-in categories). `unclassified_domains.json` lists, for the IT officer only, the
domains of unlabelled remote services.

List the MAC address of every router and firewall in `gateway_macs` before arming. The recorder also
recognises routers by itself (see above), but only once it has seen enough of their traffic, and a
record written before that names the devices behind the router wrongly.

The recorder keeps three more files on the key stick, all with real addresses, none of which leaves
the site: `devices_observed.csv` (the devices seen so far), `gateways_seen.json` (why a MAC address
counts as a router) and `neighbours.json` (which MAC address answers for which IP address).

Before a second recording with the same stick or disk, wipe both. They carry the day count of the
first recording, and the key that links its pseudonyms.

The status light: heartbeat while recording, steady when ready but not armed, fast blink when stopped.
`status.json` on the key stick and the data disk says why.

## Commands

```
python3 -m ibe_recorder status | run | preflight | init-key | arm --approval-ref REF | disarm
python3 -m ibe_recorder extend --days N [--calendar-days M] --approval-ref REF   # after a written extension by the site
python3 -m ibe_recorder export --dest DIR                       # copy with SHA-256 checksums
```

## Known limits

- A device behind a router is named by its MAC address only if the network it sits in is mirrored. Otherwise it is named by its IP address (`ib` marks these records), and an address change then looks like a new device. In the first hour of a recording, before the devices have exchanged ARP, a device behind a router can appear under its IP address as well.
- A router is recognised by the networks behind it or by the packets it forwards between mirrored networks, for devices whose ARP was seen within the last hour. A router that shows neither sign (it leads to an unmirrored local network with few addresses) must be listed in `site.json`. Until a router is recognised or listed, the devices behind it look like one device.
- A host of the site in a routed network outside the private ranges is a remote host (`wan`), unless that network is listed in the configuration before the device is shipped (`local_nets`). The devices on the mirrored networks are recognised by themselves, whatever addresses they use. `status.json` warns when it sees addresses outside the listed networks on the local link.
- Several devices behind one MAC address (a small router that translates addresses, a wireless bridge) are one device. A device that changes its MAC address (private addresses of phones and laptops) is a new device each time.
- A host that is named by its IP address is a device of its own in the records and can have inbound flow types. It has no label, so it is outside the primary group and inside the result over all devices.
- The same address range used in two VLANs is not told apart: the table of who answers for an address is kept per address, not per VLAN.
- A device that answers ARP for addresses of other devices (proxy ARP, a firewall that answers for its VPN clients) is taken for the owner of those addresses.
- Two network cards of one device that use one IP address with two MAC addresses (some forms of teaming) are two devices.
- A remote address is mapped to a domain through DNS answers and TLS server names seen in the last 24 hours. A connection without either gets the service type `unknown` or a port-based type.
- Up to one hour of data is lost at a power failure or a restart of the device, because raw logs live in RAM. A connection that was open at that moment is covered by its hourly reports up to the last full hour.
- Timestamps depend on the device clock. Fit the clock battery: without it the recorder does not record. A machine without a hardware clock does not record either, unless the check is switched off on purpose (`rtc_epoch` empty in the configuration). Then only the limit on hourly batches holds against a clock that starts in the past. A clock that jumps backwards is reported in `status.json` and `coverage.jsonl`. Records stamped before November 2026 or more than a day ahead of the clock are dropped and counted.
- Presence is exact to the clock hour. Reports are written at full hours UTC, so the packets of one report lie in one local day only where local time is a whole number of hours from UTC. Start times are written in whole seconds: a responder whose only packet in a connection falls into the first second after a full hour is also counted in the hour before.
- The MAC addresses of a connection are those of its first packet. If an address moves to another device while a silent connection is still tracked (up to a day), later packets are attributed to the first device.
- A unicast answer to a multicast or broadcast question is a flow of its own. If it comes from a service port that Zeek knows (DNS 53, NetBIOS names 137, mDNS 5353, LLMNR 5355), it counts as the answering device serving that port to the asker. If it comes from any other port (SSDP from 1900, WS-Discovery from 3702, SNMP from 161), it counts as a flow that the answering device opens towards the asker's client port. Client ports from 32768 form one class, lower ones do not. In both cases the asker has no flow type from the answer. The analysis is repeated with roles from the port rules to show how much this matters.
- For UDP the originator is the side that sent the first packet the recorder saw, unless that packet came from a service port. After a restart of the capture, a flow in progress between two other ports can therefore be turned around once.
- Duplicates across capture ports are removed within one hourly batch. A copy that falls into the next batch stays. It carries the same names, so the flow types do not change.
- IP phones choose the UDP ports of every call anew, usually below 32768. At the port and svc levels a call therefore gives both ends new flow types. The results are also reported by device type and without IP phones (`docs/method.md`).
- Two requests from the unspecified address (DHCP) by two devices within one millisecond share one record, with the MAC address of the first.
- Probes that are not connection attempts have no opener, so their roles come from the port rules. An ACK scan from one source port counts as the scanner serving that port, and probes that leave no letter in Zeek's history (no flags, or SYN with FIN) give the sender nothing. Ordinary connection attempts count for the scanner as they should.
- TCP flows that never got going (one side never spoke, or the opener sent a single packet: stray packets, a scan with ACK or FIN packets, connection attempts from made-up addresses that a server answers) are kept for a day like any silent connection, up to 50,000 of them. Beyond that they are dropped after five minutes, as Zeek does by default. A faster flood of such packets needs the memory any Zeek needs for it (about 5.6 kB per packet for five minutes).
- The hourly batch is processed in memory (see `batch_size.py` above). A site with more than about a million connections per hour needs a shorter rotation interval. If a run fails for lack of memory, capture is stopped, the RAM disk is emptied and capture starts again after the next run, so that hour and the one before it are lost.
