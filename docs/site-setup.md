# Site setup

Two people are involved. The researcher prepares and tests the recorder and never sees raw data.
The site's IT officer connects it, holds the key stick and hands over the anonymised files.

## Before shipping (researcher)

All of these produce numbers that go into the paper. Run them on the actual device.

0. **Export key.** On your own computer: `gpg --quick-generate-key ibe-export default default never`, then `gpg --armor --export ibe-export > recorder/recipient.asc`. The installer copies this public key to the device. The private key stays with you. Back it up: without it the encrypted exports cannot be opened.
1. **Install** on a fresh 64-bit Raspberry Pi OS or Debian 12/13: `sudo recorder/install.sh eth1 eth2`, reboot. For a site with three mirrored switches the built-in port is the third capture port (`sudo recorder/install.sh eth0 eth1 eth2`, from the keyboard and screen). Then run tests 3 and 4 with all three ports in use.
2. **Functional tests on the device**: the unit tests, `tests/scenarios.py`, `tests/e2e.py` with any capture file shorter than a day, `tests/egress_block.py`, `tests/live_veth.py`, `tests/batch_size.py`. `sudo recorder/tests/final.sh --benign A.pcap --scan B.pcap --work DIR --pythons python3` runs all of them in one go and keeps the output of each.
3. **Loss and speed.** Replay public captures into both capture ports through a mirroring switch at 100, 300, 600 and 1000 Mbit/s. Record Zeek's packet loss and the CPU load. `coverage.jsonl` holds the packet and drop counters.
4. **72 hours without a break.** Pull the power plug several times. Recording must resume by itself and the files must stay readable.
5. **Temperature** under load with the case closed. It should stay below 80 °C.
6. **Clock.** Fit the rechargeable clock battery and set the clock (`sudo timedatectl set-time`, then `sudo hwclock --systohc`) before shipping. The recorder does not record if the hardware clock has lost its time: pull the power with the battery unplugged and check that `status.json` says "stopped: clock is not set". Leave the device without a network for one to two weeks and measure the offset. Compare the clock again at installation and at collection.
7. **VLAN-tagged frames** from the mirror port are handled (the `vlan` field is filled).
8. **USB power.** No disconnects with the data disk and the key stick plugged in.
9. **Recording limit.** Set `max_recording_days` to 2 and check that capture stops by itself on the third day. The same number also limits the hourly batches (25 per permitted day), and `max_calendar_days` limits the days since the first recording day.
10. **Arm gate.** With the mirror ports connected and no `armed.json`, `status.json` must say "ready, not recording" and the RAM directory must stay empty.
11. **No swap.** After the reboot `cat /proc/swaps` must list nothing. If it lists anything, `status.json` says "stopped: swap to disk is on" and nothing is recorded. Current Raspberry Pi OS sets up compressed swap with a file behind it, which the installer switches off.
12. **Journal in RAM.** `journalctl --header | grep "File path"` must show files under `/run/log/journal` only.
13. **Key stick absent.** Boot without the key stick: `status.json` must say "stopped: key stick missing". Plug it in: the key is created within the hour and the state becomes "ready, not recording".
14. **Fail-safe.** While recording, make `/etc/ibe/config.json` unreadable (add a stray character) and wait for the next run. `status.json` must say "stopped: the configuration is wrong", capture must be stopped and `/run/ibe/raw` must hold no logs. Then run `sudo systemctl start ibe-failsafe.service` by hand and check the same, and that `status.json` now says "stopped: the hourly job failed or was ended" and the light blinks fast. Restore the file.
15. **Long connection.** Keep one connection open through a mirrored port for three hours (for example an SSH session with a command that prints every minute). The anonymised records must contain reports with `"open":true` for it.
16. **Chip variant.** `dmesg | grep -i r8169` must show both ports of the adapter with a chip name the driver knows (RTL8125A, B or D).
17. **Neighbour table.** After an hour of recording on a network with a router, `status.json` must show `neighbours` above zero and `gateways` with one entry, and no record of a device on the mirrored network may carry `ib`. If a second network behind the router can be mirrored as well, a connection between the two networks must carry the device pseudonyms of both ends.
18. **Key stick is the stick.** Unplug the key stick and run `init-key` and `arm` by hand: both must refuse. Nothing may appear in `/mnt/ibe-key` on the system disk.
19. **Idle stick.** Leave the device recording for a day without touching the key stick or the data disk. Every hour must have its file: a stick that the system has put to rest must still count as present.
20. **Clock set back.** While recording, set the clock back by two hours (`sudo timedatectl set-time`). After the next run `status.json` must say that the clock was set back and that capture was restarted, and `/run/ibe/raw` must hold only the open logs of the new capture. Set the clock right afterwards.
21. **Tunnel.** If a device with a VPN or a tunnel is at hand (PPTP, GRE, IPv6 in IPv4), let it send through a mirrored port: its records must show `proto` `unknown_transport` with `ipp` 47, 41 or 4, and no device may appear that does not exist on the network.
22. **Start after power comes back.** With two or three capture ports in use, pull the power and plug it in again five times. After each start all capture services must be running within three minutes (`systemctl is-active 'ibe-zeek@*'`), and `status.json` must say "ok" after the first hourly run.
23. **Brand and model stay at the site.** Fill in `devices.csv` for a few devices: a brand and a model for each, two rows with the same product in different spelling, and one row with the name of a room as its model. After the next run `devices.json` must hold a `model_code` for each of these rows and no brand or model text anywhere, the two spellings must carry the same code, and `models.csv` on the key stick must list every product once, with its code, the number of devices, and the room name as it was typed. Then, after a day of recording on a network with Windows computers, write the name of one of them into the `model` column of a row. After the next run that name must not be in `models.csv`, the row must carry the code of its brand alone, `status.json` must list the line under `device_table_problems`, and `names_seen.json` on the key stick must hold the name.

Ask the site, before shipping, whether any of its own networks uses addresses outside the private ranges
(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7). If so, list all networks of the
institution in `local_nets` of the configuration, and have the written permission cover it: hosts in a
listed network are named by tokens of their addresses. Without the list a server of the institution in
another routed network is recorded as a remote host and cannot be told from the internet afterwards.
The key stick cannot add a network later, it can only take networks away from the list.

Ship the device with `max_recording_days` set to the number of days the site has permitted, `wan_tokens`
set according to the site's written permission, and a key stick and a data disk that are empty. A stick
or disk that was used for an earlier recording must be wiped first: it carries the day count and
the key of that recording.

## At the site (IT officer)

1. Place the recorder next to the switches. Connect power. Do not connect its built-in network port to anything, unless it was prepared as the third capture port.
2. On each managed switch, mirror incoming traffic of every port to a free port and connect that port to one capture port of the recorder (see `recorder/README.md`).
3. Plug in the key stick (FAT32, label `IBE-KEY`) and the data disk (exFAT, label `IBE-DATA`).
4. Wait for the written notice that ethics approval has been granted. Only then copy `armed.json` to the key stick.
5. In the first week, label the devices: `devices_observed.csv` on the key stick lists what was seen. Fill in the columns and save as `devices.csv` on the stick. Do this outside working hours, take the stick out between ten and fifty minutes past the hour and put it back within a few minutes. The stick must be in place at seven minutes past the hour, when the hourly job runs: if it is missing then, capture stops and about two hours are not recorded.
6. Before recording starts, write the MAC address of every router, firewall and layer 3 switch into `site.json` on the key stick: `{"gateway_macs": ["aa:bb:cc:dd:ee:ff"]}`. The recorder also recognises routers by itself, but only after it has seen enough of their traffic, and the records before that name the hosts behind the router wrongly. After the first day, compare `gateways` in `status.json` with the number of routers you know, and read the warnings in the same file. If a router or firewall is replaced during the recording, add the MAC address of the new device to the list before it is connected, keep the old one in the list, and note the date.

| Column | Values |
|---|---|
| `type` | `pc`, `server`, `vm`, `ip_phone`, `printer`, `camera`, `nvr`, `storage`, `medical_device`, `medical_pc`, `switch`, `firewall`, `access_point`, `other` |
| `brand`, `model` | free text, at most 40 plain characters: the product as its maker names it. No names of people or rooms, no computer names, no addresses. This text does not leave the site by itself. The exported files carry a code for each product, and the text is listed once per product in `models.csv` on the key stick (step 8). A cell that looks like an address, or that holds a name by which computers of the site call each other on the network, is dropped and listed in `status.json`. A computer name that the network never showed is not recognised, so do not type one |
| `group` | `agentless` (embedded devices and vendor-managed medical PCs), `general` (PCs, servers, virtual machines), `infrastructure` |
| `visibility` | `full` (all of the device's traffic passes a mirrored port), `partial` (behind an unmanaged switch) |
| `switch` | a letter or a code of up to three characters for the switch the device is connected to |

7. Look at the status light once a week. If it blinks fast, read `status.json` on the key stick.
8. To hand over data, copy the folder `export` (encrypted) from the data disk outside working hours and send it. The recorder keeps a second copy and refills the disk afterwards. The folder `anon` holds the same files in readable form, so that you can see what leaves. The brands and models are not among them. They stand in `models.csv` on the key stick, one line for each product. Open that file and read every line (take the stick out as in step 5). If a line names a person, a room or a computer, correct `devices.csv` and wait for the next hourly run, at seven minutes past the hour. Then copy the lines into the text of your e-mail to the researcher, and send them again whenever the device table has changed. Do not attach files from the key stick.
9. Do not replace the key stick by another one during the recording. A new stick gets a new key, and devices before and after can no longer be matched. `status.json` reports it if it happens.
10. At the end, keep or destroy the key stick. It holds the key, the files with real addresses and names (`devices.csv`, `devices_observed.csv`, `gateways_seen.json`, `neighbours.json`, `names_seen.json`) and the list of brands and models (`models.csv`). Without it the pseudonyms cannot be linked to devices by anyone.

## What the researcher receives

`anon-*.jsonl.gz`, `devices.json`, `coverage.jsonl`, `status.json`, each encrypted (`.gpg`). Nothing else leaves the site by itself.
Decrypt with `gpg --decrypt-files export/*.gpg`.

The brands and models arrive apart, as lines that the IT officer has read and copied into an e-mail
(`code,brand,model,devices`). The code of a line is the `model_code` of its devices in `devices.json`, and
`models_in_table` in `status.json` says how many lines there should be.
