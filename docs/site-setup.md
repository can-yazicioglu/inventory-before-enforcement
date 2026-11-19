# Site setup

Two people are involved. The researcher prepares and tests the recorder and never sees raw data.
The site's IT officer connects it, holds the key stick and hands over the anonymised files.

## Before shipping (researcher)

All of these produce numbers that go into the paper. Run them on the actual device.

0. **Export key.** On your own computer: `gpg --quick-generate-key ibe-export default default never`, then `gpg --armor --export ibe-export > recorder/recipient.asc`. The installer copies this public key to the device. The private key stays with you. Back it up: without it the encrypted exports cannot be opened.
1. **Install** on a fresh 64-bit Raspberry Pi OS or Debian 12/13: `sudo recorder/install.sh eth1 eth2`, reboot.
2. **Functional tests on the device**: the unit tests, `tests/scenarios.py`, `tests/e2e.py` with any capture file shorter than a day, `tests/egress_block.py`, `tests/live_veth.py`, `tests/batch_size.py`.
3. **Loss and speed.** Replay public captures into both capture ports through a mirroring switch at 100, 300, 600 and 1000 Mbit/s. Record Zeek's packet loss and the CPU load. `coverage.jsonl` holds the packet and drop counters.
4. **72 hours without a break.** Pull the power plug several times. Recording must resume by itself and the files must stay readable.
5. **Temperature** under load with the case closed. It should stay below 80 °C.
6. **Clock drift.** Leave the device without a network for one to two weeks and measure the offset. Compare the clock again at installation and at collection. Fit the rechargeable clock battery.
7. **VLAN-tagged frames** from the mirror port are handled (the `vlan` field is filled).
8. **USB power.** No disconnects with the data disk and the key stick plugged in.
9. **Recording limit.** Set `max_recording_days` to 2 and check that capture stops by itself on the third day.
10. **Arm gate.** With the mirror ports connected and no `armed.json`, `status.json` must say "ready, not recording" and the RAM directory must stay empty.
11. **No swap.** After the reboot `cat /proc/swaps` must list nothing. If it lists anything, `status.json` says "stopped: swap to disk is on" and nothing is recorded. Current Raspberry Pi OS sets up compressed swap with a file behind it, which the installer switches off.
12. **Journal in RAM.** `journalctl --header | grep "File path"` must show files under `/run/log/journal` only.
13. **Key stick absent.** Boot without the key stick: `status.json` must say "stopped: key stick missing". Plug it in: the key is created within the hour and the state becomes "ready, not recording".
14. **Fail-safe.** While recording, make `/etc/ibe/config.json` unreadable (add a stray character) and wait for the next run. `status.json` must say "stopped: the configuration is wrong", capture must be stopped and `/run/ibe/raw` must hold no logs. Then run `sudo systemctl start ibe-failsafe.service` by hand and check the same. Restore the file.
15. **Long connection.** Keep one connection open through a mirrored port for three hours (for example an SSH session with a command that prints every minute). The anonymised records must contain reports with `"open":true` for it.
16. **Chip variant.** `dmesg | grep -i r8169` must show both ports of the adapter with a chip name the driver knows (RTL8125A, B or D).

Ship the device with `max_recording_days` set to the number of days the site has permitted, `wan_tokens`
set according to the site's written permission, and no key stick content.

## At the site (IT officer)

1. Place the recorder next to the switches. Connect power. Do not connect its built-in network port to anything.
2. On each managed switch, mirror incoming traffic of every port to a free port and connect that port to one capture port of the recorder (see `recorder/README.md`).
3. Plug in the key stick (FAT32, label `IBE-KEY`) and the data disk (exFAT, label `IBE-DATA`).
4. Wait for the written notice that ethics approval has been granted. Only then copy `armed.json` to the key stick.
5. In the first week, label the devices: `devices_observed.csv` on the key stick lists what was seen. Fill in the columns and save as `devices.csv` on the stick. Do this outside working hours and put the stick back within a few minutes: if the stick is missing when the hourly job runs (seven minutes past the hour), that hour is not recorded.
6. If a router or a layer 3 switch connects local networks to each other and is not the way to the internet, write its MAC address into `site.json` on the key stick: `{"gateway_macs": ["aa:bb:cc:dd:ee:ff"]}`. The way to the internet is found automatically. Without this, every device behind that router would look like one device.

| Column | Values |
|---|---|
| `type` | `pc`, `server`, `vm`, `ip_phone`, `printer`, `camera`, `nvr`, `storage`, `medical_device`, `medical_pc`, `switch`, `firewall`, `access_point`, `other` |
| `brand`, `model` | free text, at most 40 plain characters, no names of people or rooms |
| `group` | `agentless` (embedded devices and vendor-managed medical PCs), `general` (PCs, servers, virtual machines), `infrastructure` |
| `visibility` | `full` (all of the device's traffic passes a mirrored port), `partial` (behind an unmanaged switch) |
| `switch` | a letter for the switch the device is connected to |

7. Look at the status light once a week. If it blinks fast, read `status.json` on the key stick.
8. To hand over data, copy the folder `export` (encrypted) from the data disk outside working hours and send it. The recorder keeps a second copy and refills the disk afterwards.
9. Do not replace the key stick by another one during the recording. A new stick gets a new key, and devices before and after can no longer be matched. `status.json` reports it if it happens.
10. At the end, keep or destroy the key stick. Without it the pseudonyms cannot be linked to devices by anyone.

## What the researcher receives

`anon-*.jsonl.gz`, `devices.json`, `coverage.jsonl`, `status.json`, each encrypted (`.gpg`). Nothing else leaves the site.
Decrypt with `gpg --decrypt-files export/*.gpg`.
