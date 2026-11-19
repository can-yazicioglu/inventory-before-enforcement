# Platform selection

The recorder and the enforcement gateway share one hardware design: a Raspberry Pi 5 (quad-core
Cortex-A76, 8 GB) with a dual-port RTL8125 Ethernet adapter on its single PCIe 2.0 lane.

Requirements: at least two capture ports that are not USB, a battery-backed clock for operation
without a network, hardware AES, the ability to switch all radios off, a documented production
lifetime, and a cost low enough for a small clinic.

| Class | Decision | Reason |
|---|---|---|
| Raspberry Pi 5 with a PCIe dual 2.5 GbE adapter | selected | meets every requirement at the lowest cost |
| Raspberry Pi 4 | ruled out | no accessible PCIe lane and no on-board clock |
| Microcontrollers (ESP32 class) | ruled out | cannot run a Linux network stack or Zeek |
| FPGA platforms (NetFPGA SUME class) | ruled out | built for 10 Gbit/s and above, cost and development effort without benefit at 1 Gbit/s links |
| Fanless x86 box with four Intel I226 ports | scale-up path | the more capable recorder for large hospital networks, at a higher price |

In the kernel series used here (Raspberry Pi kernel 6.12, checked in branch rpi-6.12.y at version
6.12.118 on 19 November 2026) neither the on-board Ethernet driver of the Raspberry Pi 5 (macb) nor
the RTL8125 driver (r8169) supports native XDP. The enforcement cost reported in the study is
therefore that of the portable nftables kernel path, a conservative upper bound relative to
accelerated data planes. XDP support for macb was under review upstream in 2026, so this must be
rechecked for any later kernel.

The adapter is a PCIe packet switch with two RTL8125 controllers (boards of this design are sold by
several vendors). The in-kernel r8169 driver of the Raspberry Pi kernel handles the RTL8125A, B and D
variants (branch rpi-6.12.y), so no vendor driver is installed. The PCIe connector must be switched on
with `dtparam=pciex1`, which the installer does. The same kernel is built with zram writeback
(`CONFIG_ZRAM_WRITEBACK=y`), which is why the recorder checks that no swap can reach a disk.

The software has no board-specific code. It needs Linux (arm64 or amd64), Python 3.11 or later
(standard library only, tested with 3.11, 3.12 and 3.13), Zeek 8.0, nftables and one network
interface per mirror port.

Parts per recorder: the board, the official 27 W power supply, the dual 2.5 GbE PCIe adapter, a
cooler, the rechargeable clock battery, an endurance microSD card, a USB SSD for the data, a small
USB stick for the key, Ethernet cables.
