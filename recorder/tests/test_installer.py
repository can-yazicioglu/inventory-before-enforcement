# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Runs install.sh against a folder that stands for the system disk and checks every file it leaves.

The commands that would change the running system (apt-get, systemctl, swapoff, ip, rfkill, curl, gpg)
are replaced by stand-ins that only write down how they were called.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from ibe_recorder import pipeline  # noqa: E402

INSTALL = os.path.join(HERE, "..", "install.sh")
FSTAB = ("# /etc/fstab\n"
         "PARTUUID=1234-01  /boot/firmware  vfat  defaults  0  2\n"
         "PARTUUID=1234-02  /  ext4  defaults,noatime  0  1\n"
         "/var/swapfile none swap sw 0 0\n"
         "#UUID=aaaa none swap sw 0 0\n")
STUB = """#!/bin/bash
echo "$(basename "$0") $*" >> "$IBE_ROOT/calls.log"
case "$(basename "$0") $*" in
    "apt-get install"*zeek-8.0-core*)
        mkdir -p "$IBE_ROOT/opt/zeek/bin"
        printf '#!/bin/bash\\necho "zeek version 8.0.0-stand-in"\\n' > "$IBE_ROOT/opt/zeek/bin/zeek"
        chmod +x "$IBE_ROOT/opt/zeek/bin/zeek" ;;
    "ip -4 -o addr show dev "*)
        if [ -f "$IBE_ROOT/has-address-$6" ]; then echo "2: $6 inet 192.168.1.5/24"; fi ;;
    "gpg --dearmor") cat > /dev/null; echo key ;;
    "curl "*) echo armored-key ;;
esac
exit 0
"""


def fake_install(root, ifaces, version="13", pi=True, run=True):
    """Prepare a stand-in system below 'root' and run install.sh on it. Returns the finished process."""
    for d in ["etc", "bin-stubs", "etc/NetworkManager/conf.d"] + [f"sys/class/net/{i}" for i in ifaces]:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    if pi:
        os.makedirs(os.path.join(root, "etc/rpi"), exist_ok=True)
        os.makedirs(os.path.join(root, "boot/firmware"), exist_ok=True)
        if not os.path.exists(os.path.join(root, "boot/firmware/config.txt")):
            with open(os.path.join(root, "boot/firmware/config.txt"), "w") as f:
                f.write("# config\ndtparam=audio=on\n[all]\n")
    with open(os.path.join(root, "etc/os-release"), "w") as f:
        f.write(f'PRETTY_NAME="Stand-in GNU/Linux {version}"\nVERSION_ID="{version}"\n')
    if not os.path.exists(os.path.join(root, "etc/fstab")):
        with open(os.path.join(root, "etc/fstab"), "w") as f:
            f.write(FSTAB)
    for name in ("apt-get", "systemctl", "swapoff", "ip", "rfkill", "curl", "gpg"):
        path = os.path.join(root, "bin-stubs", name)
        with open(path, "w") as f:
            f.write(STUB)
        os.chmod(path, 0o755)
    if not run:
        return None
    env = dict(os.environ, IBE_ROOT=root, PATH=os.path.join(root, "bin-stubs") + os.pathsep + os.environ["PATH"])
    return subprocess.run(["bash", INSTALL] + list(ifaces), env=env, capture_output=True, text=True)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, rel):
        with open(os.path.join(self.root, rel), encoding="utf-8") as f:
            return f.read()

    def source(self, *rel):
        with open(os.path.join(HERE, "..", *rel), encoding="utf-8") as f:
            return f.read()

    def test_files_left_on_a_raspberry_pi(self):
        r = fake_install(self.root, ["eth1", "eth2"])
        self.assertEqual(r.returncode, 0, r.stdout[-800:] + r.stderr[-800:])
        cfg = json.loads(self.read("etc/ibe/config.json"))
        self.assertEqual(cfg["interfaces"], ["eth1", "eth2"])
        self.assertIsNone(pipeline.config_problem(dict(pipeline.DEFAULTS, **cfg)))
        fstab = self.read("etc/fstab").splitlines()
        self.assertIn("#/var/swapfile none swap sw 0 0", fstab)              # swap line switched off
        self.assertIn("#UUID=aaaa none swap sw 0 0", fstab)                  # an old comment is left alone
        self.assertEqual(fstab[:3], FSTAB.splitlines()[:3])                  # nothing else is touched
        self.assertEqual([x for x in fstab if "swap" in x and not x.startswith("#")], [])
        for label, where, kind in (("IBE-KEY", "/mnt/ibe-key", "vfat"), ("IBE-DATA", "/mnt/ibe-data", "exfat")):
            line = [x for x in fstab if x.startswith(f"LABEL={label} ")]
            self.assertEqual(len(line), 1)
            self.assertEqual(line[0].split()[1:3], [where, kind])
            for opt in ("noauto", "nofail", "x-systemd.automount", "umask=077"):
                self.assertIn(opt, line[0].split()[3].split(","))
        ram = [x for x in fstab if x.startswith("tmpfs /run/ibe ")]
        self.assertEqual(len(ram), 1)
        self.assertIn("noexec", ram[0])
        self.assertEqual(self.read("etc/rpi/swap.conf.d/90-ibe.conf"), "[Main]\nMechanism=none\n")
        self.assertEqual(self.read("etc/systemd/journald.conf.d/90-ibe.conf"), "[Journal]\nStorage=volatile\nRuntimeMaxUse=64M\n")
        for i in ("eth1", "eth2"):
            rule = self.read(f"etc/ibe/egress-{i}.nft")
            self.assertIn(f'hook egress device "{i}" priority 0; policy drop;', rule)
            self.assertEqual(rule.count(f"table netdev ibe_{i}"), 3)          # create, delete, create: safe to load twice
        self.assertEqual(self.read("etc/sysctl.d/90-ibe.conf"),
                         "net.ipv6.conf.eth1.disable_ipv6 = 1\nnet.ipv6.conf.eth2.disable_ipv6 = 1\n")
        self.assertEqual(self.read("etc/NetworkManager/conf.d/90-ibe-unmanaged.conf"),
                         "[keyfile]\nunmanaged-devices=interface-name:eth1;interface-name:eth2\n")
        boot = self.read("boot/firmware/config.txt").splitlines()
        for line in ("dtoverlay=disable-wifi", "dtoverlay=disable-bt", "dtparam=rtc_bbat_vchg=3000000", "dtparam=pciex1"):
            self.assertEqual(boot.count(line), 1)
        self.assertEqual(boot[:3], ["# config", "dtparam=audio=on", "[all]"])
        for unit in sorted(os.listdir(os.path.join(HERE, "..", "systemd"))):
            self.assertEqual(self.read(f"etc/systemd/system/{unit}"), self.source("systemd", unit))
        self.assertEqual(sorted(os.listdir(os.path.join(HERE, "..", "systemd"))),
                         ["ibe-anonymise.service", "ibe-anonymise.timer", "ibe-failsafe.service", "ibe-zeek@.service"])
        self.assertTrue(os.path.exists(os.path.join(self.root, "opt/ibe/ibe_recorder/pipeline.py")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "opt/ibe/ibe_recorder/public_suffix_list.dat")))
        self.assertEqual(self.read("opt/ibe/zeek/ibe.zeek"), self.source("zeek", "ibe.zeek"))
        self.assertEqual(oct(os.stat(os.path.join(self.root, "var/lib/ibe")).st_mode & 0o777), "0o700")
        calls = self.read("calls.log").splitlines()
        for want in ("swapoff -a", "systemctl mask swap.target", "systemctl disable --now dphys-swapfile.service",
                     "systemctl disable --now rpi-zram-writeback.timer", "systemctl enable ibe-anonymise.timer",
                     "systemctl enable ibe-zeek@eth1.service", "systemctl enable ibe-zeek@eth2.service",
                     "ip link set eth1 down", "ip link set eth2 down", "rfkill block all"):
            self.assertIn(want, calls)
        self.assertFalse(any("start" in c.split() for c in calls))            # the installer starts nothing

    def test_second_run_changes_nothing(self):
        self.assertEqual(fake_install(self.root, ["eth1", "eth2"]).returncode, 0)
        cfg_path = os.path.join(self.root, "etc/ibe/config.json")
        with open(cfg_path, "w") as f:
            json.dump({"site": "B", "interfaces": ["eth1", "eth2"]}, f)       # the site's own settings
        keep = ("etc/fstab", "boot/firmware/config.txt", "etc/sysctl.d/90-ibe.conf", "etc/ibe/egress-eth1.nft",
                "etc/ibe/config.json")
        before = {k: self.read(k) for k in keep}
        self.assertEqual(fake_install(self.root, ["eth1", "eth2"]).returncode, 0)
        self.assertEqual({k: self.read(k) for k in keep}, before)

    def test_refusals(self):
        r = fake_install(self.root, ["eth1"], version="11")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Debian 12 or 13", r.stdout)
        fake_install(self.root, ["eth1"], run=False)                          # a supported system again
        env = dict(os.environ, IBE_ROOT=self.root, PATH=os.path.join(self.root, "bin-stubs") + os.pathsep + os.environ["PATH"])
        for args, text in ((["eth9"], "no such interface"), (["eth1;reboot"], "unusable interface name"), ([], "usage")):
            r = subprocess.run(["bash", INSTALL] + args, env=env, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, args)
            self.assertIn(text, r.stdout, args)
        open(os.path.join(self.root, "has-address-eth1"), "w").close()       # the port one is logged in through
        r = subprocess.run(["bash", INSTALL, "eth1"], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("has an IP address", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/ibe")))  # nothing was installed by any of them

    def test_plain_debian_and_odd_interface_names(self):
        r = fake_install(self.root, ["enp1s0", "eth1.20"], version="12", pi=False)
        self.assertEqual(r.returncode, 0, r.stdout[-800:] + r.stderr[-800:])
        self.assertEqual(json.loads(self.read("etc/ibe/config.json"))["interfaces"], ["enp1s0", "eth1.20"])
        self.assertIn("table netdev ibe_eth1_20 {", self.read("etc/ibe/egress-eth1.20.nft"))
        self.assertIn('device "eth1.20"', self.read("etc/ibe/egress-eth1.20.nft"))
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/rpi")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "boot")))


if __name__ == "__main__":
    unittest.main()
