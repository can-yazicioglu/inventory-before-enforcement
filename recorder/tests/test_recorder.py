# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
import gzip
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ibe_recorder import core, pipeline  # noqa: E402

KEY = bytes(range(32))
PZ = core.Pseudonymiser(KEY)
SCOPE = core.Scope()
HERE = os.path.dirname(os.path.abspath(pipeline.__file__))
PSL = core.PublicSuffix(os.path.join(HERE, "public_suffix_list.dat"))
with open(os.path.join(HERE, "service_rules.csv"), encoding="utf-8") as _f:
    CAT = core.Categoriser(_f.read().splitlines())
GW = "00:11:22:33:44:55"
DEV1, DEV2 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
T0 = 1798538400            # 2026-12-29 10:00 UTC, 13:00 in Istanbul
NOW = T0 + 3600


def conn(oh, rh, omac, rmac, op=50000, rp=443, proto="tcp", ts=T0 + 0.5, hist="ShADadFf", **kw):
    r = {"ts": ts, "uid": "Cx", "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "proto": proto, "duration": 1.5, "orig_bytes": 100, "resp_bytes": 200, "conn_state": "SF",
         "history": hist, "orig_pkts": 5, "resp_pkts": 4, "orig_l2_addr": omac, "resp_l2_addr": rmac}
    r.update(kw)
    return r


def tr(rec, tokens=False, names=None, gateways=(core.norm_mac(GW),), is_open=False, neigh=None):
    return core.transform(rec, PZ, SCOPE, set(gateways), tokens, names or {}, PSL, CAT, 0, is_open, neigh)


def neighbours(*sightings):
    n = core.Neighbours()
    for ts, ip, mac in sightings:
        n.see(ts, ip, mac)
    return n


class CoreTests(unittest.TestCase):
    def test_pseudonym_is_stable_and_keyed(self):
        self.assertEqual(PZ.device("AA-BB-CC-00-00-01"), PZ.device(DEV1))
        self.assertNotEqual(PZ.device(DEV1), PZ.device(DEV2))
        self.assertNotEqual(PZ.device(DEV1), core.Pseudonymiser(bytes(32)).device(DEV1))
        self.assertRegex(PZ.device(DEV1), r"^d[a-z2-7]{10}$")

    def test_scope(self):
        self.assertEqual(SCOPE.of("192.168.1.5"), "lan")
        self.assertEqual(SCOPE.of("8.8.8.8", GW), "wan")
        self.assertEqual(SCOPE.of("8.8.8.8"), "wan")
        self.assertEqual(SCOPE.of("193.140.1.7", DEV1), "wan")                 # whatever MAC address the frame carries
        self.assertEqual(SCOPE.of("193.140.1.7", DEV1, on_link=True), "lan")   # public space used inside, seen in ARP
        self.assertEqual(SCOPE.of("224.0.0.251"), "mcast")
        self.assertEqual(SCOPE.of("192.168.1.255", "ff:ff:ff:ff:ff:ff"), "bcast")
        self.assertEqual(SCOPE.of("fe80::1"), "lan")

    def test_group_labels_hide_addresses(self):
        self.assertEqual(core.group_label("224.0.0.251", PZ), "mcast:mdns")
        self.assertEqual(core.group_label("ff02::1:ff12:3456", PZ), "mcast:sn")
        self.assertEqual(core.group_label("ff02::1:ffab:cdef", PZ), "mcast:sn")
        self.assertRegex(core.group_label("239.1.2.3", PZ), r"^mcast:og[a-z2-7]{8}$")
        self.assertEqual(core.group_label("255.255.255.255", PZ), "bcast")

    def test_public_suffix(self):
        self.assertEqual(PSL.registrable("a.b.co.uk"), "b.co.uk")
        self.assertEqual(PSL.registrable("x.y.example.com.tr"), "example.com.tr")
        self.assertEqual(PSL.registrable("router7.teamviewer.com"), "teamviewer.com")
        self.assertEqual(PSL.registrable("co.uk"), None)
        self.assertEqual(PSL.registrable("10.1.2.3"), None)

    def test_lan_to_wan_without_tokens(self):
        rec, why = tr(conn("192.168.1.10", "52.1.2.3", DEV1, GW), names={"52.1.2.3": "router7.teamviewer.com"})
        self.assertIsNone(why)
        self.assertEqual((rec["o"], rec["r"], rec["os"], rec["rs"]), (PZ.device(DEV1), "wan", "lan", "wan"))
        self.assertEqual(rec["wc"], "remote_access")
        self.assertNotIn("wh", rec)
        self.assertIsNone(core.leak_check(rec))

    def test_lan_to_wan_with_tokens(self):
        a, _ = tr(conn("192.168.1.10", "52.1.2.3", DEV1, GW), tokens=True, names={"52.1.2.3": "x.example.com"})
        b, _ = tr(conn("192.168.1.11", "52.1.2.99", DEV2, GW), tokens=True)
        self.assertEqual(a["wn"], b["wn"])            # same /24
        self.assertNotEqual(a["wh"], b["wh"])
        self.assertRegex(a["wd"], r"^m[a-z2-7]{10}$")
        self.assertEqual(b["wd"], "")
        self.assertIsNone(core.leak_check(a))

    def test_inbound_and_lan_to_lan(self):
        rec, _ = tr(conn("8.8.4.4", "192.168.1.10", GW, DEV1))
        self.assertEqual((rec["o"], rec["r"]), ("wan", PZ.device(DEV1)))
        rec, _ = tr(conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=445))
        self.assertEqual((rec["o"], rec["r"], rec["ib"]), (PZ.device(DEV1), PZ.device(DEV2), ""))
        self.assertNotIn("wc", rec)

    def test_routed_local_peer_falls_back_to_ip(self):
        rec, _ = tr(conn("192.168.1.10", "10.9.9.9", DEV1, GW))
        self.assertEqual(rec["ib"], "r")
        self.assertEqual(rec["r"], PZ.device_by_ip("10.9.9.9"))

    def test_multicast_and_drops(self):
        rec, _ = tr(conn("192.168.1.10", "239.255.255.250", DEV1, "01:00:5e:7f:ff:fa", proto="udp", rp=1900))
        self.assertEqual((rec["r"], rec["rs"]), ("mcast:ssdp", "mcast"))
        self.assertEqual(tr(conn("8.8.8.8", "1.1.1.1", GW, GW))[1], "no_local_endpoint")
        igmp, _ = tr(conn("192.168.1.10", "224.0.0.22", DEV1, "01:00:5e:00:00:16", proto="unknown_transport",
                          op=0, rp=0, ip_proto=2))
        self.assertEqual((igmp["proto"], igmp["ipp"], igmp["r"]), ("unknown_transport", 2, "mcast:igmp"))
        self.assertIsNone(core.leak_check(igmp))
        self.assertEqual(tr({"ts": 1})[1], "malformed")

    def test_established(self):
        self.assertTrue(core.established({"proto": "tcp", "history": "ShADadFf"}))
        self.assertFalse(core.established({"proto": "tcp", "history": "S"}))
        self.assertFalse(core.established({"proto": "tcp", "history": "Sr"}))          # refused
        self.assertFalse(core.established({"proto": "tcp", "history": "Ar"}))          # stray packet, reset
        self.assertFalse(core.established({"proto": "tcp", "history": "SAD"}))         # only the originator spoke
        for h in ("Da", "Dd", "^dA", "DAf", "ShR"):                                    # handshake not seen, or reset later
            self.assertTrue(core.established({"proto": "tcp", "history": h}), h)
        self.assertTrue(core.established({"proto": "udp", "resp_pkts": 1}))
        self.assertFalse(core.established({"proto": "udp", "resp_pkts": 0, "resp_bytes": 0}))
        self.assertFalse(core.established({"proto": "udp"}))
        # a report about an open connection counts one interval: the responder must have sent in it
        self.assertTrue(core.established({"proto": "tcp", "history": "ShADad", "resp_pkts": 2}, True))
        self.assertFalse(core.established({"proto": "tcp", "history": "ShADad", "resp_pkts": 0}, True))
        self.assertFalse(core.established({"proto": "udp", "history": "Dd", "resp_pkts": 0}, True))
        # The packet that moves the clock over the full hour is left for the next report, its bytes are not:
        # bytes without a packet do not make the responder present in the hour before its packet
        self.assertFalse(core.established({"proto": "tcp", "history": "ShADad", "resp_pkts": 0, "resp_bytes": 20}, True))
        self.assertFalse(core.established({"proto": "udp", "history": "Dd", "resp_pkts": 0, "resp_bytes": 20}, True))
        self.assertTrue(core.established({"proto": "udp", "history": "Dd", "resp_pkts": 0, "resp_bytes": 20}))

    def test_open_report(self):
        rec, why = tr(conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=1883, hist="ShADad"), is_open=True)
        self.assertIsNone(why)
        self.assertIs(rec["open"], True)
        self.assertIsNone(core.leak_check(rec))
        self.assertIsNotNone(core.leak_check(dict(rec, open="yes")))
        self.assertNotIn("open", tr(conn("192.168.1.10", "192.168.1.20", DEV1, DEV2))[0])

    def test_malformed_records_are_dropped_not_fatal(self):
        good = conn("192.168.1.10", "52.1.2.3", DEV1, GW)
        for change in ({"ts": None}, {"ts": "x"}, {"ts": 0}, {"ts": float("inf")}, {"ts": float("nan")},
                       {"duration": "long"}, {"duration": float("inf")}, {"id.orig_h": None}, {"id.orig_h": 5},
                       {"id.resp_h": "not an address"}, {"id.resp_h": ["52.1.2.3"]}, {"orig_l2_addr": "zz:zz"},
                       {"orig_l2_addr": 7}, {"resp_l2_addr": {"a": 1}}, {"proto": "tcp udp"}, {"proto": None},
                       {"proto": "x" * 30}):
            self.assertEqual(tr(dict(good, **change)), (None, "malformed"), change)
        v6 = conn("fe80::1", "fe80::2", "bad mac", DEV2)
        self.assertEqual(tr(v6), (None, "malformed"))
        # odd but harmless values are neutralised, never copied
        rec, why = tr(dict(good, history="Sh<script>", service="Dr. Ahmet", conn_state="192.168.1.10",
                           vlan="x", orig_bytes="many", resp_pkts=None, **{"id.orig_p": "http"}))
        self.assertIsNone(why)
        self.assertEqual((rec["hist"], rec["svc"], rec["st"], rec["vlan"], rec["ob"], rec["rpk"], rec["op"]),
                         ("", "", "", -1, 0, 0, -1))
        self.assertIsNone(core.leak_check(rec))

    def test_random_records_never_leak_or_crash(self):
        """Any record, however broken, is either dropped or passes the whitelist and the address scan."""
        rnd = random.Random(20261118)
        ips = ["192.168.1.10", "10.0.0.7", "172.16.5.5", "52.1.2.3", "8.8.8.8", "193.140.1.7", "224.0.0.251",
               "239.1.2.3", "255.255.255.255", "192.168.1.255", "0.0.0.0", "fe80::1", "fd00::5", "2a00:1450:4017::200e",
               "ff02::fb", "ff02::1:ff12:3456", "ff05::c", "::", "::ffff:192.168.1.9", "169.254.3.4", "100.64.1.1"]
        macs = [DEV1, DEV2, GW, "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "33:33:00:00:00:fb", "", "AA-BB-CC-00-00-01"]
        junk = [None, "", 0, -1, 3.5, True, [], {}, "x", "192.168.1.10", "aa:bb:cc:00:00:01", "fe80::1", "a" * 300,
                float("nan"), float("inf"), 2 ** 70, "\u00e7", "tcp", "dns,ssl"]
        fields = list(conn("192.168.1.10", "52.1.2.3", DEV1, GW)) + ["vlan", "service", "ip_proto", "extra"]
        # a neighbour table fed with the same mixture: whatever it holds, only pseudonyms come out
        table = core.Neighbours()
        for _ in range(4000):
            table.see(rnd.choice([T0, T0 - 9000, T0 + 9000, "x", None, float("nan")]), rnd.choice(ips + junk), rnd.choice(macs + junk))
        self.assertGreater(len(table.table), 10)
        written = dropped = 0
        for _ in range(20000):
            r = conn(rnd.choice(ips), rnd.choice(ips), rnd.choice(macs), rnd.choice(macs), op=rnd.randrange(0, 70000),
                     rp=rnd.choice([0, 53, 123, 443, 1900, 5353, 40000, 65535]),
                     proto=rnd.choice(["tcp", "udp", "icmp", "unknown_transport"]), service=rnd.choice(["", "dns", "ssl"]))
            for _ in range(rnd.choice([0, 0, 1, 2])):
                r[rnd.choice(fields)] = rnd.choice(junk)
            names = {r["id.resp_h"]: rnd.choice(["a.example.com", "x.teamviewer.com", 5, None, "192.168.1.10"])} \
                if isinstance(r["id.resp_h"], str) else {}
            rec, why = tr(r, tokens=rnd.random() < 0.5, names=names, is_open=rnd.random() < 0.2,
                          neigh=rnd.choice([None, table]))
            if rec is None:
                self.assertIn(why, ("malformed", "group_source", "no_local_endpoint"))
                dropped += 1
                continue
            written += 1
            self.assertIsNone(core.leak_check(rec), rec)
            text = json.dumps(rec, separators=(",", ":"), sort_keys=True)
            self.assertIsNone(core.scan_text(text), text)
            self.assertEqual(json.loads(text), rec)                 # valid JSON, no NaN
            for raw in ips[:6] + ips[11:14] + [DEV1, DEV2, GW, "aabbcc", "example", "teamviewer"]:
                self.assertNotIn(raw, text)
        self.assertGreater(written, 5000)
        self.assertGreater(dropped, 5000)

    def test_scan_text_shapes(self):
        for bad in ("10.0.0.1", "x=255.255.255.255,", "::ffff:10.1.2.3", "2001:db8::1", "fe80::a00:27ff:fe4e:66a1",
                    "ff02::1:ff12:3456", "1:2:3:4:5:6:7:8", "00:1A:2B:3C:4D:5E", "00-1a-2b-3c-4d-5e", "fd00::", "::1"):
            self.assertIsNotNone(core.scan_text(f'{{"a":"{bad}"}}'), bad)
        for ok in ('{"dur":0.123,"ts":1798538400,"rp":443}', '{"o":"dabcdefghij","r":"mcast:mdns","st":"SF"}',
                   '{"t": 1798538400, "version": "0.4.0", "stats": [[1798538400, 12], [1798538700, 0]]}',
                   '"day": "2026-12-29"', '"loss_mean":0.25,"loss_max":1.5'):
            self.assertIsNone(core.scan_text(ok), ok)

    def test_leak_check_and_scan(self):
        rec, _ = tr(conn("192.168.1.10", "52.1.2.3", DEV1, GW), tokens=True)
        self.assertIsNone(core.scan_text(json.dumps(rec, separators=(",", ":"))))
        self.assertIsNotNone(core.leak_check(dict(rec, o="192.168.1.10")))
        self.assertIsNotNone(core.leak_check(dict(rec, host="pc-reception")))
        self.assertIsNotNone(core.leak_check(dict(rec, svc="Dr. Ahmet")))
        for bad in ("x 192.168.1.10 y", "aa:bb:cc:00:00:01", "AA-BB-CC-00-00-01", "fe80::1", "2001:db8:0:1::5", "a ::1 b"):
            self.assertIsNotNone(core.scan_text(bad), bad)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.cfg = dict(pipeline.DEFAULTS, raw_dir=f"{t}/raw", data_dirs=[f"{t}/ssd/anon", f"{t}/sd/anon"],
                        key_dir=f"{t}/key", state_dir=f"{t}/state", manage_services=False,
                        gateway_macs=[GW], interfaces=["eth1", "eth2"], sysfs_net=f"{t}/sys",
                        proc_swaps=f"{t}/no-swaps", raise_errors=True, require_ram_disk=False,
                        require_key_mount=False, rtc_epoch="")
        with open(f"{t}/no-swaps", "w") as f:
            f.write("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")
        for d in ("raw/eth1", "raw/eth2", "key", "state", "sys/eth1/statistics", "sys/eth2/statistics"):
            os.makedirs(f"{t}/{d}")
        with open(f"{t}/key/hmac.key", "w") as f:
            f.write(KEY.hex())
        self.link("eth1", 1, 1000)
        self.link("eth2", 1, 1000)

    def tearDown(self):
        self.tmp.cleanup()

    def link(self, iface, carrier, rx):
        base = os.path.join(self.cfg["sysfs_net"], iface)
        for name, v in (("carrier", carrier), ("statistics/rx_packets", rx)):
            with open(os.path.join(base, name), "w") as f:
                f.write(f"{v}\n")

    def arm(self, text='{"approval_ref": "2026/12-05"}'):
        with open(os.path.join(self.cfg["key_dir"], "armed.json"), "w") as f:
            f.write(text)

    def write(self, iface, stem, records, active=False):
        name = f"{stem}.log" if active else f"{stem}.2026-12-29-10-00-00.log"
        with open(os.path.join(self.cfg["raw_dir"], iface, name), "a") as f:
            f.write("".join(json.dumps(r) + "\n" for r in records))

    def read(self, *parts):
        with open(os.path.join(*parts), "rb") as f:
            raw = f.read()
        return gzip.decompress(raw).decode() if parts[-1].endswith(".gz") else raw.decode()

    def outputs(self, d=0):
        base = self.cfg["data_dirs"][d]
        recs = []
        for n in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            if n.startswith("anon-"):
                recs += [json.loads(x) for x in self.read(base, n).splitlines()]
        return recs

    def fill(self):
        a = conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=445)
        b = conn("192.168.1.10", "52.1.2.3", DEV1, GW, ts=T0 + 100.0)
        c = conn("192.168.1.20", "239.255.255.250", DEV2, "01:00:5e:7f:ff:fa", proto="udp", rp=1900, hist="D")
        self.write("eth1", "conn", [a, b])
        self.write("eth2", "conn", [dict(a, ts=a["ts"] + 0.4, orig_pkts=9), c])      # a seen on both mirrors
        self.write("eth1", "dns", [{"query": "router7.teamviewer.com", "answers": ["cname.x.net", "52.1.2.3"]}])
        self.write("eth1", "capture_loss", [{"percent_lost": 0.5}, {"percent_lost": 1.5}])
        self.write("eth1", "stats", [{"ts": T0 + 300.2, "pkts_proc": 700, "pkts_dropped": 0},
                                     {"ts": T0 + 600.2, "pkts_proc": 300, "pkts_dropped": 2}])
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.99", DEV1, DEV2)], active=True)
        now = pipeline.time.time()                # a log that Zeek is writing right now (also under a test clock)
        os.utime(os.path.join(self.cfg["raw_dir"], "eth1", "conn.log"), (now, now))
        with open(os.path.join(self.cfg["raw_dir"], "eth1", ".shadow.conn.log"), "w") as f:
            f.write("x")
        with open(os.path.join(self.cfg["key_dir"], "devices.csv"), "w") as f:
            f.write("mac,ip,type,brand,model,group,visibility,switch\n"
                    f"{DEV1},192.168.1.10,medical_pc,Optovue,Solix,agentless,full,A\n"
                    f"{DEV2},,Dr Ahmet odasi,HP,LaserJet,agentless,full,B\n")

    def raw_files(self, hidden=True):
        return sorted(os.path.join(i, n) for i in self.cfg["interfaces"]
                      for n in os.listdir(os.path.join(self.cfg["raw_dir"], i)) if hidden or not n.startswith("."))

    def test_not_armed_writes_nothing_and_keeps_nothing(self):
        self.fill()
        for text in (None, "", "{}", '{"approval_ref": ""}', "[1]"):
            if text is not None:
                self.arm(text)
            st = pipeline.run_once(self.cfg, now=NOW)
            self.assertIn("not armed", st["state"], text)
        self.assertEqual(self.outputs(), [])
        self.assertEqual(self.raw_files(), [])                # nothing raw is kept while not recording

    def test_full_run(self):
        self.fill()
        self.arm()
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual(st["state"], "ok")
        recs = self.outputs()
        self.assertEqual(len(recs), 3)                       # duplicate across mirrors removed
        self.assertEqual(self.outputs(1), recs)              # second copy is identical
        self.assertEqual(st["records_dropped"]["duplicate"], 1)
        smb = [r for r in recs if r["rp"] == 445][0]
        self.assertEqual(smb["opk"], 9)                      # the fuller copy is kept
        wan = [r for r in recs if r["rs"] == "wan"][0]
        self.assertEqual(wan["wc"], "remote_access")
        self.assertNotIn("wh", wan)
        self.assertEqual(st["recording_days"], 1)
        self.assertEqual(st["quality_last"]["0"], {"stats": [[T0 + 300, 700], [T0 + 600, 300]], "pkts": 1000, "dropped": 2,
                                                   "loss_n": 2, "loss_mean": 1.0, "loss_max": 1.5})
        self.assertIn("capture loss above 1 percent in the last hour", st["warnings"])
        self.assertEqual(st["gateways"], [PZ.device(GW)])
        self.assertEqual(self.raw_files(), ["eth1/.shadow.conn.log", "eth1/conn.log"])    # only the open log is left
        # device labels: valid row kept, free text in a controlled column refused
        labels = json.loads(self.read(self.cfg["data_dirs"][0], "devices.json"))
        self.assertEqual(labels[PZ.device(DEV1)]["type"], "medical_pc")
        self.assertEqual(labels[PZ.device(DEV2)]["type"], "")
        self.assertEqual(st["devices_labelled"], 2)
        # nothing that leaves the site contains an address, a name or a real domain
        for d in self.cfg["data_dirs"]:
            self.assertEqual(sorted(n.split("-")[0] for n in os.listdir(d)),
                             ["anon", "coverage.jsonl", "devices.json", "status.json"])
            for n in os.listdir(d):
                text = self.read(d, n)
                self.assertIsNone(core.scan_text(text), n)
                for secret in ("192.168", "aa:bb", "teamviewer", "Ahmet", "aabbcc", KEY.hex()[:16]):
                    self.assertNotIn(secret, text, n)
        # the list for the IT officer stays on the key stick, with real addresses and his labels
        obs = self.read(self.cfg["key_dir"], "devices_observed.csv").splitlines()
        self.assertEqual(obs[1], "aa:bb:cc:00:00:01,192.168.1.10,medical_pc,Optovue,Solix,agentless,full,A")
        self.assertEqual(len(obs), 3)                         # the gateway is not listed as a device
        cov = [json.loads(x) for x in self.read(self.cfg["data_dirs"][0], "coverage.jsonl").splitlines()]
        self.assertEqual((cov[0]["t"], cov[0]["records"]), (NOW, 3))

    def test_tokens_and_unclassified_report(self):
        self.fill()
        self.arm()
        self.write("eth1", "dns", [{"query": "telemetry.vendor-xyz.example", "answers": ["52.9.9.9"]}])
        self.write("eth2", "conn", [conn("192.168.1.10", "52.9.9.9", DEV1, GW, ts=T0 + 200.0)])
        pipeline.run_once(dict(self.cfg, wan_tokens=True), now=NOW)
        wan = [r for r in self.outputs() if r["rs"] == "wan"]
        self.assertEqual(len(wan), 2)
        self.assertTrue(all(r["wh"] and r["wn"] for r in wan))
        report = json.loads(self.read(self.cfg["key_dir"], "unclassified_domains.json"))
        self.assertEqual(report, {"vendor-xyz.example": 1})          # stays on the key stick

    def test_limit_is_exact_and_permanent(self):
        self.fill()
        self.arm()
        cfg = dict(self.cfg, max_recording_days=1)
        st = pipeline.run_once(cfg, now=NOW)                 # still the first day: keep recording
        self.assertEqual(st["state"], "ok")
        self.assertFalse(os.path.exists(os.path.join(cfg["state_dir"], "STOP")))
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + 86400.0)])
        st = pipeline.run_once(cfg, now=NOW + 86400)         # a second day is over the limit
        self.assertIn("limit", st["state"])
        self.assertEqual(st["records_dropped"]["over_limit"], 1)
        self.assertEqual(len(self.outputs()), 3)
        self.assertTrue(os.path.exists(os.path.join(cfg["state_dir"], "STOP")))
        self.assertEqual(self.raw_files(), [])
        self.assertEqual(pipeline.preflight(cfg, NOW + 90000), "recording limit reached")

    def test_missing_key_or_unset_clock_stops(self):
        self.fill()
        self.arm()
        self.assertIn("clock is not set", pipeline.run_once(self.cfg, now=1000000000)["state"])
        self.fill()
        os.remove(os.path.join(self.cfg["key_dir"], "hmac.key"))
        self.assertIn("key stick missing", pipeline.run_once(self.cfg, now=NOW)["state"])
        self.assertEqual(self.outputs(), [])
        self.assertEqual(self.raw_files(), [])

    def test_short_key_is_refused(self):
        with open(os.path.join(self.cfg["key_dir"], "hmac.key"), "w") as f:
            f.write("00ff")
        self.assertIsNone(pipeline.load_key(self.cfg["key_dir"]))

    def test_init_key_never_overwrites(self):
        os.remove(os.path.join(self.cfg["key_dir"], "hmac.key"))
        pipeline.init_key(self.cfg["key_dir"])
        self.assertEqual(len(pipeline.load_key(self.cfg["key_dir"])), 32)
        with self.assertRaises(FileExistsError):
            pipeline.init_key(self.cfg["key_dir"])

    def test_link_warnings(self):
        self.arm()
        pipeline.run_once(self.cfg, now=NOW)
        self.link("eth1", 1, 5000)
        self.link("eth2", 0, 1000)
        st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(st["warnings"], ["no link on capture port 1",
                                          "no packets on capture port 1 since the last run"])

    def test_clock_backwards_is_recorded(self):
        self.arm()
        pipeline.run_once(self.cfg, now=NOW)
        st = pipeline.run_once(self.cfg, now=NOW - 7200)
        self.assertEqual(st["clock_jumps"][0]["back_s"], 7200)
        self.assertEqual(st["state"], "ok")

    def test_data_directories_heal(self):
        self.fill()
        self.arm()
        pipeline.run_once(self.cfg, now=NOW)
        ssd = self.cfg["data_dirs"][0]
        gone = [n for n in os.listdir(ssd) if n.startswith("anon-")]
        os.remove(os.path.join(ssd, gone[0]))               # for example the disk was away for an export
        pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(self.outputs(0), self.outputs(1))
        self.assertEqual(len(self.outputs(0)), 3)

    def test_site_file_on_key_stick(self):
        self.fill()
        self.arm()
        with open(os.path.join(self.cfg["key_dir"], "site.json"), "w") as f:
            json.dump({"gateway_macs": [DEV2], "local_nets": ["192.168.1.0/24"], "wan_tokens": True}, f)
        st = pipeline.run_once(dict(self.cfg, gateway_macs=[]), now=NOW)
        self.assertEqual(st["gateways"], [PZ.device(DEV2)])
        self.assertTrue(all("wh" not in r for r in self.outputs()))      # tokens cannot be switched on from the stick

    @unittest.skipUnless(shutil.which("gpg"), "gpg is not installed")
    def test_export_is_encrypted_for_the_researcher(self):
        home = os.path.join(self.tmp.name, "researcher")           # stands for the researcher's own computer
        os.makedirs(home, mode=0o700)
        gpg = ["gpg", "--batch", "--yes", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run(gpg + ["--quick-generate-key", "ibe-test", "default", "default", "never"], check=True,
                       capture_output=True)
        pub = os.path.join(self.tmp.name, "recipient.asc")
        subprocess.run(gpg + ["--armor", "--output", pub, "--export", "ibe-test"], check=True, capture_output=True)
        self.fill()
        self.arm()
        cfg = dict(self.cfg, export_recipient=pub)
        st = pipeline.run_once(cfg, now=NOW)
        self.assertEqual([w for w in st["warnings"] if "export" in w], [])
        exp = os.path.join(self.tmp.name, "ssd", "export")
        plain = sorted(os.listdir(cfg["data_dirs"][0]))
        self.assertEqual(sorted(os.listdir(exp)), sorted(n + ".gpg" for n in plain))
        anon = [n for n in plain if n.startswith("anon-")][0]
        with open(os.path.join(exp, anon + ".gpg"), "rb") as f:
            cipher = f.read()
        with open(os.path.join(cfg["data_dirs"][0], anon), "rb") as f:
            clear = f.read()
        self.assertNotIn(clear[:24], cipher)
        back = subprocess.run(gpg + ["--decrypt", os.path.join(exp, anon + ".gpg")], check=True, capture_output=True)
        self.assertEqual(back.stdout, clear)                        # only the private key opens it
        first = os.path.getmtime(os.path.join(exp, anon + ".gpg"))
        pipeline.run_once(cfg, now=NOW + 3600)
        self.assertEqual(os.path.getmtime(os.path.join(exp, anon + ".gpg")), first)   # encrypted once
        bad = dict(cfg, export_recipient=os.path.join(self.cfg["key_dir"], "hmac.key"))  # not a public key
        st = pipeline.run_once(bad, now=NOW + 7200)
        self.assertIn("export encryption failed: gpg refused the key or the file", st["warnings"])

    def test_low_disk_warning(self):
        self.arm()
        st = pipeline.run_once(dict(self.cfg, min_free_gb=10 ** 9), now=NOW)
        self.assertIn("the data disk is almost full", st["warnings"])
        st = pipeline.run_once(dict(self.cfg, min_free_gb=0), now=NOW + 3600)
        self.assertNotIn("the data disk is almost full", st["warnings"])

    def test_raw_logs_must_be_in_ram(self):
        m = os.path.join(self.tmp.name, "mounts")
        with open(m, "w") as f:
            f.write("/dev/mmcblk0p2 / ext4 rw,noatime 0 0\n"
                    "tmpfs /run tmpfs rw,nosuid,nodev,size=800000k,mode=755 0 0\n"
                    "tmpfs /run/ibe tmpfs rw,nosuid,nodev,noexec,size=2097152k,mode=700 0 0\n"
                    "/dev/sda1 /mnt/ibe-data exfat rw 0 0\n"
                    "/dev/sdb1 /run/media/usb\\040stick vfat rw 0 0\n"
                    "/dev/sdc1 /run/ibe/raw/onadisk ext4 rw 0 0\n")
        for path, want in (("/run/ibe/raw", True), ("/run/ibe/raw/eth1", True), ("/run/ibe", True), ("/run/other", True),
                           ("/var/lib/ibe/raw", False), ("/mnt/ibe-data/raw", False), ("/runx/ibe", False),
                           ("/run/media/usb stick/raw", False), ("/run/ibe/raw/onadisk", False), ("/", False)):
            self.assertEqual(pipeline.on_ram_disk(path, m), want, path)
        self.assertFalse(pipeline.on_ram_disk("/run/ibe/raw", os.path.join(self.tmp.name, "missing")))
        self.fill()
        self.arm()
        cfg = dict(self.cfg, require_ram_disk=True, proc_mounts=m)        # the test folder is on a disk
        st = pipeline.run_once(cfg, now=NOW)
        self.assertEqual(st["state"], "stopped: the raw log directory is not in RAM")
        self.assertEqual(self.outputs(), [])
        self.assertEqual(self.raw_files(), [])
        with open(m, "a") as f:
            f.write(f"tmpfs {os.path.realpath(self.cfg['raw_dir'])} tmpfs rw 0 0\n")
        self.fill()
        self.assertEqual(pipeline.run_once(cfg, now=NOW + 3600)["state"], "ok")
        self.assertTrue(pipeline.DEFAULTS["require_ram_disk"])

    def test_swap_to_disk_stops_the_recording(self):
        p, blk = os.path.join(self.tmp.name, "swaps"), os.path.join(self.tmp.name, "block")
        os.makedirs(os.path.join(blk, "zram0"))
        os.makedirs(os.path.join(blk, "zram1"))
        head = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
        with open(os.path.join(blk, "zram0", "backing_dev"), "w") as f:
            f.write("none\n")
        with open(os.path.join(blk, "zram1", "backing_dev"), "w") as f:
            f.write("/dev/loop0\n")                          # idle pages are moved to a file on the disk
        for body, want in (("", False), ("/dev/zram0 partition 2097148 0 100\n", False),
                           ("/dev/zram1 partition 2097148 0 100\n", True),
                           ("/dev/zram2 partition 2097148 0 100\n", False),       # no writeback in the kernel
                           ("/var/swap file 204796 0 -2\n", True), ("/dev/mmcblk0p3 partition 1 0 -2\n", True),
                           ("/dev/zram0 partition 1 0 100\n/var/swap file 204796 0 -2\n", True)):
            with open(p, "w") as f:
                f.write(head + body)
            self.assertEqual(pipeline.disk_swap_on(p, blk), want, body)
        self.assertTrue(pipeline.disk_swap_on(os.path.join(self.tmp.name, "missing"), blk))    # unreadable: assume the worst
        with open(p, "w") as f:
            f.write(head + "/var/zram-swapfile file 204796 0 -2\n")                              # a file on a disk, whatever its name
        self.assertTrue(pipeline.disk_swap_on(p, blk))
        self.fill()
        self.arm()
        cfg = dict(self.cfg, proc_swaps=p, sysfs_block=blk)
        st = pipeline.run_once(cfg, now=NOW)
        self.assertEqual(st["state"], "stopped: swap to disk is on")
        self.assertEqual(self.outputs(), [])
        self.assertEqual(self.raw_files(), [])
        self.assertEqual(pipeline.preflight(cfg, NOW), "swap to disk is on")

    def test_semicolon_device_table(self):
        with open(os.path.join(self.cfg["key_dir"], "devices.csv"), "w", encoding="utf-8-sig") as f:
            f.write("MAC;IP;Type;Brand;Model;Group;Visibility;Switch\n"
                    f"{DEV1.upper().replace(':', '-')};;ip_phone;Yealink;T31P;agentless;full;A\n")
        labels, problems = pipeline.load_devices(self.cfg["key_dir"], PZ)
        self.assertEqual(labels[PZ.device(DEV1)]["type"], "ip_phone")
        self.assertEqual(problems, [])

    def test_open_reports_are_read_and_marked(self):
        self.arm()
        a = conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=1883, hist="ShADad")
        self.write("eth1", "conn", [a])
        quiet = dict(a, ts=T0 + 1800.0, resp_pkts=0, resp_bytes=0)                     # only the originator sent
        self.write("eth1", "open_conn", [dict(a, ts=T0 + 0.9, resp_pkts=2), quiet])
        self.write("eth2", "open_conn", [dict(quiet, ts=T0 + 1800.3)])                 # the same report on the other mirror
        self.write("eth1", "open_conn", [dict(a, ts=T0 + 3000.0)], active=True)        # still being written
        st = pipeline.run_once(self.cfg, now=NOW)
        recs = sorted(self.outputs(), key=lambda r: r["ts"])
        self.assertEqual([(r["ts"] - T0, r.get("open", False), r["est"]) for r in recs],
                         [(0, False, True), (0, True, True), (1800, True, False)])
        self.assertEqual((st["records_out"], st["records_open"], st["records_dropped"]["duplicate"]), (3, 2, 1))
        self.assertEqual(self.raw_files(), ["eth1/open_conn.log"])

    def test_failed_run_still_deletes_raw_logs(self):
        self.fill()
        self.arm()
        cfg = dict(self.cfg, raise_errors=False)
        real = core.transform

        def broken(rec, *a, **k):
            raise ValueError("cannot handle " + rec["id.orig_h"])        # an error text that quotes raw data
        core.transform = broken
        try:
            st = pipeline.run_once(cfg, now=NOW)
            self.check_failed(st)
            self.fill()
            with self.assertRaises(ValueError):
                pipeline.run_once(dict(cfg, raise_errors=True), now=NOW + 3600)
        finally:
            core.transform = real
        self.assertEqual(self.raw_files(), ["eth1/.shadow.conn.log", "eth1/conn.log"])

    def check_failed(self, st):
        self.assertEqual(self.outputs(), [])
        self.assertEqual(self.raw_files(), ["eth1/.shadow.conn.log", "eth1/conn.log"])
        self.assertEqual(st["state"], "ok")
        self.assertRegex(st["errors"][-1]["e"], r"^run failed, the hour was not written: \w+ at \w+\.py:\d+$")
        self.assertTrue(any(w.startswith("the last run failed") for w in st["warnings"]))
        for d in self.cfg["data_dirs"]:                              # the status does not quote the error text
            self.assertIsNone(core.scan_text(self.read(d, "status.json")))
            self.assertNotIn("cannot handle", self.read(d, "status.json"))

    def test_wrong_configuration_stops_cleanly(self):
        self.fill()
        self.arm()
        for change in ({"timezone": "No/Such_Zone"}, {"timezone": ""}, {"timezone": None}, {"interfaces": []},
                       {"interfaces": None}, {"interfaces": "eth1"}, {"data_dirs": "x"}, {"data_dirs": [5]},
                       {"site": "A/../x"}, {"site": ""}, {"config_unreadable": True},
                       {"interfaces": None, "data_dirs": None, "timezone": 5, "site": 7},
                       {"max_recording_days": 0}, {"max_recording_days": "112"}, {"local_nets": ["300.1.1.1/8"]},
                       {"gateway_macs": ["zz"]}):
            st = pipeline.run_once(dict(self.cfg, raise_errors=False, **change), now=NOW)
            self.assertIn("the configuration is wrong", st["state"], change)
            self.assertEqual(pipeline.preflight(dict(self.cfg, **change), NOW)[:26], "the configuration is wrong")
            self.assertEqual(self.raw_files(), [], change)       # capture stopped, nothing raw kept
            self.fill()
        self.assertEqual(self.outputs(), [])
        self.assertIsNone(pipeline.config_problem(self.cfg))
        self.assertIsNone(pipeline.config_problem(pipeline.DEFAULTS))
        with open(os.path.join(os.path.dirname(HERE), "config.example.json"), encoding="utf-8") as f:
            self.assertIsNone(pipeline.config_problem(dict(pipeline.DEFAULTS, **json.load(f))))

    def test_log_completed_during_a_run_is_kept_for_the_next_run(self):
        self.fill()
        self.arm()
        late = conn("192.168.1.10", "192.168.1.30", DEV1, DEV2, rp=8080, ts=T0 + 3500.0)
        real = pipeline._process

        def slow(cfg, st, now, files):
            out = real(cfg, st, now, files)
            with open(os.path.join(cfg["raw_dir"], "eth1", "conn.2026-12-29-11-00-00.log"), "w") as f:
                f.write(json.dumps(late) + "\n")                     # Zeek rotates while the run is busy
            return out
        pipeline._process = slow
        try:
            pipeline.run_once(self.cfg, now=NOW)
        finally:
            pipeline._process = real
        self.assertIn("eth1/conn.2026-12-29-11-00-00.log", self.raw_files())
        self.assertEqual(len(self.outputs()), 3)
        pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(len(self.outputs()), 4)
        self.assertEqual(self.raw_files(), ["eth1/.shadow.conn.log", "eth1/conn.log"])

    def test_key_cannot_be_created_without_a_stick(self):
        """An automount point with no stick behind it looks like a mount but cannot be written."""
        self.fill()
        self.arm()
        os.remove(os.path.join(self.cfg["key_dir"], "hmac.key"))
        real_ismount, real_init = os.path.ismount, pipeline.init_key

        def no_stick(key_dir):
            raise OSError(19, "No such device")
        os.path.ismount, pipeline.init_key = (lambda p: True), no_stick
        try:
            st = pipeline.run_once(dict(self.cfg, auto_init_key=True), now=NOW)
        finally:
            os.path.ismount, pipeline.init_key = real_ismount, real_init
        self.assertIn("key stick missing", st["state"])
        self.assertEqual(self.raw_files(), [])
        self.assertEqual(self.outputs(), [])
        # and a key is never created on a plain directory that is not a mounted stick
        st = pipeline.run_once(dict(self.cfg, auto_init_key=True), now=NOW + 3600)
        self.assertFalse(os.path.exists(os.path.join(self.cfg["key_dir"], "hmac.key")))

    def test_replaced_key_is_reported(self):
        self.fill()
        self.arm()
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual(st["key_id"], pipeline.key_id(KEY))
        self.assertNotIn(st["key_id"], KEY.hex())
        self.assertNotIn("key_changes", st)
        with open(os.path.join(self.cfg["key_dir"], "hmac.key"), "w") as f:
            f.write(bytes(range(1, 33)).hex())
        self.fill()
        st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(len(st["key_changes"]), 1)
        self.assertTrue(any("key on the stick was replaced" in w for w in st["warnings"]))
        cov = [json.loads(x) for x in self.read(self.cfg["data_dirs"][0], "coverage.jsonl").splitlines()]
        self.assertNotEqual(cov[0]["key"], cov[1]["key"])

    def test_names_of_local_addresses_are_not_kept(self):
        dns = [{"query": "dr-ahmet-pc.klinik.local", "answers": ["192.168.1.44", "fd00::44"]},
               {"query": "updates.vendor.example", "answers": ["cname.cdn.example", "52.7.7.7", 5, None]},
               {"query": None, "answers": ["52.8.8.8"]}, {"query": "x.example", "answers": "52.9.9.9"}]
        ssl = [{"server_name": "nas.klinik.local", "id.resp_h": "192.168.1.5"},
               {"server_name": "api.vendor.example", "id.resp_h": "52.7.7.8"}, {"server_name": 7, "id.resp_h": "52.7.7.9"}]
        old = {"10.0.0.9": ["old-pc.local", NOW], "52.1.1.1": ["a.example", NOW - 90000], "52.2.2.2": ["b.example", NOW - 10],
               "52.3.3.3": "broken", "52.4.4.4": [None, NOW]}
        got = pipeline.build_ip2dom(dns, ssl, old, NOW, SCOPE)
        self.assertEqual(got, {"52.7.7.7": ["updates.vendor.example", NOW], "52.7.7.8": ["api.vendor.example", NOW],
                               "52.2.2.2": ["b.example", NOW - 10]})

    def test_coverage_is_merged_across_data_directories(self):
        self.arm()
        pipeline.run_once(self.cfg, now=NOW)
        ssd, sd = self.cfg["data_dirs"]
        shutil.rmtree(os.path.dirname(ssd))                      # the data disk is away for an hour
        with open(os.path.dirname(ssd), "w") as f:               # and its mount point cannot be written
            f.write("")
        st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertIn("a data directory is not writable", st["warnings"])
        os.remove(os.path.dirname(ssd))                          # the disk is back, empty
        pipeline.run_once(self.cfg, now=NOW + 7200)
        times = [[json.loads(x)["t"] for x in self.read(d, "coverage.jsonl").splitlines()] for d in (ssd, sd)]
        self.assertEqual(times, [[NOW, NOW + 3600, NOW + 7200]] * 2)

    def test_records_stamped_by_an_unset_clock_are_dropped(self):
        self.arm()
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=1000000000.0),
                                    conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=NOW + 10 * 86400.0),
                                    conn("192.168.1.10", "192.168.1.20", DEV1, DEV2)])
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual((st["records_out"], st["records_dropped"]["bad_time"], st["days"]), (1, 2, ["2026-12-29"]))

    def test_day_boundary_is_local_midnight(self):
        self.arm()
        # 20:59:59 and 21:00:00 UTC are 23:59:59 and 00:00:00 in Istanbul
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + 11 * 3600 - 1.0),
                                    conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + 11 * 3600.0, rp=80)])
        st = pipeline.run_once(self.cfg, now=T0 + 12 * 3600)
        self.assertEqual(st["days"], ["2026-12-29", "2026-12-30"])

    def test_command_line(self):
        from ibe_recorder import cli
        import contextlib
        import io
        path = os.path.join(self.tmp.name, "config.json")
        cfg = {k: v for k, v in self.cfg.items() if pipeline.DEFAULTS.get(k) != v}
        cfg["manage_services"] = False
        with open(path, "w") as f:
            json.dump(cfg, f)
        real_time = pipeline.time.time
        pipeline.time.time = lambda: float(NOW)               # the command line reads the clock
        self.addCleanup(setattr, pipeline.time, "time", real_time)

        def run(*args, code=None):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                try:
                    cli.main(["--config", path] + list(args))
                    got = None
                except SystemExit as e:
                    got = e.code
            if code is None:
                self.assertIsNone(got, out.getvalue())
            elif isinstance(code, int):
                self.assertEqual(got, code, out.getvalue())
            else:
                self.assertIn(code, str(got))
            return out.getvalue()
        os.remove(os.path.join(self.cfg["key_dir"], "hmac.key"))
        run("arm", "--approval-ref", "2026/12-05", code="no key")           # no key, no arming
        self.assertIn("no status yet", run("status"))
        self.assertIn("key written", run("init-key"))
        run("init-key", code="refusing to overwrite")
        self.assertIn("not armed", run("preflight", code=3))
        self.fill()
        self.assertIn("ready, not recording", run("run"))
        self.assertEqual(self.raw_files(), [])
        run("arm", "--approval-ref", "2026/12-05")
        self.assertIn("capture allowed", run("preflight"))
        self.fill()
        out = run("run")
        self.assertTrue(out.startswith("ok | recording days: 1 | records: 3"), out)
        self.assertIn('"state": "ok"', run("status"))
        dest = os.path.join(self.tmp.name, "usb")
        self.assertIn("files copied", run("export", "--dest", dest))
        sums = dict(reversed(x.split("  ")) for x in self.read(dest, "SHA256SUMS").splitlines())
        self.assertEqual(sorted(sums), sorted(n for n in os.listdir(dest) if n != "SHA256SUMS"))
        import hashlib
        for name, digest in sums.items():
            with open(os.path.join(dest, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest)
        self.assertEqual(sorted(n.split("-")[0] for n in sums), ["anon", "coverage.jsonl", "devices.json", "status.json"])
        run("disarm")
        self.assertIn("not armed", run("preflight", code=3))
        # the limit: a permanent stop, lifted only by 'extend'
        with open(os.path.join(self.cfg["state_dir"], "STOP"), "w") as f:
            f.write("limit")
        run("arm", "--approval-ref", "again", code="limit was reached")
        run("extend", "--days", "0", "--approval-ref", "x", code="at least one day")
        self.assertIn("limit is now 140", run("extend", "--days", "140", "--approval-ref", "letter of 2027-03-01"))
        self.assertFalse(os.path.exists(os.path.join(self.cfg["state_dir"], "STOP")))
        with open(path) as f:
            saved = json.load(f)
        self.assertEqual((saved["max_recording_days"], saved["extensions"][0]["approval_ref"]), (140, "letter of 2027-03-01"))
        # a configuration file that cannot be read stops everything cleanly and says so
        run("arm", "--approval-ref", "2026/12-05")
        self.fill()
        with open(path, "w") as f:
            f.write("{ not json")
        self.assertIn("capture not allowed: the configuration is wrong", run("preflight", code=3))

    def test_last_resort_when_the_run_itself_fails(self):
        from ibe_recorder import cli
        import contextlib
        import io
        self.fill()
        self.arm()
        real = pipeline.run_once

        def broken(cfg, now=None):
            raise RuntimeError("192.168.1.10 could not be handled")
        pipeline.run_once = broken
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
                cli.cmd_run(self.cfg, None)
        finally:
            pipeline.run_once = real
        self.assertEqual(e.exception.code, 1)                 # the service fails, which triggers the fail-safe unit
        self.assertEqual(out.getvalue(), "run failed: RuntimeError\n")      # the text of the error is not printed
        self.assertEqual(self.raw_files(), ["eth1/.shadow.conn.log", "eth1/conn.log"])

    def test_broken_raw_lines_cost_one_record_not_the_hour(self):
        """Whatever a raw log contains, the run finishes, the good records are written and every line is counted."""
        rnd = random.Random(7)
        junk = [None, "", 0, -1, 3.5, True, [], {}, [1], {"a": 1}, "x", "not an address", float("inf"), 2 ** 70, "tcp"]
        good = conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=445)
        lines, n_json = [], 0
        for i in range(3000):
            r = dict(good, ts=T0 + i * 0.5, **{"id.orig_p": 40000 + i % 20000})
            if i % 3:
                for _ in range(rnd.choice([1, 1, 2, 3])):
                    r[rnd.choice(list(good) + ["vlan", "service", "ip_proto", "_open"])] = rnd.choice(junk)
            lines.append(json.dumps(r))
            n_json += 1
        lines += ["{ truncated", "", "[1, 2]", '"text"', "{}", '{"ts": 1}', "\x00\x01 binary"]
        n_json += 2                                                  # of those, only {} and {"ts": 1} are JSON objects
        for iface, stem in (("eth1", "conn"), ("eth2", "conn"), ("eth1", "open_conn"), ("eth2", "dns"), ("eth1", "ssl"),
                            ("eth1", "stats"), ("eth2", "capture_loss")):
            with open(os.path.join(self.cfg["raw_dir"], iface, f"{stem}.2026-12-29-10-00-00.log"), "w") as f:
                f.write("\n".join(lines) + "\n")
        self.arm()
        st = pipeline.run_once(self.cfg, now=NOW)                    # raise_errors is on: a crash would fail here
        self.assertEqual(st["state"], "ok")
        self.assertEqual(st["errors"], [])
        self.assertEqual(st["records_out"] + sum(st["records_dropped"].values()), 3 * n_json)
        self.assertGreater(st["records_out"], 1000)
        self.assertGreater(st["records_dropped"]["malformed"], 1000)
        self.assertEqual(self.raw_files(), [])
        for d in self.cfg["data_dirs"]:
            for n in os.listdir(d):
                self.assertIsNone(core.scan_text(self.read(d, n)), n)

    def test_key_directory_must_be_the_stick(self):
        m = os.path.join(self.tmp.name, "mounts")
        key = os.path.realpath(self.cfg["key_dir"])
        with open(m, "w") as f:
            f.write(f"/dev/mmcblk0p2 / ext4 rw 0 0\nsystemd-1 {key} autofs rw,relatime 0 0\n")
        cfg = dict(self.cfg, require_key_mount=True, proc_mounts=m)
        self.assertFalse(pipeline.on_stick(key, m))                      # only the automount placeholder
        self.assertFalse(pipeline.on_stick(os.path.dirname(key), m))     # a plain folder on the system disk
        self.fill()
        self.arm()
        st = pipeline.run_once(cfg, now=NOW)
        self.assertEqual(st["state"], "stopped: key stick missing")
        self.assertEqual(self.outputs(), [])
        self.assertFalse(os.path.exists(os.path.join(key, "status.json")))        # nothing is written next to the key
        self.assertFalse(os.path.exists(os.path.join(key, "devices_observed.csv")))
        from ibe_recorder import cli
        with self.assertRaises(SystemExit) as e:
            cli.cmd_init_key(cfg, None)
        self.assertIn("not plugged in", str(e.exception))
        with open(m, "a") as f:
            f.write(f"/dev/sda1 {key} vfat rw,umask=077 0 0\n")                   # the stick is mounted on top
        self.assertTrue(pipeline.on_stick(key, m))
        self.fill()
        self.assertEqual(pipeline.run_once(cfg, now=NOW + 3600)["state"], "ok")
        self.assertTrue(pipeline.DEFAULTS["require_key_mount"])

    def test_clock_without_battery_and_weak_key(self):
        rtc = os.path.join(self.tmp.name, "rtc")
        with open(rtc, "w") as f:
            f.write("86400\n")                                 # the hardware clock restarted in 1970
        self.arm()
        self.assertEqual(pipeline.preflight(dict(self.cfg, rtc_epoch=rtc), NOW), "clock is not set")
        with open(rtc, "w") as f:
            f.write(f"{NOW}\n")
        self.assertIsNone(pipeline.preflight(dict(self.cfg, rtc_epoch=rtc), NOW))
        with open(os.path.join(self.cfg["key_dir"], "hmac.key"), "w") as f:
            f.write("00" * 32)
        self.assertEqual(pipeline.preflight(self.cfg, NOW), "key stick missing")

    def test_log_of_a_dead_capture_is_read_and_removed(self):
        self.arm()
        old = os.path.join(self.cfg["raw_dir"], "eth2", "conn.log")
        self.write("eth2", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=8080)], active=True)
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=445)], active=True)
        os.utime(old, (pipeline.time.time() - 3 * 3600,) * 2)   # nothing has written to it for three hours
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual([r["rp"] for r in self.outputs()], [8080])
        self.assertEqual(self.raw_files(), ["eth1/conn.log"])    # the log that is still being written stays
        self.assertEqual(st["state"], "ok")

    def test_limit_holds_when_the_clock_is_set_back(self):
        self.arm()
        cfg = dict(self.cfg, max_recording_days=2)
        for k in range(2):
            self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + k * 86400.0)])
            self.assertEqual(pipeline.run_once(cfg, now=NOW + k * 86400)["state"], "ok")
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + 60.0)])
        st = pipeline.run_once(cfg, now=NOW + 120)               # the clock now shows the first day again
        self.assertIn("limit", st["state"])
        self.assertTrue(os.path.exists(os.path.join(cfg["state_dir"], "STOP")))

    def test_limit_holds_when_the_clock_stands_still(self):
        """A clock that is set back to the same day every time: the number of hourly batches is the limit."""
        self.arm()
        cfg = dict(self.cfg, max_recording_days=1)
        states = []
        for k in range(30):
            self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + k)])
            states.append(pipeline.run_once(cfg, now=NOW)["state"])
        self.assertEqual(states[:24], ["ok"] * 24)
        self.assertIn("limit", states[24])                        # 25 batches are more than one day can hold
        self.assertEqual(len(self.outputs()), 25)
        self.assertEqual(pipeline.preflight(cfg, NOW), "recording limit reached")

    def test_neighbour_log_names_devices_behind_the_router(self):
        """The ARP sightings of the hour are read, the table stays on the key stick, and nothing of it leaves."""
        self.arm()
        self.write("eth1", "neigh", [{"ts": T0 + 0.1, "ip": "192.168.20.5", "mac": DEV2},
                                     {"ts": T0 + 0.2, "ip": "192.168.1.1", "mac": GW},
                                     {"ts": T0 + 0.3, "ip": "not an address", "mac": DEV2}, {"ts": "x"}, 7])
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.20.5", DEV1, GW, rp=9100),
                                    conn("192.168.1.10", "192.168.1.1", DEV1, GW, rp=53, proto="udp", hist="Dd")])
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual((st["state"], st["errors"], st["neighbours"]), ("ok", [], 2))
        out = self.outputs()
        self.assertEqual([(r["r"], r["ib"]) for r in out], [(PZ.device(DEV2), ""), (PZ.device(GW), "")])
        self.assertEqual(self.raw_files(), [])
        stick = json.loads(self.read(self.cfg["key_dir"], "neighbours.json"))
        self.assertEqual(sorted(stick), ["192.168.1.1", "192.168.20.5"])
        for d in self.cfg["data_dirs"]:
            for name in os.listdir(d):
                text = self.read(d, name)
                self.assertNotIn("neighbours", name)
                self.assertIsNone(core.scan_text(text), name)
                self.assertNotIn("192.168.", text)
        # the next hour has no ARP at all: the table of the key stick still names the device
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.20.5", DEV1, GW, rp=9100, ts=T0 + 3700.0)])
        pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(self.outputs()[-1]["r"], PZ.device(DEV2))
        # a damaged table on the key stick costs the names it held, not the hour
        with open(os.path.join(self.cfg["key_dir"], "neighbours.json"), "w") as f:
            f.write('{"192.168.20.5": [["zz", 1, 2]], "x": 5, ')
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.20.5", DEV1, GW, rp=9100, ts=T0 + 7300.0)])
        st = pipeline.run_once(self.cfg, now=NOW + 7200)
        self.assertEqual((st["state"], st["errors"]), ("ok", []))
        self.assertEqual((self.outputs()[-1]["r"], self.outputs()[-1]["ib"]), (PZ.device_by_ip("192.168.20.5"), "r"))

    def test_addresses_on_the_link_outside_the_local_networks_are_reported(self):
        """A site that uses other address space inside. The devices on the mirrored link are recognised by
        themselves. A server of the site in another network of that kind is not: the status says so."""
        self.arm()
        self.write("eth1", "neigh", [{"ts": T0 + 0.1, "ip": "192.168.1.10", "mac": DEV1}])
        self.write("eth1", "conn", [conn("192.168.1.10", "52.1.2.3", DEV1, GW)])
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual([w for w in st["warnings"] if "local link" in w], [])
        self.write("eth1", "neigh", [{"ts": T0 + 3700.1, "ip": "193.140.1.10", "mac": DEV1},
                                     {"ts": T0 + 3700.2, "ip": "193.140.1.20", "mac": DEV2}])
        self.write("eth1", "conn", [conn("193.140.1.10", "193.140.1.20", DEV1, DEV2, rp=445, ts=T0 + 3701.0),
                                    conn("193.140.1.10", "193.140.9.5", DEV1, GW, rp=104, ts=T0 + 3702.0)])
        st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(len([w for w in st["warnings"]
                              if w.startswith("2 addresses on the local link are outside the local networks")]), 1)
        self.assertEqual([(r["os"], r["rs"], r["r"]) for r in self.outputs()[-2:]],
                         [("lan", "lan", PZ.device(DEV2)), ("lan", "wan", "wan")])
        listed = self.read(self.cfg["key_dir"], "devices_observed.csv")
        self.assertIn("193.140.1.10", listed)                      # the IT officer gets them to label
        self.assertIn("193.140.1.20", listed)
        self.assertNotIn("193.140.9.5", listed)
        # with the network in the configuration, the server is a host of the site with a name of its own
        cfg = dict(self.cfg, local_nets=list(core.DEFAULT_LOCAL_NETS) + ["193.140.0.0/16"])
        self.write("eth1", "conn", [conn("193.140.1.10", "193.140.9.5", DEV1, GW, rp=104, ts=T0 + 7302.0)])
        st = pipeline.run_once(cfg, now=NOW + 7200)
        r = self.outputs()[-1]
        self.assertEqual((r["rs"], r["r"], r["ib"]), ("lan", PZ.device_by_ip("193.140.9.5"), "r"))
        self.assertEqual([w for w in st["warnings"] if "local link" in w], [])
        self.assertEqual(len([w for w in st["warnings"] if "public address space" in w]), 1)

    def test_capture_folder_outside_the_configuration_is_emptied(self):
        """A capture process for a port that the configuration does not name: nobody would read its logs."""
        self.arm()
        self.fill()
        stray, other = (os.path.join(self.cfg["raw_dir"], n) for n in ("eth9", "something-else"))
        os.makedirs(stray)
        os.makedirs(other)
        for name in ("conn.log", "conn.2026-12-29-10-00-00.log", ".shadow.conn.log", "neigh.log", "notes.txt"):
            with open(os.path.join(stray, name), "w") as f:
                f.write(json.dumps(conn("192.168.1.10", "192.168.1.20", DEV1, DEV2)) + "\n")
        with open(os.path.join(other, "keep.txt"), "w") as f:
            f.write("x")
        mounts = os.path.join(self.tmp.name, "mounts")
        with open(mounts, "w") as f:
            f.write(f"/dev/root / ext4 rw 0 0\ntmpfs {os.path.realpath(self.cfg['raw_dir'])} tmpfs rw 0 0\n")
        st = pipeline.run_once(dict(self.cfg, proc_mounts=mounts), now=NOW)
        self.assertEqual(st["state"], "ok")
        self.assertEqual(os.listdir(stray), ["notes.txt"])       # only what has the name of a Zeek log is removed
        self.assertEqual(os.listdir(other), ["keep.txt"])        # a folder without Zeek logs is not a capture folder
        self.assertIn("a capture directory that is not in the configuration was stopped and emptied", st["warnings"])
        self.assertEqual(len(self.outputs()), 3)                 # the records of the configured ports only
        # where the raw directory is not a RAM disk, folders that the configuration does not name are left alone
        with open(os.path.join(stray, "conn.log"), "w") as f:
            f.write("{}\n")
        self.fill()
        st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(sorted(os.listdir(stray)), ["conn.log", "notes.txt"])

    def test_damaged_files_and_huge_values_do_not_cost_the_hour(self):
        self.arm()
        cfg = dict(self.cfg, raise_errors=False)
        # a number with 400 digits in one raw line, and a TLS name of 60,000 characters
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=445),
                                    conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=446, orig_bytes=10 ** 400),
                                    conn("192.168.1.10", "52.7.7.8", DEV1, GW, rp=447, ts=T0 + 5.0)])
        with open(os.path.join(cfg["raw_dir"], "eth1", "conn.2026-12-29-10-00-00.log"), "a") as f:
            f.write('{"ts": 1' + "0" * 400 + ', "id.orig_h": "192.168.1.10"}\n')
        self.write("eth1", "ssl", [{"server_name": "a" * 60000 + ".example.com", "id.resp_h": "52.7.7.8"}])
        started = time.time()
        st = pipeline.run_once(cfg, now=NOW)
        self.assertLess(time.time() - started, 20)
        self.assertEqual((st["state"], st["errors"]), ("ok", []))
        self.assertEqual(sorted(r["rp"] for r in self.outputs()), [445, 446, 447])
        self.assertEqual(st["records_dropped"].get("malformed"), 1)
        self.assertEqual(json.loads(self.read(cfg["raw_dir"], "ip2dom.json")), {})      # the long name was not kept
        # a byte that is not text in the coverage file of one data directory
        with open(os.path.join(cfg["data_dirs"][1], "coverage.jsonl"), "ab") as f:
            f.write(b"\xff\xfe broken\n")
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=448, ts=T0 + 3700.0)])
        st = pipeline.run_once(cfg, now=NOW + 3600)
        self.assertEqual((st["state"], st["errors"]), ("ok", []))
        self.assertEqual(len(self.outputs()), 4)

    def test_remote_names_expire_without_traffic(self):
        self.arm()
        self.write("eth1", "dns", [{"query": "api.vendor.example", "answers": ["52.7.7.8"]}])
        pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual(list(json.loads(self.read(self.cfg["raw_dir"], "ip2dom.json"))), ["52.7.7.8"])
        pipeline.run_once(self.cfg, now=NOW + 30 * 3600)          # more than a day later, and not one connection since
        self.assertEqual(json.loads(self.read(self.cfg["raw_dir"], "ip2dom.json")), {})

    def test_files_saved_by_a_windows_editor(self):
        """Notepad puts a byte order mark in front of a file. The file must still count."""
        self.fill()
        with open(os.path.join(self.cfg["key_dir"], "armed.json"), "w", encoding="utf-8-sig") as f:
            f.write('{"approval_ref": "2026/12-05"}')
        with open(os.path.join(self.cfg["key_dir"], "site.json"), "w", encoding="utf-8-sig") as f:
            json.dump({"gateway_macs": [DEV2]}, f)
        st = pipeline.run_once(dict(self.cfg, gateway_macs=[]), now=NOW)
        self.assertEqual(st["state"], "ok")                         # armed
        self.assertFalse([w for w in st["warnings"] if "json" in w])
        self.assertEqual(st["gateways"], [PZ.device(DEV2)])         # the site file was read
        with open(os.path.join(self.cfg["key_dir"], "site.json"), "w") as f:
            f.write('{"gateway_macs": ["aa:bb')                    # a typing mistake is reported, not passed over
        self.fill()
        st = pipeline.run_once(dict(self.cfg, gateway_macs=[]), now=NOW + 3600)
        self.assertIn("site.json on the key stick cannot be read and is ignored", st["warnings"])

    def test_missing_export_key_is_reported_and_export_refused(self):
        from ibe_recorder import cli
        self.arm()
        self.fill()
        cfg = dict(self.cfg, export_recipient=os.path.join(self.tmp.name, "no-such-key.asc"))
        st = pipeline.run_once(cfg, now=NOW)
        self.assertEqual(st["state"], "ok")
        self.assertIn("export encryption failed: the export key file is missing, nothing is encrypted", st["warnings"])
        self.assertFalse(os.path.isdir(os.path.join(self.tmp.name, "ssd", "export")))
        dest = os.path.join(self.tmp.name, "out")
        with self.assertRaises(SystemExit) as e:
            cli.cmd_export(cfg, type("A", (), {"dest": dest})())
        self.assertIn("nothing has been encrypted", str(e.exception))
        self.assertFalse(os.path.exists(dest))                      # the readable files were not copied instead

    def test_approval_reference_must_say_something(self):
        from ibe_recorder import cli
        path = os.path.join(self.tmp.name, "config.json")
        with open(path, "w") as f:
            json.dump({k: v for k, v in self.cfg.items() if pipeline.DEFAULTS.get(k) != v}, f)
        for args in (["arm", "--approval-ref", ""], ["arm", "--approval-ref", "  "], ["extend", "--days", "9999", "--approval-ref", "x"]):
            with self.assertRaises(SystemExit) as e:
                cli.main(["--config", path] + args)
            self.assertIn("too short", str(e.exception))
        self.assertFalse(os.path.exists(os.path.join(self.cfg["key_dir"], "armed.json")))
        with open(path) as f:
            self.assertNotIn("extensions", json.load(f))

    def test_clock_set_back_while_capture_runs(self):
        """Zeek completes a log when its own clock reaches the next full hour, and that clock never goes back.
        After the system clock is set back, capture is stopped once, its open logs are read and removed, and
        it starts again, instead of raw logs waiting in RAM until the clock has caught up."""
        self.arm()
        calls, mono = [], [1000.0]
        cfg = dict(self.cfg, manage_services=True)
        with mock.patch.object(pipeline, "_services", lambda c, action: calls.append(action)), \
                mock.patch.object(pipeline.time, "monotonic", lambda: mono[0]):
            self.fill()
            pipeline.run_once(cfg, now=NOW)
            self.assertEqual(calls, ["start"])
            calls.clear()
            mono[0] += 3600                              # an hour later by the clock that cannot be set ...
            raw = os.path.join(cfg["raw_dir"], "eth1")
            with open(os.path.join(raw, "conn.log"), "w") as f:      # ... Zeek still holds this log open
                f.write(json.dumps(conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=8001, ts=T0 + 3000.0)) + "\n")
            with open(os.path.join(raw, ".shadow.conn.log"), "w") as f:
                f.write("x\n")
            st = pipeline.run_once(cfg, now=NOW + 3600 - 3 * 3600)   # ... and the system clock is two hours back
            self.assertEqual(calls, ["stop", "start"])
            self.assertIn("the clock was set back: capture was restarted so that its logs are completed again", st["warnings"])
            self.assertEqual(os.listdir(raw), [])
            self.assertIn(8001, [r["rp"] for r in self.outputs()])
            calls.clear()
            mono[0] += 3600                              # the next hour is an ordinary one
            with open(os.path.join(raw, "conn.log"), "w") as f:
                f.write("{}\n")
            st = pipeline.run_once(cfg, now=NOW + 3600 - 3 * 3600 + 3600)
            self.assertEqual(calls, ["start"])
            self.assertEqual(os.listdir(raw), ["conn.log"])          # an open log of a running capture is left alone
        # after a restart of the device the two clocks cannot be compared, and nothing is concluded
        self.assertEqual(pipeline.clock_step({"clock_ref": [NOW, 99999.0]}, NOW - 9000), 0.0)
        self.assertEqual(pipeline.clock_step({"clock_ref": "x"}, NOW), 0.0)
        self.assertEqual(pipeline.clock_step({}, NOW), 0.0)

    def test_local_networks_cannot_be_widened_from_the_stick(self):
        """A host in a local network is named by a token of its address. A network that covers remote hosts
        would hand out tokens for them although the site has not permitted tokens."""
        self.arm()
        for nets in (["192.168.0.0/16", "10.0.0.0/0"], ["0.0.0.0/0"], ["193.140.0.0/16"], ["::/0"], ["2a02:ff0::/32"]):
            with open(os.path.join(self.cfg["key_dir"], "site.json"), "w") as f:
                json.dump({"local_nets": nets}, f)
            self.write("eth1", "conn", [conn("192.168.1.10", "52.1.2.3", DEV1, GW), conn("192.168.1.10", "193.140.1.7", DEV1, GW),
                                        conn("fe80::1", "2a02:ff0:1::7", DEV1, GW)])
            st = pipeline.run_once(self.cfg, now=NOW)
            self.assertIn("site.json: local_nets ignored, " + pipeline.NOT_PRIVATE, st["warnings"], nets)
            self.assertEqual({r["r"] for r in self.outputs()}, {"wan"}, nets)
        with open(os.path.join(self.cfg["key_dir"], "site.json"), "w") as f:           # narrowing is the stick's to decide
            json.dump({"local_nets": ["192.168.1.0/24"]}, f)
        self.write("eth1", "conn", [conn("192.168.1.10", "10.9.9.9", DEV1, GW)])
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual((self.outputs()[-1]["r"], [w for w in st["warnings"] if "site.json" in w]), ("wan", []))
        os.remove(os.path.join(self.cfg["key_dir"], "site.json"))
        # in the configuration a public network can be declared, never one wider than the widest private range
        self.assertIn("local_nets", pipeline.config_problem(dict(self.cfg, local_nets=["10.0.0.0/0"])))
        self.assertIn("local_nets", pipeline.config_problem(dict(self.cfg, local_nets=["::/0"])))
        self.assertIsNone(pipeline.config_problem(dict(self.cfg, local_nets=["10.0.0.0/8", "fc00::/7", "193.140.0.0/16"])))
        self.fill()
        st = pipeline.run_once(dict(self.cfg, local_nets=["192.168.0.0/16", "193.140.0.0/16"]), now=NOW)
        self.assertIn("1 of the local networks in the configuration are public address space: hosts in them are named by tokens",
                      st["warnings"])

    def test_wrong_raw_directory_does_not_empty_other_folders(self):
        """Every hour everything below the raw log directory is deleted. A path that is not the RAM disk
        must not turn that into deleting the key and the data."""
        self.arm()
        top = os.path.join(self.tmp.name, "mnt")
        key, data, other = (os.path.join(top, n) for n in ("ibe-key", "ibe-data", "other"))
        for d in (key, data, other):
            os.makedirs(d)
            with open(os.path.join(d, "keep.txt"), "w") as f:
                f.write("x")
        cfg = dict(self.cfg, raw_dir=top, key_dir=key, data_dirs=[data], raise_errors=False)
        self.assertEqual(pipeline.config_problem(cfg), "raw_dir")
        self.assertEqual(pipeline.config_problem(dict(self.cfg, raw_dir="/")), "raw_dir")
        self.assertEqual(pipeline.config_problem(dict(self.cfg, raw_dir=self.cfg["key_dir"])), "raw_dir")
        st = pipeline.run_once(cfg, now=NOW)
        self.assertEqual(st["state"], "stopped: the configuration is wrong: raw_dir")
        # also when the other folders are named elsewhere and only the RAM check can tell
        mounts = os.path.join(self.tmp.name, "mounts")
        with open(mounts, "w") as f:
            f.write("/dev/root / ext4 rw 0 0\n")
        st = pipeline.run_once(dict(self.cfg, raw_dir=top, require_ram_disk=True, proc_mounts=mounts, raise_errors=False), now=NOW)
        self.assertEqual(st["state"], "stopped: the raw log directory is not in RAM")
        for d in (key, data, other):
            self.assertIn("keep.txt", os.listdir(d), d)
        # and even on a RAM disk only files with the name of a Zeek log are removed from a folder that is not configured
        with open(mounts, "w") as f:
            f.write(f"tmpfs {os.path.realpath(top)} tmpfs rw 0 0\n")
        with open(os.path.join(other, "conn.log"), "w") as f:
            f.write("{}\n")
        pipeline.purge_raw(dict(self.cfg, raw_dir=top, proc_mounts=mounts), everything=True)
        self.assertEqual(os.listdir(other), ["keep.txt"])
        for d in (key, data):
            self.assertIn("keep.txt", os.listdir(d), d)

    def test_batch_is_counted_before_it_is_written(self):
        self.arm()
        self.fill()
        with mock.patch.object(pipeline, "sync_dirs", side_effect=KeyboardInterrupt):      # the run dies after the write
            with self.assertRaises(KeyboardInterrupt):
                pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual(len(self.outputs()), 3)
        saved = json.loads(self.read(self.cfg["state_dir"], "status.json"))
        self.assertEqual((saved["files"], saved["days"]), (1, ["2026-12-29"]))
        st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual((st["files"], st["recording_days"]), (1, 1))

    def test_more_damaged_files(self):
        self.arm()
        cfg = dict(self.cfg, raise_errors=False)
        stick = self.cfg["key_dir"]
        cases = (("neighbours.json", '{"192.168.1.20": [["aabbcc000002", 1' + "0" * 400 + ', 2]]}'),
                 ("neighbours.json", "[" * 100000 + "]" * 100000), ("gateways_seen.json", "[" * 100000),
                 ("site.json", "[" * 100000), ("armed.json", '{"approval_ref": "2026/12-05", "x": ' + "[" * 100000))
        for n, (name, text) in enumerate(cases):
            with open(os.path.join(stick, name), "w") as f:
                f.write(text)
            self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=9000 + n, ts=T0 + n)])
            st = pipeline.run_once(cfg, now=NOW + n)
            if name == "armed.json":
                self.assertEqual(st["state"], "ready, not recording (not armed)")
                self.arm()
            else:
                self.assertEqual((st["state"], st["errors"]), ("ok", []), name)
                self.assertIn(9000 + n, [r["rp"] for r in self.outputs()], name)
                os.remove(os.path.join(stick, name))
        # a folder where a table is expected, and a coverage line whose time is not a number
        for name in ("devices.csv", "service_rules.csv"):
            os.makedirs(os.path.join(stick, name))
        with open(os.path.join(cfg["data_dirs"][0], "coverage.jsonl"), "a") as f:
            f.write('{"t": null}\n{"t": "soon"}\n{"t": [1]}\n')
        self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, rp=9100, ts=T0 + 50.0)])
        st = pipeline.run_once(cfg, now=NOW + 60)
        self.assertEqual((st["state"], st["errors"]), ("ok", []))
        self.assertIn(9100, [r["rp"] for r in self.outputs()])
        self.assertIn("the device table cannot be opened or read, the rest of it is ignored", st["device_table_problems"])

    def test_devices_seen_does_not_grow_with_addresses_that_were_only_tried(self):
        self.arm()
        sweep = [conn("192.168.1.10", f"10.7.{i // 250}.{i % 250 + 1}", DEV1, GW, rp=445, hist="S", orig_pkts=1, resp_pkts=0,
                      resp_bytes=0, conn_state="S0", ts=T0 + i * 0.01) for i in range(3000)]
        self.write("eth1", "conn", sweep + [conn("192.168.1.10", "10.8.0.1", DEV1, GW, rp=445, ts=T0 + 40.0)])
        st = pipeline.run_once(self.cfg, now=NOW)
        self.assertEqual(len(self.outputs()), 3001)
        self.assertEqual(st["devices_seen"], sorted([PZ.device(DEV1), PZ.device_by_ip("10.8.0.1")]))
        with mock.patch.object(pipeline, "MAX_DEVICES_SEEN", 5):
            self.write("eth1", "conn", [conn(f"192.168.2.{i}", "192.168.1.20", f"aa:bb:cc:00:02:{i:02x}", DEV2, ts=T0 + 3700.0 + i)
                                        for i in range(1, 30)])
            st = pipeline.run_once(self.cfg, now=NOW + 3600)
        self.assertEqual(len(st["devices_seen"]), 5)
        self.assertIn("more devices than the status can list, the list is cut", st["warnings"])

    def test_address_requests_on_two_ports_are_not_duplicates_of_each_other(self):
        def dhcp(mac, ts):
            return conn("0.0.0.0", "255.255.255.255", mac, "ff:ff:ff:ff:ff:ff", op=68, rp=67, proto="udp", hist="D", ts=ts,
                        resp_pkts=0, resp_bytes=0, conn_state="S0")
        recs = [(0, dhcp(DEV1, T0)), (1, dhcp(DEV2, T0 + 0.7)), (1, dhcp("aa:bb:cc:00:00:03", T0 + 1.4)),
                (1, dhcp(DEV1, T0 + 0.001))]                               # the last one is a real second copy
        kept, dropped = pipeline.dedup(recs, 2)
        self.assertEqual((sorted(r["orig_l2_addr"] for _, r in kept), dropped), ([DEV1, DEV2, "aa:bb:cc:00:00:03"], 1))
        # One port sees a frame twice, so the two copies of one device differ in packets. The fuller copy
        # replaces the other copy of the same device, never the record of another device.
        third = "aa:bb:cc:00:00:03"
        def n(rec, pkts):
            return dict(rec, orig_pkts=pkts)
        recs = [(1, n(dhcp(DEV1, T0), 1)), (0, n(dhcp(DEV1, T0 + 0.0003), 2)),
                (1, n(dhcp(DEV2, T0 + 0.3), 1)), (0, n(dhcp(DEV2.upper(), T0 + 0.3005), 1)),
                (1, n(dhcp(third, T0 + 1.2), 2)), (0, n(dhcp(third, T0 + 1.2002), 1))]
        kept, dropped = pipeline.dedup(recs, 2)
        self.assertEqual((sorted((r["orig_l2_addr"].lower(), r["orig_pkts"]) for _, r in kept), dropped),
                         ([(DEV1, 2), (DEV2, 1), (third, 2)], 3))

    def test_flows_of_two_protocols_without_ports_are_not_duplicates_of_each_other(self):
        """ESP and GRE between the same two hosts share the word 'unknown_transport' and the ports 0."""
        def flow(ipp, ts, pkts):
            return dict(conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, op=0, rp=0, proto="unknown_transport", hist="",
                             ts=ts), ip_proto=ipp, orig_pkts=pkts, resp_pkts=pkts)
        recs = [(0, flow(50, T0, 3)), (1, flow(50, T0 + 0.0002, 3)), (1, flow(47, T0 + 1, 40)), (0, flow(47, T0 + 1.0002, 40))]
        kept, dropped = pipeline.dedup(recs, 2)
        self.assertEqual((sorted(r["ip_proto"] for _, r in kept), dropped), ([47, 50], 2))
        self.arm()
        self.write("eth1", "conn", [flow(50, T0, 3), flow(47, T0 + 1, 40)])
        self.write("eth2", "conn", [flow(50, T0 + 0.0002, 3), flow(47, T0 + 1.0002, 40)])
        st = pipeline.run_once(dict(self.cfg, interfaces=["eth1", "eth2"]), now=NOW)
        self.assertEqual((st["state"], st["records_dropped"].get("duplicate")), ("ok", 2))
        self.assertEqual(sorted((r["proto"], r["ipp"]) for r in self.outputs()), [("unknown_transport", 47), ("unknown_transport", 50)])

    def test_whitelist_ranges_and_words(self):
        good = tr(conn("192.168.1.10", "224.0.0.251", DEV1, "01:00:5e:00:00:fb", op=5353, rp=5353, proto="udp", hist="D"))[0]
        self.assertIsNone(core.leak_check(good))
        for field, value in (("op", 3232235786), ("rp", 65536), ("vlan", 187723558158337), ("vlan", 4096), ("if", 256), ("ipp", 256),
                             ("ts", 1798538400.5), ("ob", 1.5), ("opk", -1), ("r", "mcast:aabbcc000001"), ("r", "mcast:pcreception7"),
                             ("dur", 5e8)):
            self.assertIsNotNone(core.leak_check(dict(good, **{field: value})), (field, value))
        self.assertIsNotNone(core.leak_check(dict(good, wc="dr_ahmet_yilmaz"), {"dns", "other", "unknown"}))
        self.assertIsNotNone(core.leak_check(dict(good, wc="dr_ahmet_yilmaz")))            # the list of service types is closed
        self.assertIsNotNone(core.leak_check(dict(good, wc="pc_reception_klinik")))
        with open(os.path.join(os.path.dirname(core.__file__), "service_rules.csv"), encoding="utf-8") as f:
            self.assertLessEqual(set(core.Categoriser(f.read().splitlines()).rules.values()), set(core.CATEGORIES))
        with self.assertRaises(ValueError):
            core.Categoriser(["vendor.example,dr_ahmet_yilmaz"])
        self.assertIsNone(core.leak_check(dict(good, wc="dns"), {"dns", "other", "unknown"}))
        for text in ("host 192.168.1.20.", "10.1.168.192.in-addr.arpa", "192.168.1.20.5", "at 10.0.0.7, then"):
            self.assertTrue((core.scan_text(text) or "").startswith("ipv4"), text)
        for text in ('{"dur":0.123,"ts":1798538400,"rp":443}', "version 0.5.0", '"stats": [[1798538400, 12]]'):
            self.assertIsNone(core.scan_text(text), text)

    def test_command_line_traps(self):
        from ibe_recorder import cli
        path = os.path.join(self.tmp.name, "config.json")
        with open(path, "w") as f:
            json.dump({k: v for k, v in self.cfg.items() if pipeline.DEFAULTS.get(k) != v}, f)
        self.arm()
        # disarm without the stick must not say "disarmed"
        with mock.patch.object(pipeline, "key_dir_ok", lambda cfg: False):
            with self.assertRaises(SystemExit) as e:
                cli.main(["--config", path, "disarm"])
        self.assertIn("not removed", str(e.exception))
        self.assertTrue(os.path.exists(os.path.join(self.cfg["key_dir"], "armed.json")))
        # extend never creates a configuration
        missing = os.path.join(self.tmp.name, "none.json")
        with self.assertRaises(SystemExit) as e:
            cli.main(["--config", missing, "extend", "--days", "200", "--approval-ref", "letter of 2027-03-01"])
        self.assertIn("missing", str(e.exception))
        self.assertFalse(os.path.exists(missing))
        # the name of an unknown entry reaches the status only if it is a plain word
        self.assertEqual(pipeline.config_problem(dict(self.cfg, wan_token=True)), "unknown entry wan_token")
        got = pipeline.config_problem({**self.cfg, "gateway_macs 00:11:22:33:44:55": True})
        self.assertNotIn("0011", got)
        self.assertIsNone(core.scan_text(got))

    def test_hardware_clock_that_cannot_be_read(self):
        self.arm()
        self.assertEqual(pipeline.preflight(dict(self.cfg, rtc_epoch=os.path.join(self.tmp.name, "no-such-clock")), NOW),
                         "clock is not set")
        self.assertIsNone(pipeline.preflight(dict(self.cfg, rtc_epoch=""), NOW))        # switched off on purpose

    def test_limit_by_the_calendar(self):
        """Days without recording move the end, but not past max_calendar_days after the first day."""
        self.arm()
        cfg = dict(self.cfg, max_recording_days=5, max_calendar_days=10)
        seen = {}
        for d in (0, 3, 9, 10, 11):                               # the device was on only on these days
            self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + d * 86400.0)])
            seen[d] = pipeline.run_once(cfg, now=NOW + d * 86400)
        self.assertEqual([seen[d]["state"] for d in (0, 3, 9)], ["ok"] * 3)
        self.assertIn("limit of 10 days since the first recording day", seen[10]["state"])
        self.assertEqual(seen[10]["days"], ["2026-12-29", "2027-01-01", "2027-01-07"])    # day 10 was not written
        self.assertEqual(seen[10]["records_dropped"]["over_limit"], 1)
        self.assertEqual(len(self.outputs()), 3)
        self.assertEqual(pipeline.preflight(cfg, NOW + 12 * 86400), "recording limit reached")
        self.assertEqual(self.raw_files(), [])
        # a date that is not a date in a copy of the status is ignored, it cannot crash the run or move the end
        with open(os.path.join(cfg["key_dir"], "status.json"), "w") as f:
            json.dump({"days": ["2026-13-45", "0000-00-00", "2026-12-29", 7, None]}, f)
        self.assertEqual(pipeline.known_days(cfg, {}), ["2026-12-29", "2027-01-01", "2027-01-07"])
        self.assertIsNotNone(pipeline.config_problem(dict(self.cfg, max_calendar_days=0)))
        self.assertIsNotNone(pipeline.config_problem(dict(self.cfg, max_calendar_days="365")))
        self.assertEqual(pipeline.last_day_allowed(["2026-12-29"], 10 ** 9), "9999-12-31")

    def test_extend_sets_both_limits(self):
        path = os.path.join(self.tmp.name, "config.json")
        with open(path, "w") as f:
            json.dump(dict(self.cfg, max_recording_days=1), f)
        with open(os.path.join(self.cfg["state_dir"], "STOP"), "w") as f:
            f.write("limit")
        from ibe_recorder import cli
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--config", path, "extend", "--days", "30", "--calendar-days", "400",
                      "--approval-ref", "letter of 2027-03-01, no 12"])
        with open(path) as f:
            got = json.load(f)
        self.assertEqual((got["max_recording_days"], got["max_calendar_days"]), (30, 400))
        self.assertEqual(got["extensions"][-1]["calendar_days"], 400)
        self.assertFalse(os.path.exists(os.path.join(self.cfg["state_dir"], "STOP")))
        self.assertIsNone(pipeline.config_problem(pipeline.load_config(path)))
        with self.assertRaises(SystemExit):
            cli.main(["--config", path, "extend", "--days", "30", "--calendar-days", "0", "--approval-ref", "letter 12"])

    def test_day_count_survives_a_lost_state_file(self):
        self.arm()
        cfg = dict(self.cfg, max_recording_days=2)
        for k in range(4):
            self.write("eth1", "conn", [conn("192.168.1.10", "192.168.1.20", DEV1, DEV2, ts=T0 + k * 86400.0)])
            st = pipeline.run_once(cfg, now=NOW + k * 86400)
            p = os.path.join(cfg["state_dir"], "status.json")
            if os.path.exists(p):
                os.remove(p)                                      # the state file is lost after every run
        self.assertEqual(st["days"], ["2026-12-29", "2026-12-30"])
        self.assertEqual(len(self.outputs()), 2)
        self.assertIn("limit", st["state"])

    def test_labels_typed_on_site(self):
        rows = [("HP", "LaserJet M404dn", "A"), ("HP 192.168.1.20.", "x", "A"), ("AABBCC000003", "x", "A"),
                ("x", "oct1.klinik.local", "A"), ("x", "10.1.168.192.in-addr.arpa", "A"), ("x", "192-168-1-254", "A"),
                ("x", "y", "sw-kat2.klinik.local"), ("x", "aabb.cc00.0003", "B2")]
        with open(os.path.join(self.cfg["key_dir"], "devices.csv"), "w") as f:
            f.write("mac,ip,type,brand,model,group,visibility,switch\n")
            for i, (brand, model, sw) in enumerate(rows):
                f.write(f"aa:bb:cc:00:01:{i:02x},,printer,{brand},{model},agentless,full,{sw}\n")
            f.write("aa:bb:cc:00:01:99,,printer,HP,one cell,too,many,agentless,full,A\n")     # a comma inside a name
        labels, problems = pipeline.load_devices(self.cfg["key_dir"], PZ)
        got = [(v["brand"], v["model"], v["switch"]) for v in (labels[PZ.device(f"aa:bb:cc:00:01:{i:02x}")] for i in range(8))]
        self.assertEqual(got, [("HP", "LaserJet M404dn", "A"), ("", "x", "A"), ("", "x", "A"), ("x", "", "A"),
                               ("x", "", "A"), ("x", "", "A"), ("x", "y", ""), ("x", "", "B2")])
        self.assertGreaterEqual(len(problems), 8)

    def test_settings_must_be_spelt_and_typed_right(self):
        for change in ({"max_recording_day": 2}, {"wan_tokens": "false"}, {"wan_tokens": 1}, {"require_ram_disk": "no"},
                       {"gateway_learn_threshold": "16"}, {"led": None}):
            self.assertIsNotNone(pipeline.config_problem(dict(self.cfg, **change)), change)
        self.assertTrue(pipeline.load_config(os.path.join(self.tmp.name, "missing.json")).get("config_unreadable"))

    def test_a_device_with_many_addresses_is_not_a_router(self):
        pc = [(0, conn(f"2a02:ff0:1:2::{i:x}", "2a00:1450:4017::200e", DEV1, GW)) for i in range(1, 40)]
        state, learned = pipeline.learn_gateways(pc, SCOPE, {}, 16)
        self.assertNotIn(core.norm_mac(DEV1), learned)            # 39 addresses of one network: a PC with privacy addresses
        nets = [(0, conn("192.168.1.10", f"52.{i}.2.3", DEV1, GW)) for i in range(20)]
        self.assertEqual(pipeline.learn_gateways(nets, SCOPE, {}, 16)[1], {core.norm_mac(GW)})

    def test_neighbour_table(self):
        n = neighbours((T0, "192.168.1.20", DEV2), (T0 + 50, "192.168.1.20", DEV2), (T0 + 9000, "192.168.1.20", DEV1))
        d1, d2 = core.norm_mac(DEV1), core.norm_mac(DEV2)
        self.assertEqual(n.at("192.168.1.20", T0 + 10), d2)
        self.assertEqual(n.at("192.168.1.20", T0 - 500), d2)                  # before the first sighting: the first owner
        self.assertEqual(n.at("192.168.1.20", T0 + 9000), d1)                 # the address moved to another device
        self.assertEqual(n.at("192.168.1.20", T0 + 8000), d2)
        self.assertIsNone(n.at("192.168.1.99", T0))
        self.assertEqual(n.live_at("192.168.1.20", T0 + 3000), d2)
        self.assertIsNone(n.live_at("192.168.1.20", T0 + 8000))               # last seen more than an hour before
        self.assertTrue(n.owned_by("192.168.1.20", d2) and not n.owned_by("192.168.1.20", core.norm_mac(GW)))
        for bad in ((T0, "224.0.0.251", DEV1), (T0, "0.0.0.0", DEV1), (T0, "255.255.255.255", DEV1), (T0, "192.168.1.5", "ff:ff:ff:ff:ff:ff"),
                    (T0, "192.168.1.5", "01:00:5e:00:00:fb"), (T0, "192.168.1.5", "00:00:00:00:00:00"), (T0, "nonsense", DEV1),
                    (T0, 3232235786, DEV1), (T0, "192.168.1.5", None), ("x", "192.168.1.5", DEV1), (float("inf"), "192.168.1.5", DEV1),
                    (True, "192.168.1.5", DEV1), (T0, ["192.168.1.5"], DEV1), (T0, "192.168.1.5", {"a": 1})):
            self.assertFalse(n.see(*bad), bad)
        self.assertEqual(sorted(n.table), ["192.168.1.20"])
        # what is stored can be read back, and a damaged or hostile file is ignored piece by piece
        again = core.Neighbours(json.loads(json.dumps(n.dump(T0 + 9000))))
        self.assertEqual(again.at("192.168.1.20", T0 + 10), d2)
        for junk in (None, [], "x", {"192.168.1.20": "x"}, {"192.168.1.20": [["zz", 1, 2]]}, {"192.168.1.20": [[d1, "1", 2]]},
                     {"not an address": [[d1, 1, 2]]}, {"192.168.001.020": [[d1, 1, 2]]}, {5: [[d1, 1, 2]]},
                     {"192.168.1.20": [[d1, 1]]}, {"192.168.1.20": [[d1, True, 2]]}, {"192.168.1.20": [[d1, float("nan"), 2]]}):
            self.assertEqual(core.Neighbours(junk).table, {}, junk)
        # at most four owners per address, old addresses are forgotten, and the table has a size limit
        for k in range(10):
            n.see(T0 + 20000 + k, "192.168.1.30", f"aa:bb:cc:00:01:{k:02x}")
        self.assertEqual(len(n.table["192.168.1.30"]), 4)
        self.assertEqual(sorted(n.dump(T0 + 20000 + 36 * 86400)), [])
        big = core.Neighbours()
        big.CAP = 5
        for k in range(9):
            big.see(T0 + k, f"192.168.2.{k}", DEV1)
        self.assertEqual(sorted(big.dump(T0 + 10)), [f"192.168.2.{k}" for k in range(4, 9)])

    def test_device_behind_a_router_is_named_by_its_own_mac(self):
        gw = core.norm_mac(GW)
        n = neighbours((T0, "192.168.20.5", DEV2), (T0, "192.168.1.1", GW))
        # a frame on its way to the router: the far side carries the router's MAC address
        rec, _ = tr(conn("192.168.1.10", "192.168.20.5", DEV1, GW), neigh=n)
        self.assertEqual((rec["o"], rec["r"], rec["ib"]), (PZ.device(DEV1), PZ.device(DEV2), ""))
        # the copy captured after the router: now the near side carries the router's MAC address
        rec, _ = tr(conn("192.168.20.5", "192.168.1.10", GW, DEV1), neigh=n)
        self.assertEqual((rec["o"], rec["r"], rec["ib"]), (PZ.device(DEV2), PZ.device(DEV1), ""))
        # the router's own address is the router, under the name its MAC address has
        rec, _ = tr(conn("192.168.1.10", "192.168.1.1", DEV1, GW, rp=53, proto="udp"), neigh=n)
        self.assertEqual((rec["r"], rec["rs"], rec["ib"]), (PZ.device(GW), "lan", ""))
        # a device that no mirrored network has shown is still named by its address
        rec, _ = tr(conn("192.168.1.10", "192.168.30.9", DEV1, GW), neigh=n)
        self.assertEqual((rec["r"], rec["ib"]), (PZ.device_by_ip("192.168.30.9"), "r"))
        # without a table, and for a frame that names the device itself, nothing changes
        rec, _ = tr(conn("192.168.1.10", "192.168.20.5", DEV1, GW))
        self.assertEqual((rec["r"], rec["ib"]), (PZ.device_by_ip("192.168.20.5"), "r"))
        rec, _ = tr(conn("192.168.1.10", "192.168.20.5", DEV1, "aa:bb:cc:00:00:09"), neigh=n, gateways={gw})
        self.assertEqual(rec["r"], PZ.device("aa:bb:cc:00:00:09"))

    def test_address_outside_the_local_networks(self):
        # remote, whatever MAC address the frame carries: a router that is not known as one changes nothing
        rec, _ = tr(conn("192.168.1.10", "52.1.2.3", DEV1, "aa:bb:cc:00:00:09"), gateways=())
        self.assertEqual((rec["rs"], rec["r"]), ("wan", "wan"))
        self.assertEqual(tr(conn("52.1.2.3", "8.8.8.8", DEV1, DEV2), gateways=()), (None, "no_local_endpoint"))
        # local, if the devices themselves place it on the local link (public addresses used inside)
        n = neighbours((T0, "193.140.1.7", DEV2), (T0, "2a02:ff0:1:2::7", DEV2))
        for addr in ("193.140.1.7", "2a02:ff0:1:2::7"):
            rec, _ = tr(conn("192.168.1.10" if "." in addr else "fe80::1", addr, DEV1, DEV2), neigh=n, gateways=())
            self.assertEqual((rec["rs"], rec["r"]), ("lan", PZ.device(DEV2)), addr)

    def test_router_between_local_networks_is_learned(self):
        rx, d1, d2 = core.norm_mac("aa:bb:cc:00:00:fd"), core.norm_mac(DEV1), core.norm_mac(DEV2)
        n = neighbours((T0, "192.168.10.5", DEV1), (T0, "192.168.20.5", DEV2), (T0, "192.168.10.1", "aa:bb:cc:00:00:fd"))
        one = [(0, conn("192.168.10.5", "192.168.20.5", DEV1, "aa:bb:cc:00:00:fd"))]
        two = one + [(0, conn("192.168.20.5", "192.168.10.5", DEV2, "aa:bb:cc:00:00:fd"))]
        self.assertEqual(pipeline.learn_gateways(one, SCOPE, {}, 16, n)[1], set())          # one address is not enough
        state, learned = pipeline.learn_gateways(two, SCOPE, {}, 16, n)
        self.assertEqual(learned, {rx})
        self.assertEqual(state["fwd"][rx], ["192.168.10.5", "192.168.20.5"])
        self.assertEqual(pipeline.learn_gateways([], SCOPE, json.loads(json.dumps(state)), 16, n)[1], {rx})   # remembered
        # a frame to the router's own address, and a frame between two devices, are no sign of a router
        plain = [(0, conn("192.168.10.5", "192.168.10.1", DEV1, "aa:bb:cc:00:00:fd")), (0, conn("192.168.10.5", "192.168.20.5", DEV1, DEV2))]
        self.assertEqual(pipeline.learn_gateways(plain * 5, SCOPE, {}, 16, n)[1], set())
        # an address that moved from one device to another: frames to the old owner are no sign either
        moved = neighbours((T0 - 5000, "192.168.10.5", DEV2), (T0 - 5000, "192.168.10.6", DEV2), (T0, "192.168.10.5", DEV1),
                           (T0, "192.168.10.6", "aa:bb:cc:00:00:07"))
        stale = [(0, conn("192.168.10.9", "192.168.10.5", "aa:bb:cc:00:00:08", DEV2)), (0, conn("192.168.10.9", "192.168.10.6", "aa:bb:cc:00:00:08", DEV2))]
        self.assertEqual(pipeline.learn_gateways(stale, SCOPE, {}, 16, moved)[1], set())
        # an owner that has not been seen for hours does not count
        old = neighbours((T0 - 9000, "192.168.10.5", DEV1), (T0 - 9000, "192.168.20.5", DEV2))
        self.assertEqual(pipeline.learn_gateways(two, SCOPE, {}, 16, old)[1], set())
        # an address on the local link is not an address behind a router, however many there are
        many = neighbours(*[(T0, f"193.140.{i}.7", DEV1) for i in range(30)])
        pc = [(0, conn(f"193.140.{i}.7", "192.168.1.20", DEV1, DEV2)) for i in range(30)]
        self.assertEqual(pipeline.learn_gateways(pc, SCOPE, {}, 16, many)[1], set())
        self.assertEqual(pipeline.learn_gateways(pc, SCOPE, {}, 16)[1], {d1})                  # without the table it would be
        # a damaged state file on the key stick is ignored
        for junk in (None, [], {"nets": 5}, {"nets": {"zz": ["a"]}, "fwd": {rx: "x"}}, {rx: ["1.2.3.0/24"] * 20}):
            self.assertEqual(pipeline.learn_gateways([], SCOPE, junk, 16)[1], set(), junk)
        self.assertNotIn(d2, learned)

    def test_whitelist_names_values(self):
        good = conn("192.168.1.10", "192.168.1.20", DEV1, DEV2)
        rec, _ = tr(dict(good, service="ssl,pc-reception,dns", conn_state="c0a8010a", history="DrAhmetYilmaz",
                         orig_bytes=2 ** 60, vlan=70000, ip_proto=999, duration=1e12, **{"id.resp_p": 3232235786}))
        self.assertEqual((rec["svc"], rec["st"], rec["hist"], rec["ob"], rec["vlan"], rec["ipp"], rec["dur"], rec["rp"]),
                         ("ssl,dns", "", "", 0, -1, -1, 0.0, -1))
        self.assertIsNone(core.leak_check(rec))
        for field, bad in (("svc", "192-168-1-10"), ("svc", "pc-reception"), ("st", "c0a8010a"), ("hist", "DrAhmet"),
                           ("proto", "reception_pc_01"), ("ob", 2 ** 60), ("rp", 3232235786.5e9)):
            self.assertIsNotNone(core.leak_check(dict(rec, **{field: bad})), (field, bad))
        self.assertEqual(tr(dict(good, proto="reception_pc_01")), (None, "malformed"))
        self.assertEqual(tr(dict(good, ts=2 ** 70)), (None, "malformed"))

    def test_gateway_learning_and_dedup_preference(self):
        recs = [(0, conn("192.168.1.10", f"52.1.{i}.3", DEV1, "00:de:ad:be:ef:00")) for i in range(20)]
        state, learned = pipeline.learn_gateways(recs, SCOPE, {}, 16)
        self.assertEqual(learned, {"00deadbeef00"})
        self.assertNotIn(core.norm_mac(DEV1), learned)
        # the same connection seen behind a router on one mirror and directly on the other
        near = conn("192.168.1.10", "192.168.2.20", DEV1, DEV2, orig_pkts=3)
        far = conn("192.168.1.10", "192.168.2.20", GW, DEV2, orig_pkts=30)
        kept, n = pipeline.dedup([(0, far), (1, near)], 2, {core.norm_mac(GW)})
        self.assertEqual((n, kept[0][1]["orig_l2_addr"]), (1, DEV1))
        # not duplicates: the same port twice, more than the window apart, or a report next to the final record
        a = conn("192.168.1.10", "192.168.1.20", DEV1, DEV2)
        for other in ((0, dict(a, ts=a["ts"] + 1)), (1, dict(a, ts=a["ts"] + 2.5)), (1, dict(a, _open=True))):
            self.assertEqual(pipeline.dedup([(0, a), other], 2)[1], 0, other)
        self.assertEqual(pipeline.dedup([(0, a), (1, dict(a, ts=a["ts"] + 1.9))], 2)[1], 1)


if __name__ == "__main__":
    unittest.main()
