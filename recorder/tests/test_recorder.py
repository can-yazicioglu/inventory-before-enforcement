# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
import gzip
import json
import os
import sys
import tempfile
import unittest

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


def tr(rec, tokens=False, names=None, gateways=(core.norm_mac(GW),)):
    return core.transform(rec, PZ, SCOPE, set(gateways), tokens, names or {}, PSL, CAT, 0)


class CoreTests(unittest.TestCase):
    def test_pseudonym_is_stable_and_keyed(self):
        self.assertEqual(PZ.device("AA-BB-CC-00-00-01"), PZ.device(DEV1))
        self.assertNotEqual(PZ.device(DEV1), PZ.device(DEV2))
        self.assertNotEqual(PZ.device(DEV1), core.Pseudonymiser(bytes(32)).device(DEV1))
        self.assertRegex(PZ.device(DEV1), r"^d[a-z2-7]{10}$")

    def test_scope(self):
        self.assertEqual(SCOPE.of("192.168.1.5"), "lan")
        self.assertEqual(SCOPE.of("8.8.8.8", GW, {core.norm_mac(GW)}), "wan")
        self.assertEqual(SCOPE.of("8.8.8.8"), "wan")
        self.assertEqual(SCOPE.of("193.140.1.7", DEV1, {core.norm_mac(GW)}), "lan")   # public space used inside
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
        self.assertTrue(core.established({"proto": "udp", "resp_pkts": 1}))
        self.assertFalse(core.established({"proto": "udp", "resp_pkts": 0, "resp_bytes": 0}))

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
                        gateway_macs=[GW], interfaces=["eth1", "eth2"], sysfs_net=f"{t}/sys")
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

    def test_swap_detection(self):
        p = os.path.join(self.tmp.name, "swaps")
        head = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
        for body, want in (("", False), ("/dev/zram0 partition 2097148 0 100\n", False),
                           ("/var/swap file 204796 0 -2\n", True)):
            with open(p, "w") as f:
                f.write(head + body)
            self.assertEqual(pipeline.disk_swap_on(p), want, body)

    def test_semicolon_device_table(self):
        with open(os.path.join(self.cfg["key_dir"], "devices.csv"), "w", encoding="utf-8-sig") as f:
            f.write("MAC;IP;Type;Brand;Model;Group;Visibility;Switch\n"
                    f"{DEV1.upper().replace(':', '-')};;ip_phone;Yealink;T31P;agentless;full;A\n")
        labels, problems = pipeline.load_devices(self.cfg["key_dir"], PZ)
        self.assertEqual(labels[PZ.device(DEV1)]["type"], "ip_phone")
        self.assertEqual(problems, [])

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


if __name__ == "__main__":
    unittest.main()
