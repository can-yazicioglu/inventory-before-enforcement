# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Recorder output through the adapter and the incidence step: which flow types come out."""
import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import adapt_recorder as ar  # noqa: E402

A, B, C, GWD = "daaaaaaaaaa", "dbbbbbbbbbb", "dcccccccccc", "dggggggggggg"[:11]
T0 = 1798538400            # 2026-12-29 13:00 in Istanbul
DAY = 86400


def rec(o, r, op, rp, ts=T0, proto="tcp", hist="ShADadFf", est=True, ob=100, rb=200, os_="lan", rs="lan", **kw):
    out = {"ts": ts, "dur": 1.0, "proto": proto, "ipp": 6 if proto == "tcp" else 17, "op": op, "rp": rp, "os": os_,
           "rs": rs, "o": o, "r": r, "st": "SF", "hist": hist, "svc": "", "ob": ob, "rb": rb, "opk": 5, "rpk": 4,
           "est": est, "vlan": -1, "if": 0, "ib": ""}
    out.update(kw)
    return out


class RowTests(unittest.TestCase):
    def run_chain(self, records, role="init"):
        import duckdb
        with tempfile.TemporaryDirectory() as t:
            src = os.path.join(t, "export")
            os.makedirs(os.path.join(t, "inc", "tmp"))
            os.makedirs(src)
            with gzip.open(os.path.join(src, "anon-A-1-x.jsonl.gz"), "wt", encoding="utf-8") as f:
                f.write("".join(json.dumps(r) + "\n" for r in records))
            with open(os.path.join(src, "status.json"), "w") as f:
                json.dump({"site": "A", "gateways": [GWD]}, f)
            with open(os.path.join(src, "coverage.jsonl"), "w") as f:
                f.write('{"t": 1, "q": {}, "key": "aaaa1111"}\n{"t": 2, "q": {}, "key": "aaaa1111"}\n')
            norm = os.path.join(t, "norm.parquet")
            summary = ar.convert(src, norm, dataset="t", tz="Europe/Istanbul", hours="none")
            env = dict(os.environ, GT_INPUTS=f"{norm}|Europe/Istanbul")
            env.pop("GT_ROLE", None)
            if role:
                env["GT_ROLE"] = role
            r = subprocess.run([sys.executable, "-W", "ignore", os.path.join(HERE, "..", "incidence3.py"), "x", "x",
                                os.path.join(t, "inc")], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            con = duckdb.connect()
            inc = con.execute(f"""SELECT device, CAST(day AS VARCHAR), ftype, b FROM read_parquet('{t}/inc/inc_day.parquet')
                                  WHERE gran = 'svc'""").fetchall()
            rows = con.execute(f"SELECT device, dev_init, dev_pl, n_bytes, is_open, no_handshake FROM read_parquet('{norm}')"
                               ).fetchall()
        return {(d, day[8:10], f) for d, day, f, _ in inc}, {(d, day[8:10], f): b for d, day, f, b in inc}, rows, summary

    def test_handshake_seen(self):
        types, _, rows, _ = self.run_chain([
            rec(A, B, 50000, 445),                                   # answered
            rec(A, B, 50001, 23, hist="Sr", est=False, rb=0),        # refused
            rec(A, B, 50002, 8443, hist="S", est=False, rb=0),       # no answer
            rec(A, "wan", 50003, 443, rs="wan", wc="other"),
            rec(A, "mcast:mdns", 5353, 5353, proto="udp", hist="D", est=False, rs="mcast"),
            rec(A, B, 50004, 161, proto="udp", hist="Dd"),           # answered UDP
            rec(A, C, 50005, 161, proto="udp", hist="D", est=False, rb=0),
            rec(GWD, B, 50006, 22),                                  # the gateway is not a device
        ])
        self.assertEqual(types, {
            (A, "29", f"6/out/445@dev:{B}"), (B, "29", f"6/in/445@dev:{A}"),
            (A, "29", f"6/out/23@dev:{B}"), (A, "29", f"6/out/8443@dev:{B}"),           # B did not take part
            (A, "29", "6/out/443@wan"), (A, "29", "17/out/5353@mcast:mdns"),
            (A, "29", f"17/out/161@dev:{B}"), (B, "29", f"17/in/161@dev:{A}"),
            (A, "29", f"17/out/161@dev:{C}"),
            (B, "29", f"6/in/22@dev:{GWD}"),
        })
        self.assertTrue(all(r[1] is not None and not r[5] for r in rows))
        self.assertEqual(self.run_chain([rec(A, B, 50000, 445)])[3]["keys"], ["aaaa1111"])

    def test_handshake_not_seen_falls_back_to_port_rules(self):
        normal = [rec(A, B, 50000 + i, 8081, ts=T0 + i) for i in range(3)]
        types, _, rows, summary = self.run_chain(normal + [
            # picked up in the middle: the server B spoke first, so Zeek calls it the originator
            rec(B, A, 8081, 2001, ts=T0 + 100, hist="Da", ob=30, rb=0),
            # a stray packet answered by a reset: only the sender counts
            rec(A, C, 50007, 9000, ts=T0 + 200, hist="Ar", est=False, ob=0, rb=0),
            # the other side never sent anything but resets
            rec(C, A, 50008, 9001, ts=T0 + 300, hist="Rr", est=False, ob=0, rb=0),
            # direction turned by Zeek's port rule, handshake still not seen
            rec(A, "wan", 50009, 443, ts=T0 + 400, hist="^dA", rs="wan", wc="other", ob=0, rb=30),
        ])
        self.assertEqual(types, {
            (A, "29", f"6/out/8081@dev:{B}"), (B, "29", f"6/in/8081@dev:{A}"),      # the same types as the normal ones
            (A, "29", f"6/out/9000@dev:{C}"),
            (A, "29", "6/out/443@wan"),
        })
        unknown = [r for r in rows if r[5]]
        self.assertEqual(len(unknown), 4)                       # B and A, A alone, nobody, A alone
        self.assertTrue(all(r[1] is None and r[2] >= 1 for r in unknown))
        self.assertEqual(summary["no_handshake_rows"], 4)

    def test_wrong_role_without_the_rule(self):
        """What the fallback prevents: taken at face value, the server would open a connection to a client port."""
        normal = [rec(A, B, 50000 + i, 8081, ts=T0 + i) for i in range(3)]
        mid = rec(B, A, 8081, 2001, ts=T0 + 100, hist="ShADad", ob=30, rb=0)      # as if the handshake had been seen
        types, _, _, _ = self.run_chain(normal + [mid])
        self.assertIn((B, "29", f"6/out/2001@dev:{A}"), types)

    def test_open_reports_mark_presence_without_bytes(self):
        long = dict(hist="ShADad", open=True)
        types, volume, rows, summary = self.run_chain([
            rec(A, B, 50000, 1883, ts=T0, ob=10, rb=20),                              # day 29: a short one, finished
            rec(A, B, 50001, 1883, ts=T0 + DAY, ob=5, rb=5, **long),                   # day 30: open, both sides sent
            rec(A, B, 50001, 1883, ts=T0 + 2 * DAY, ob=5, rb=0, rpk=0, est=False, **long),   # day 31: only A sent
            rec(A, B, 50001, 1883, ts=T0 + 3 * DAY, ob=0, rb=7, opk=0, **long),        # day 1: only B sent
        ])
        self.assertEqual(types, {
            (A, "29", f"6/out/1883@dev:{B}"), (B, "29", f"6/in/1883@dev:{A}"),
            (A, "30", f"6/out/1883@dev:{B}"), (B, "30", f"6/in/1883@dev:{A}"),
            (A, "31", f"6/out/1883@dev:{B}"),                                         # B silent that day
            (B, "01", f"6/in/1883@dev:{A}"),                                          # A silent that day (switched off)
        })
        self.assertEqual(volume[(A, "29", f"6/out/1883@dev:{B}")], 30)
        self.assertEqual(volume[(A, "30", f"6/out/1883@dev:{B}")], 0)                  # bytes come with the final record
        self.assertEqual(summary["open_rows"], 5)             # three reports, two sides each, less the silent opener

    def test_udp_turned_around_by_zeek(self):
        """The first packet came from a server port: an answer whose question went to a group address
        (LLMNR, mDNS) or was not captured. The asker sent nothing in this flow and gets no flow type."""
        types, _, rows, _ = self.run_chain([rec(A, B, 50000 + i, 5355, ts=T0 + i, proto="udp", hist="Dd") for i in range(3)] + [
            rec(C, B, 50010, 5355, ts=T0 + 50, proto="udp", hist="^d", ob=0, rb=40, opk=0, rpk=1),       # only B sent
            rec(C, B, 50011, 5355, ts=T0 + 60, proto="udp", hist="^dD", ob=20, rb=40, opk=1, rpk=1),     # C sent later
            rec(C, "mcast:llmnr", 50010, 5355, ts=T0 + 49, proto="udp", hist="D", est=False, rs="mcast"),
        ])
        self.assertEqual(types, {
            (A, "29", f"17/out/5355@dev:{B}"), (B, "29", f"17/in/5355@dev:{A}"),
            (B, "29", f"17/in/5355@dev:{C}"),                       # B answered C
            (C, "29", f"17/out/5355@dev:{B}"),                      # from the flow in which C did send
            (C, "29", "17/out/5355@mcast:llmnr"),
        })
        self.assertEqual(sum(1 for r in rows if r[0] == C and r[5]), 1)          # C has one row from a turned record

    def test_protocols_without_ports(self):
        icmp = dict(proto="icmp", ipp=1, hist="")
        types, _, _, _ = self.run_chain([
            rec(A, B, 8, 0, ts=T0, est=True, **icmp),                 # ping answered
            rec(A, C, 8, 0, ts=T0 + 1, est=False, rb=0, **icmp),      # ping not answered
            rec(C, A, 3, 3, ts=T0 + 2, est=False, rb=0, **icmp),      # an error message, nothing comes back
            rec(A, B, 8, 0, ts=T0 + DAY, open=True, opk=0, rpk=3, est=True, ob=0, rb=30, **icmp),   # only B still sends
        ])
        self.assertEqual(types, {
            (A, "29", f"1@dev:{B}"), (B, "29", f"1@dev:{A}"),
            (A, "29", f"1@dev:{C}"),                                 # C got a ping and did not answer it
            (B, "30", f"1@dev:{A}"),                                 # C's error message gives nobody a flow type
        })

    def test_finished_record_of_a_long_connection_speaks_for_its_opener_only(self):
        """A finished record is stamped with its start, and its 'est' and its history cover its whole life.
        If it ends in a later clock hour, who sent on which day is taken from the hourly reports. Here the
        other side is switched off on the 29th and sends from the 30th on."""
        long, report = dict(dur=30 * 3600.0), dict(open=True)        # 13:00 on the 29th to 19:00 on the 30th
        silent_r, silent_o = dict(rpk=0, rb=0, est=False), dict(opk=0, ob=0)
        icmp = dict(proto="icmp", ipp=1, hist="")
        types, _, _, _ = self.run_chain([
            # a datagram every minute from A to B
            rec(A, B, 40001, 7000, ts=T0, proto="udp", hist="Dd", **long),
            rec(A, B, 40001, 7000, ts=T0 + 3599, proto="udp", hist="D", **silent_r, **report),
            rec(A, B, 40001, 7000, ts=T0 + DAY, proto="udp", hist="Dd", **report),
            # a ping from A to C
            rec(A, C, 8, 0, ts=T0, **icmp, **long),
            rec(A, C, 8, 0, ts=T0 + 3599, **icmp, **silent_r, **report),
            rec(A, C, 8, 0, ts=T0 + DAY, **icmp, **report),
            # a record that Zeek turned around: B sends from port 443, its originator C is the silent one
            rec(C, B, 40002, 443, ts=T0, proto="udp", hist="^dD", **long),
            rec(C, B, 40002, 443, ts=T0 + 3599, proto="udp", hist="^d", **silent_o, **report),
            rec(C, B, 40002, 443, ts=T0 + DAY, proto="udp", hist="^dD", **report),
            # a TCP connection picked up without its handshake, the same
            rec(C, B, 40003, 8081, ts=T0, hist="dDaA", **long),
            rec(C, B, 40003, 8081, ts=T0 + 3599, hist="d", **silent_o, **report),
            rec(C, B, 40003, 8081, ts=T0 + DAY, hist="dDaA", **report),
            # a flow that lies within one clock hour has no report: its record counts for both sides
            rec(A, B, 40004, 9000, ts=T0 + 10, proto="udp", hist="Dd", dur=3000.0),
            # the last second of the hour belongs to it: no report is written for such a record
            rec(A, B, 40005, 9001, ts=T0 + 10, proto="udp", hist="Dd", dur=3590.0),
        ])
        self.assertEqual(types, {
            (A, "29", f"17/out/7000@dev:{B}"), (A, "30", f"17/out/7000@dev:{B}"), (B, "30", f"17/in/7000@dev:{A}"),
            (A, "29", f"1@dev:{C}"), (A, "30", f"1@dev:{C}"), (C, "30", f"1@dev:{A}"),
            (B, "29", f"17/in/443@dev:{C}"), (B, "30", f"17/in/443@dev:{C}"), (C, "30", f"17/out/443@dev:{B}"),
            (B, "29", f"6/in/8081@dev:{C}"), (B, "30", f"6/in/8081@dev:{C}"), (C, "30", f"6/out/8081@dev:{B}"),
            (A, "29", f"17/out/9000@dev:{B}"), (B, "29", f"17/in/9000@dev:{A}"),
            (A, "29", f"17/out/9001@dev:{B}"), (B, "29", f"17/in/9001@dev:{A}"),
        })

    def test_outage_rule_must_be_chosen(self):
        import contextlib
        import io
        argv = sys.argv
        sys.argv = ["adapt_recorder.py", "in", "out.parquet"]                 # no --hours
        try:
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                ar.main()
        finally:
            sys.argv = argv

    def test_open_report_without_handshake(self):
        types, _, rows, _ = self.run_chain([rec(A, B, 50000 + i, 1883, ts=T0 + i) for i in range(3)] + [
            rec(B, A, 1883, 3000, ts=T0 + DAY, hist="Da", open=True, ob=9, rb=0),          # both sent in that hour
            rec(B, A, 1883, 3000, ts=T0 + 2 * DAY, hist="Da", open=True, ob=9, rb=0, rpk=0, est=False),   # only B sent
        ])
        self.assertEqual(types, {
            (A, "29", f"6/out/1883@dev:{B}"), (B, "29", f"6/in/1883@dev:{A}"),
            (A, "30", f"6/out/1883@dev:{B}"), (B, "30", f"6/in/1883@dev:{A}"),
            (B, "31", f"6/in/1883@dev:{A}"),
        })

    def test_port_rules_for_everything_as_sensitivity(self):
        """GT_ROLE unset: roles from port fan-out for every record, the recorded opener only breaks ties."""
        recs = [rec(A, B, 50000 + i, 8081, ts=T0 + i) for i in range(3)]
        self.assertEqual(self.run_chain(recs, role=None)[0], self.run_chain(recs)[0])


if __name__ == "__main__":
    unittest.main()
