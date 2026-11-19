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
            summary = ar.convert(src, norm, dataset="t", tz="Europe/Istanbul")
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
            (A, "01", f"6/out/1883@dev:{B}"), (B, "01", f"6/in/1883@dev:{A}"),
        })
        self.assertEqual(volume[(A, "29", f"6/out/1883@dev:{B}")], 30)
        self.assertEqual(volume[(A, "30", f"6/out/1883@dev:{B}")], 0)                  # bytes come with the final record
        self.assertEqual(summary["open_rows"], 6)                           # three reports, two sides each

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
