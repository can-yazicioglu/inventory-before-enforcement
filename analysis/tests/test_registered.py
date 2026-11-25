# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""The analyses registered on 25 November 2026 (docs/method.md): the bound that is valid at every look, lists of flow types
seen on at least k days, the unit filters, the coverage of a capture, and the chain from an incidence table to the tables."""
import csv
import datetime
import os
import subprocess
import sys
import tempfile
import unittest

import duckdb
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
A = os.path.join(HERE, "..")
sys.path.insert(0, A)
import reglib  # noqa: E402

D0 = datetime.date(2027, 1, 4)          # a Monday


def run(*args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-I", "-W", "ignore", *args], check=True, capture_output=True, text=True, env=e).stdout


def write_inc(path, rows):
    """rows: (dataset, site, device, day, gran, ftype, n)"""
    con = duckdb.connect()
    con.execute("CREATE TABLE t (dataset VARCHAR, site VARCHAR, device VARCHAR, day DATE, gran VARCHAR, ftype VARCHAR, n BIGINT, b DOUBLE)")
    con.executemany("INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, 0)", rows)
    con.execute(f"COPY t TO '{path}' (FORMAT parquet)")
    con.close()


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def read(path, sql="SELECT * FROM t"):
    con = duckdb.connect()
    con.execute(f"CREATE VIEW t AS SELECT * FROM read_parquet('{path}')")
    return con.execute(sql).fetchall()


class EveryLookTests(unittest.TestCase):
    def test_levels_add_up_to_the_nominal_level(self):
        daily = sum(float(reglib.tu_alpha(T)) for T in range(7, 20007))
        weekly = sum(float(reglib.tu_alpha(T, weekly=True)) for T in range(7, 7 * 20001, 7))
        self.assertLess(daily, 0.05)
        self.assertLess(weekly, 0.05)
        self.assertAlmostEqual(daily, 0.05, places=5)
        self.assertAlmostEqual(weekly, 0.05, places=5)
        self.assertAlmostEqual(float(reglib.tu_alpha(7)), 0.025)
        self.assertAlmostEqual(float(reglib.tu_alpha(14, weekly=True)), 0.05 / 6)

    def test_a_day_that_is_no_look_cannot_enforce(self):
        self.assertTrue(np.isnan(reglib.tu_alpha(8, weekly=True)))
        self.assertTrue(np.isinf(reglib.tu_first_term(0, 20, weekly=True)))
        self.assertTrue(np.isinf(reglib.tu_first_term(0, 6)))
        self.assertTrue(np.isfinite(reglib.tu_first_term(0, 21, weekly=True)))

    def test_first_possible_enforcement_days_are_those_of_the_method_note(self):
        """Without any singleton: GT-C day 10 and day 30, daily looks day 32 and day 126, weekly looks day 21 and day 84."""
        got = {eps: (reglib.first_possible_day(eps), reglib.first_possible_day(eps, False), reglib.first_possible_day(eps, True))
               for eps in (0.1, 0.3, 1.0)}
        self.assertEqual(got, {0.1: (30, 126, 84), 0.3: (10, 32, 21), 1.0: (7, 7, 7)})

    def test_never_below_the_frozen_bound(self):
        from scipy import stats
        for q1 in (0, 1, 5, 40):
            for T in range(7, 200):
                frozen = stats.chi2.ppf(0.95, 2 * (q1 + 1)) / (2 * T)
                self.assertGreater(float(reglib.tu_first_term(q1, T)), frozen)

    def test_arrays(self):
        got = reglib.tu_first_term(np.array([0, 1, 2]), np.array([32, 43, 53]))
        self.assertEqual(got.shape, (3,))
        self.assertTrue((got <= 0.3).all())
        self.assertTrue((reglib.tu_first_term(np.array([0, 1, 2]), np.array([31, 42, 52])) > 0.3).all())


class ListTests(unittest.TestCase):
    #          learning days 0..4      | days after enforcement 5..8
    M = np.array([[1, 1, 1, 1, 1,       1, 1, 1, 1],     # seen every day
                  [1, 0, 1, 0, 0,       0, 1, 0, 0],     # seen on two learning days
                  [0, 0, 0, 1, 0,       1, 0, 1, 0],     # seen on one learning day
                  [0, 0, 0, 0, 0,       0, 1, 1, 0],     # new after enforcement
                  [0, 0, 0, 0, 0,       0, 0, 0, 1]], dtype=bool)
    W = M * np.array([[10], [1], [2], [3], [4]], dtype=float)

    def test_primary_list(self):
        r = reglib.list_outcomes(self.M, self.W, 5, 4, 1)
        self.assertEqual((r["list_size"], r["new_types"], r["once_days"], r["never_days"]), (3, 2, 2, 3))
        self.assertEqual((r["blocked"], r["total"]), (10.0, 55.0))

    def test_at_least_two_days(self):
        r = reglib.list_outcomes(self.M, self.W, 5, 4, 2)
        # the type seen on one learning day is outside the list: it alerts once on day 5 and is used again on day 7
        self.assertEqual((r["list_size"], r["new_types"], r["once_days"], r["never_days"]), (2, 3, 3, 4))
        self.assertEqual(r["blocked"], 14.0)

    def test_at_least_three_days(self):
        r = reglib.list_outcomes(self.M, self.W, 5, 4, 3)
        self.assertEqual((r["list_size"], r["new_types"], r["once_days"], r["never_days"]), (1, 4, 3, 4))
        self.assertEqual(r["blocked"], 15.0)

    def test_horizon_cut(self):
        r = reglib.list_outcomes(self.M, self.W, 5, 2, 1)
        self.assertEqual((r["new_types"], r["once_days"], r["never_days"]), (1, 1, 1))

    def test_exact_upper_limit(self):
        self.assertAlmostEqual(reglib.exact_upper(0, 9), 0.336, places=3)      # as in fixed_list.py for 9 devices
        self.assertEqual(reglib.exact_upper(4, 4), 1.0)
        self.assertTrue(np.isnan(reglib.exact_upper(0, 0)))


class UnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_coverage(self):
        con = duckdb.connect()
        con.execute("""CREATE TABLE t AS SELECT * FROM (VALUES
            ('x', 's', TIMESTAMP '2027-01-04 13:30:00'), ('x', 's', TIMESTAMP '2027-01-05 13:00:00'),
            ('x', 's', TIMESTAMP '2027-01-05 14:00:00'), ('x', 's', TIMESTAMP '2027-01-06 00:00:00')) v(dataset, site, ts)""")
        con.execute(f"COPY t TO '{self.d}/n.parquet' (FORMAT parquet)")
        con.close()
        run(f"{A}/coverage.py", f"{self.d}/c.csv", f"norm|{self.d}/n.parquet|Australia/Sydney")
        rows = {r["day"]: r for r in read_csv(f"{self.d}/c.csv")}
        # Sydney is 11 hours ahead of UTC in January: the four records fall on 5 January 00:30 and 6 January 00:00, 01:00 and 11:00
        self.assertEqual(sorted(rows), ["2027-01-05", "2027-01-06"])
        self.assertAlmostEqual(float(rows["2027-01-05"]["hours"]), 0.0)
        self.assertAlmostEqual(float(rows["2027-01-06"]["hours"]), 11.0)
        self.assertEqual(rows["2027-01-06"]["partial"], "True")

    def test_variants(self):
        rows, cov = [], []
        for i in range(120):                                  # a capture of 120 days: long enough for the two parts
            day = D0 + datetime.timedelta(days=i)
            hours = 12.0 if i in (3, 60) else 23.9            # two partial recording days
            cov.append(("long", "a", day.isoformat(), hours))
            rows.append(("long", "a", "dev1", day, "svc", "t", 1))
        for i in range(30):                                   # a short capture: no parts
            day = D0 + datetime.timedelta(days=i)
            cov.append(("short", "b", day.isoformat(), 23.9))
            rows.append(("short", "b", "dev2", day, "svc", "t", 1))
        rows.append(("hvac", "hvac", "dev3", D0, "svc", "t", 1))  # a trace whose unit is not the day is left out
        cov.append(("hvac", "hvac", D0.isoformat(), 23.9))
        write_inc(f"{self.d}/inc.parquet", rows)
        with open(f"{self.d}/cov.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["dataset", "site", "day", "hours"])
            w.writerows(cov)
        run(f"{A}/sens_units.py", f"{self.d}/cov.csv", f"{self.d}/out", f"{self.d}/inc.parquet")
        days = lambda v, ds: [r[0] for r in read(f"{self.d}/out/{v}/inc_day.parquet", f"SELECT day FROM t WHERE dataset = '{ds}' ORDER BY day")]
        self.assertEqual(len(days("partial20", "long")), 118)
        self.assertNotIn(D0 + datetime.timedelta(days=3), days("partial20", "long"))
        self.assertEqual(len(days("partial20", "short")), 30)
        self.assertEqual({d.isoweekday() for d in days("wd5", "long")}, {1, 2, 3, 4, 5})
        self.assertEqual({d.isoweekday() for d in days("wd6", "long")}, {1, 2, 3, 4, 5, 6})
        self.assertEqual(len(days("wd5", "long")), 86)        # 17 full weeks and Monday of week 18
        p1, p2 = days("part1", "long"), days("part2", "long")
        self.assertEqual((p1[0], p1[-1], len(p1)), (D0, D0 + datetime.timedelta(days=55), 56))
        self.assertEqual((p2[0], p2[-1], len(p2)), (D0 + datetime.timedelta(days=56), D0 + datetime.timedelta(days=111), 56))
        self.assertEqual(days("part1", "short"), [])
        for v in ("partial20", "wd5", "wd6", "part1", "part2"):
            self.assertEqual(days(v, "hvac"), [])
        removed = {r["dataset"]: r for r in read_csv(f"{self.d}/out/partial20/days.csv")}
        self.assertEqual(float(removed["long"]["days_removed"]), 2.0)

    def test_a_day_without_coverage_stops_the_run(self):
        write_inc(f"{self.d}/inc.parquet", [("x", "s", "dev", D0, "svc", "t", 1)])
        with open(f"{self.d}/cov.csv", "w") as f:
            f.write("dataset,site,day,hours\nx,s,2027-01-05,23.0\n")
        with self.assertRaises(subprocess.CalledProcessError):
            run(f"{A}/sens_units.py", f"{self.d}/cov.csv", f"{self.d}/out", f"{self.d}/inc.parquet")


class ChainTests(unittest.TestCase):
    """A small synthetic site through the frozen chain and the new tables. The numbers are not checked against a model:
    the test checks that the tables agree with each other where they state the same quantity."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.d = cls.tmp.name
        rng = np.random.default_rng(3)
        rows = []
        for dev in range(6):
            p = np.concatenate([np.full(4, 0.95), rng.uniform(0.02, 0.5, 6), rng.uniform(0.002, 0.03, 30)])
            for i in range(150):
                day = D0 + datetime.timedelta(days=i)
                for t in np.nonzero(rng.random(len(p)) < p)[0]:
                    for gran in ("port", "svc"):
                        rows.append(("syn", "a", f"dev{dev}", day, gran, f"t{t if gran == 'svc' else t // 2}", int(1 + t)))
        write_inc(f"{d}/inc.parquet", rows)
        os.makedirs(f"{d}/res")
        run(f"{A}/run_series3.py", f"{d}/inc.parquet", f"{d}/res", env={"GT_GRANS": "port,svc"})
        run("-c", f"import sys, pandas as pd; sys.path.insert(0, r'{A}'); import scores; "
                  f"scores.add_scores(pd.read_parquet(r'{d}/res/series.parquet')).to_parquet(r'{d}/res/scored.parquet', index=False)")
        run(f"{A}/eval_all3.py", f"{d}/res", "14", "7")
        run(f"{A}/fixed_list.py", f"{d}/inc.parquet", f"{d}/res")
        run(f"{A}/rules_eval.py", f"{d}/inc.parquet", f"{d}/res")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def table(self, name):
        return read_csv(f"{self.d}/res/tables/{name}.csv")

    def test_k1_is_the_primary_analysis(self):
        seq = {(r["gran"], r["rule"]): r for r in self.table("sequential_H14") if float(r["eps"]) == 0.3}
        fx = {(r["gran"], r["rule"]): r for r in self.table("fixed_list_alert")}
        n = 0
        for r in self.table("min_k"):
            if r["k"] != "1" or not r["med_T"]:
                continue
            s, f = seq[r["gran"], r["rule"]], fx[r["gran"], r["rule"]]
            self.assertAlmostEqual(float(r["stopped"]), float(s["stopped"]))
            self.assertAlmostEqual(float(r["med_T"]), float(s["med_T"]))
            self.assertAlmostEqual(float(r["exceed_once"]), float(s["violA"]))
            self.assertAlmostEqual(float(r["exceed_types"]), float(s["viol"]))
            self.assertAlmostEqual(float(r["exceed_never"]), float(f["exceed_fixed_list"]))
            self.assertEqual(int(float(r["devices"])), int(float(f["devices"])))
            self.assertAlmostEqual(float(r["exact_upper_limit"]), float(f["exact_upper_limit"]))
            self.assertAlmostEqual(float(r["list_share"]), 1.0)
            n += 1
        self.assertGreaterEqual(n, 4)

    def test_a_stricter_list_is_smaller_and_alerts_more(self):
        by = {}
        for r in self.table("min_k"):
            if r["med_T"]:
                by.setdefault((r["gran"], r["rule"]), {})[int(r["k"])] = r
        for cell in by.values():
            self.assertEqual(sorted(cell), [1, 2, 3])
            for a, b in ((1, 2), (2, 3)):
                self.assertGreaterEqual(float(cell[a]["list_share"]), float(cell[b]["list_share"]))
                self.assertLessEqual(float(cell[a]["mean_never_days"]), float(cell[b]["mean_never_days"]))
                self.assertLessEqual(float(cell[a]["blocked_pct_pooled"]), float(cell[b]["blocked_pct_pooled"]))

    def test_every_look_enforces_later_and_no_more_often(self):
        t = {(r["gran"], float(r["eps"]), r["rule"]): r for r in self.table("time_uniform")}
        for (gran, eps, rule), r in t.items():
            ref = t[gran, eps, "GT-C"]
            self.assertLessEqual(float(r["stopped"]), float(ref["stopped"]) + 1e-12)
            if rule != "GT-C" and r["med_T"]:
                self.assertGreaterEqual(float(r["med_delay"]), 0.0)
                self.assertEqual(int(float(r["also_gtc"])), round(float(r["stopped"]) * int(r["episodes"])))
                if eps == 0.3:
                    self.assertGreaterEqual(float(r["med_T"]), 32 if rule.endswith("daily") else 21)
        self.assertEqual({r["rule"] for r in self.table("time_uniform")}, {"GT-C", "GT-C every look, daily", "GT-C every look, weekly"})


class ReplicationTests(unittest.TestCase):
    """Three synthetic captures through the two-part chain of run_sens.sh: one that is long enough, one whose part 2 holds
    too few days with records, and one whose part 1 holds too few days for any learning episode that can be evaluated."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.d = cls.tmp.name
        rng = np.random.default_rng(5)
        spans = {"full": list(range(150)), "short2": list(range(56)) + list(range(56, 86)) + list(range(112, 140)),
                 "gap1": list(range(18)) + list(range(56, 150))}
        rows, cov = [], []
        for ds, days in spans.items():
            cov += [(ds, D0 + datetime.timedelta(days=i)) for i in days]
            for dev in range(5):
                p = np.concatenate([np.full(4, 0.95), rng.uniform(0.02, 0.5, 4), rng.uniform(0.002, 0.02, 8)])
                for i in days:
                    for t in np.nonzero(rng.random(len(p)) < p)[0]:
                        rows.append((ds, "a", f"dev{dev}", D0 + datetime.timedelta(days=i), "svc", f"t{t}", int(1 + t)))
        write_inc(f"{d}/inc.parquet", rows)
        with open(f"{d}/cov.csv", "w") as f:
            f.write("dataset,site,day,hours\n" + "".join(f"{ds},a,{day},24.0\n" for ds, day in cov))
        run(f"{A}/sens_units.py", f"{d}/cov.csv", f"{d}/sens", f"{d}/inc.parquet")
        for v in ("part1", "part2"):
            r = f"{d}/sens/{v}/res"
            os.makedirs(r)
            run(f"{A}/run_series3.py", f"{d}/sens/{v}/inc_day.parquet", r, env={"GT_GRANS": "svc"})
            run("-c", f"import sys, pandas as pd; sys.path.insert(0, r'{A}'); import scores; "
                      f"scores.add_scores(pd.read_parquet(r'{r}/series.parquet')).to_parquet(r'{r}/scored.parquet', index=False)")
            run(f"{A}/eval_all3.py", r, "14", "7")
            run(f"{A}/extra.py", r, "14")
            run(f"{A}/fixed_list.py", f"{d}/sens/{v}/inc_day.parquet", r)
        run(f"{A}/halves.py", f"{d}/sens/part1", f"{d}/sens/part2", f"{d}/out")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rows(self, name, ds):
        return [r for r in read_csv(f"{self.d}/out/{name}.csv") if r["dataset"] == ds]

    def test_a_long_capture_is_analysed_in_both_parts(self):
        t = {r["rule"]: r for r in self.rows("halves_table", "full")}
        self.assertEqual(sorted(t), ["GT-C", "fixed 14", "quiet streak"])
        for n in ("1", "2"):
            seq = {r["rule"]: r for r in read_csv(f"{self.d}/sens/part{n}/res/tables/sequential_H14.csv")
                   if r["dataset"] == "full" and float(r["eps"]) == 0.3}
            for rule, r in t.items():
                self.assertEqual(r["status"], "analysed")
                self.assertEqual(int(r[f"days{n}"]), 56)
                self.assertEqual(int(float(r[f"episodes{n}"])), int(float(seq[rule]["episodes"])))
                self.assertAlmostEqual(float(r[f"stopped{n}"]), float(seq[rule]["stopped"]))
        self.assertEqual(float(t["fixed 14"]["stopped1"]), 1.0)
        self.assertEqual(int(float(t["GT-C"]["dev_both"])), 5)

    def test_the_two_by_two_table_covers_every_device(self):
        (r,) = self.rows("halves_devices", "full")
        self.assertEqual(int(r["devices"]), 5)
        self.assertEqual(sum(int(r[k]) for k in ("both", "only_part1", "only_part2", "neither")), 5)

    def test_a_list_that_is_never_updated_alerts_at_least_as_often(self):
        (r,) = self.rows("halves_ageing", "full")
        self.assertGreaterEqual(int(r["devices"]), 1)
        self.assertGreaterEqual(float(r["never_rate_mean"]), float(r["once_rate_mean"]))
        self.assertLessEqual(float(r["never_rate_mean"]), 1.0)

    def test_a_short_second_part_is_not_analysed(self):
        t = self.rows("halves_table", "short2")
        self.assertEqual(len(t), 3)
        for r in t:
            self.assertTrue(r["status"].startswith("part 2 has fewer than 42 days"))
            self.assertEqual((int(r["days1"]), int(r["days2"])), (56, 30))
            self.assertEqual(r["episodes1"] + r["episodes2"] + r["violA1"] + r["violA2"], "")
        self.assertEqual(self.rows("halves_devices", "short2"), [])
        self.assertEqual(self.rows("halves_ageing", "short2"), [])

    def test_a_first_part_without_an_evaluable_episode_is_named(self):
        for r in self.rows("halves_table", "gap1"):
            self.assertEqual(r["status"], "no learning episode can be evaluated in part 1")
            self.assertEqual((int(r["days1"]), int(r["days2"])), (18, 56))
            self.assertEqual(r["episodes1"], "")
            self.assertGreater(int(float(r["episodes2"])), 0)


if __name__ == "__main__":
    unittest.main()
