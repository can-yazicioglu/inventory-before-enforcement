# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
import datetime
import os
import sys
import unittest
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import adapt_recorder as ar  # noqa: E402

TZ = "Europe/Istanbul"
HOURS = ar.parse_hours("1-5=08:00-17:00,6=08:00-13:30")


def at(day, hhmm):
    h, m = hhmm.split(":")
    return int(datetime.datetime(2026, 12, day, int(h), int(m), tzinfo=ZoneInfo(TZ)).timestamp())


def reports(day, start, end, ports=("0", "1"), skip=()):
    """Coverage lines with one report every five minutes on each port, from start to end."""
    lines = []
    t = at(day, start) + 300
    while t <= at(day, end):
        q = {p: {"stats": [[t + 7 * int(p), 50]]} for p in ports if not any(a <= t - 300 < b for a, b in skip)}
        lines.append({"t": t, "q": q})
        t += 300
    return lines


class OutageTests(unittest.TestCase):
    def test_hours(self):
        self.assertEqual(HOURS[1], (480, 1020))
        self.assertEqual(HOURS[6], (480, 810))
        self.assertNotIn(7, HOURS)

    def test_full_day_is_kept(self):          # 14 December 2026 is a Monday
        dropped, down = ar.outage_days(reports(14, "00:00", "23:55"), TZ, HOURS)
        self.assertEqual(dropped, [])
        self.assertLessEqual(max(down.values(), default=0), 14)      # ports report a few seconds apart

    def test_gap_of_fifty_minutes_is_kept_and_seventy_is_dropped(self):
        gap50 = [(at(14, "10:00"), at(14, "10:50"))]
        gap70 = [(at(14, "10:00"), at(14, "11:10"))]
        d50, down50 = ar.outage_days(reports(14, "00:00", "23:55", skip=gap50), TZ, HOURS)
        d70, down70 = ar.outage_days(reports(14, "00:00", "23:55", skip=gap70), TZ, HOURS)
        self.assertEqual(d50, [])
        self.assertEqual(d70, ["2026-12-14"])
        self.assertAlmostEqual(down50["2026-12-14"], 3000, delta=60)
        self.assertAlmostEqual(down70["2026-12-14"], 4200, delta=60)

    def test_gap_outside_working_hours_does_not_count(self):
        night = [(at(14, "18:00"), at(14, "23:00"))]
        self.assertEqual(ar.outage_days(reports(14, "00:00", "23:55", skip=night), TZ, HOURS)[0], [])

    def test_one_dead_port_drops_the_day(self):
        lines = reports(14, "00:00", "23:55", ports=("0",)) + [{"t": at(14, "07:00"), "q": {"1": {"stats": []}}}]
        self.assertEqual(ar.outage_days(lines, TZ, HOURS)[0], ["2026-12-14"])

    def test_reports_without_packets_do_not_count(self):
        lines = reports(14, "00:00", "23:55")
        for line in lines:
            line["q"]["1"]["stats"][0][1] = 0
        self.assertEqual(ar.outage_days(lines, TZ, HOURS)[0], ["2026-12-14"])

    def test_sunday_is_never_dropped(self):
        self.assertEqual(ar.outage_days(reports(13, "00:00", "02:00"), TZ, HOURS), ([], {}))


if __name__ == "__main__":
    unittest.main()
