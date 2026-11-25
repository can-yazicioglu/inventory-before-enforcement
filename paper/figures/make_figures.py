#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Figures of the public-data results, drawn from the stored result tables.

Usage: make_figures.py [out_dir]
Reads the stored tables under $IBE_DATA: v3/res_base (12 homes, UNSW 2016), val/res (UNSW 2025 v1, v2), servtrace/res
(IoT-ServTrace, port level only), deakin/res (Deakin D-IoT, if that trace was prepared) and out (tables over several traces).
Writes eight figures as PDF and PNG, and results_tables.md with the numbers behind every mark:
  fig_exceedance      exceedance after enforcement, three rules
  fig_certification   share of devices certified by day T
  fig_calibration     realised over predicted new flow types
  fig_discrimination  fixed 14 days on the episodes that GT-C enforced and on those it did not
  fig_risk_coverage   exceedance against the share of episodes enforced, for every threshold of the rules
  fig_alertday        the alert-day estimate D(T)/T and the order-statistic bound
  fig_fleet           one list for all homes that run the same device model
  fig_capture_length  how long a capture must be before the primary metric can be evaluated
"""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

DATA = os.environ.get("IBE_DATA", "data")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
BASE, VAL = f"{DATA}/v3/res_base/tables", f"{DATA}/val/res/tables"
SERV, DEAK, MULTI = f"{DATA}/servtrace/res", f"{DATA}/deakin/res", f"{DATA}/out"
HAVE_DEAKIN = os.path.exists(f"{DEAK}/tables/sequential_H14.csv")

INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"          # validated: colour-blind safe as a set of three
LIGHT, DARK = "#86b6ef", "#104281"                            # with BLUE: one hue, light to dark (validated as an ordinal ramp)
DATASETS = [("homes", "12 homes"), ("unsw", "UNSW 2016"), ("unsw25v1", "UNSW 2025 v1"), ("unsw25v2", "UNSW 2025 v2")] \
    + ([("deakin", "Deakin D-IoT")] if HAVE_DEAKIN else [])
PORT_ONLY = [("servtrace19", "ServTrace 2019"), ("servtrace22", "ServTrace 2022")]   # traces without peers: port level only
ALL_SETS = DATASETS + PORT_ONLY
LEVELS = [("port", "port level"), ("svc", "svc level (primary)"), ("net", "net level")]
RULES = [("GT-C", "GT-C", BLUE, "o"), ("quiet streak", "quiet streak", AQUA, "^"), ("fixed 14", "fixed 14 days", ORANGE, "s")]
LEVEL_STYLE = {"port": (LIGHT, "o"), "svc": (BLUE, "^"), "net": (DARK, "s"), "host": (DARK, "s")}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "axes.linewidth": 0.6, "xtick.color": MUTED, "ytick.color": INK, "xtick.major.width": 0.6,
    "ytick.major.width": 0, "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.dpi": 300, "figure.facecolor": "white",
})


def save(fig, name):
    fig.savefig(os.path.join(OUT, f"{name}.pdf"), metadata={"CreationDate": None, "ModDate": None})
    fig.savefig(os.path.join(OUT, f"{name}.png"))
    plt.close(fig)


def table(name, multi=False):
    """One stored table over all traces. multi: tables that a script writes once for several traces."""
    if multi:
        paths = [f"{MULTI}/{name}", f"{SERV}/{name}", f"{DEAK}/{name}"]
    else:
        paths = [f"{BASE}/{name}", f"{VAL}/{name}", f"{SERV}/tables/{name}", f"{DEAK}/tables/{name}"]
    return pd.concat([pd.read_csv(p) for p in paths if os.path.exists(p)], ignore_index=True)


def rows_axis(ax, names, title, grid_axis="x"):
    ax.set_title(title, fontsize=8, color=INK, loc="left")
    ax.grid(axis=grid_axis, color=GRID, lw=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names)
    ax.set_ylim(len(names) - 0.5, -0.5)


def exceedance(md):
    seq = table("sequential_H14.csv")
    seq = seq[seq.eps == 0.3]
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 0.5 + 0.42 * len(ALL_SETS)), sharey=True)
    rows = []
    for ax, (lv, lv_name) in zip(axes, LEVELS):
        for i, (ds, ds_name) in enumerate(ALL_SETS):
            for k, (rule, rule_name, color, marker) in enumerate(RULES):
                r = seq[(seq.dataset == ds) & (seq.gran == lv) & (seq.rule == rule)]
                if r.empty:
                    continue
                r = r.iloc[0]
                y = i + (k - 1) * 0.24
                ax.plot([r.violA_lo, r.violA_hi], [y, y], color=color, lw=1.2, solid_capstyle="round", zorder=2)
                ax.plot(r.violA, y, marker=marker, ms=4.5, color=color, mec="white", mew=0.6, zorder=3,
                        label=rule_name if (i == 0 and lv == "port") else None)
                rows.append((ds_name, lv, rule_name, int(r.episodes), r.stopped, r.med_T, r.violA, r.violA_lo, r.violA_hi))
            if lv != "port" and (ds, ds_name) in PORT_ONLY:
                ax.text(0.02, i, "port level only", color=MUTED, fontsize=6.5, va="center")
        ax.axvline(0.10, color=MUTED, lw=0.6, ls=(0, (3, 3)), zorder=1)
        ax.set_xlim(-0.03, 0.85)
        ax.set_xticks([0, 0.1, 0.25, 0.5, 0.75])
        ax.set_xticklabels(["0", "10", "25", "50", "75"])
        rows_axis(ax, [n for _, n in ALL_SETS], lv_name)
    axes[1].set_xlabel("learning episodes whose alert-day rate exceeded the target in the next 14 active days (percent)")
    axes[0].text(0.115, -0.47, "10 percent", color=MUTED, fontsize=6.5, va="top")
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.08),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_exceedance")
    t = pd.DataFrame(rows, columns=["data", "level", "rule", "episodes", "enforced share", "median day",
                                    "exceedance", "low", "high"])
    md.append("## Figure: exceedance after enforcement (target 0.3 new flow types per day, next 14 active days)\n")
    md.append("Exceedance: share of enforced learning episodes whose alert-day rate was above the target. "
              "Interval: 95 percent cluster bootstrap over devices.\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f") + "\n")


def certification(md):
    c = pd.read_csv(f"{BASE}/cert_curves.csv")
    c = c[c.eps == 0.3]
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.3), sharey=True)
    colors = {"port": LIGHT, "svc": BLUE, "net": DARK}             # one hue, light to dark: coarse to fine level
    for ax, (ds, ds_name) in zip(axes, DATASETS[:2]):
        for lv, lv_name in LEVELS:
            d = c[(c.dataset == ds) & (c.gran == lv)].sort_values("T")
            ax.step(d["T"], d.certified, where="post", color=colors[lv], lw=1.6)
            ax.plot(d["T"], d.certified, ls="none", marker="o", ms=3, color=colors[lv], mec="white", mew=0.5)
            last = d.iloc[-1]
            ax.annotate(lv, (last["T"], last.certified), xytext=(5, 0), textcoords="offset points",
                        va="center", fontsize=7.5, color=INK)
        ax.set_title(ds_name, fontsize=8, color=INK, loc="left")
        ax.set_xlabel("observation length T (active days)")
        ax.grid(axis="y", color=GRID, lw=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(0, 1)
        ax.set_yticks([0, 0.25, 0.5, 0.75, 1])
        ax.set_yticklabels(["0", "25", "50", "75", "100"])
        ax.tick_params(axis="y", colors=MUTED)
        ax.set_xlim(5, max(c[c.dataset == ds]["T"]) * 1.12)
    axes[0].set_ylabel("devices certified by GT-C (percent)")
    save(fig, "fig_certification")
    t = c[c.gran.isin([lv for lv, _ in LEVELS])].pivot_table(index=["dataset", "T"], columns="gran", values="certified")
    md.append("## Figure: share of devices certified by day T (Kaplan-Meier, target 0.3)\n")
    t = t[["port", "svc", "net"]].reset_index().rename(columns={"dataset": "data", "T": "day T"})
    t["data"] = t["data"].map(dict(DATASETS))
    md.append("Empty cell: too few devices are still under observation on that day.\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f", missingval="") + "\n")


def calibration(md):
    e = table("calibration_explicit.csv")
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 0.5 + 0.42 * len(ALL_SETS)), sharey=True)
    rows = []
    for ax, (lv, lv_name) in zip(axes, LEVELS):
        for i, (ds, ds_name) in enumerate(ALL_SETS):
            r = e[(e.dataset == ds) & (e.gran == lv)]
            if r.empty:
                if lv != "port" and (ds, ds_name) in PORT_ONLY:
                    ax.text(0.04, i, "port level only", color=MUTED, fontsize=6.5, va="center")
                continue
            r = r.iloc[0]
            ax.plot([r.dev_med_lo, r.dev_med_hi], [i - 0.12, i - 0.12], color=BLUE, lw=1.2, solid_capstyle="round")
            ax.plot(r.dev_median, i - 0.12, marker="o", ms=4.5, color=BLUE, mec="white", mew=0.6,
                    label="Good-Turing estimate" if (i == 0 and lv == "port") else None)
            ax.plot(r.dev_median_corrected, i + 0.12, marker="D", ms=4, color=ORANGE, mec="white", mew=0.6, ls="none",
                    label="with drift correction" if (i == 0 and lv == "port") else None)
            rows.append((ds_name, lv, int(r.devices), int(r.dev_with_pred), r.dev_median, r.dev_med_lo, r.dev_med_hi,
                         r.dev_median_corrected, r.pooled, r.pooled_lo, r.pooled_hi))
        ax.axvline(1.0, color=MUTED, lw=0.6, ls=(0, (3, 3)))
        ax.set_xlim(0, 2.2)
        rows_axis(ax, [n for _, n in ALL_SETS], lv_name)
    axes[1].set_xlabel("realised new flow types / predicted, median over devices (1 = calibrated, above 1 = underestimate)")
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.08),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_calibration")
    t = pd.DataFrame(rows, columns=["data", "level", "devices", "devices with a prediction", "median ratio", "low", "high",
                                    "median ratio corrected", "pooled ratio", "pooled low", "pooled high"])
    md.append("## Figure: calibration (first learning episode, T at least 7, no smoothing)\n")
    md.append("Ratio: realised new flow types over predicted. Median ratio: over the devices with a prediction above zero, with a "
              "95 percent bootstrap interval. Pooled ratio: all devices together. In UNSW 2025 v1 one device shows 22,797 flow "
              "types at the svc level and decides the pooled ratio alone, so the pooled ratio of that archive is not interpretable.\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f") + "\n")


def discrimination(md):
    p = table("paired_gtc_fixed14.csv")
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 0.5 + 0.42 * len(ALL_SETS)), sharey=True)
    rows = []
    for ax, (lv, lv_name) in zip(axes, LEVELS):
        for i, (ds, ds_name) in enumerate(ALL_SETS):
            r = p[(p.dataset == ds) & (p.gran == lv)]
            if r.empty:
                if lv != "port" and (ds, ds_name) in PORT_ONLY:
                    ax.text(0.02, i, "port level only", color=MUTED, fontsize=6.5, va="center")
                continue
            r = r.iloc[0]
            a, b = r.fixed14_viol_where_gtc_certified, r.fixed14_viol_where_gtc_refused
            if pd.notna(a) and pd.notna(b):
                ax.plot([a, b], [i, i], color=GRID, lw=1.6, solid_capstyle="round", zorder=1)
            if pd.notna(a):
                ax.plot(a, i, marker="o", ms=5, color=BLUE, mec="white", mew=0.6, zorder=3,
                        label="episodes that GT-C enforced" if (i == 0 and lv == "port") else None)
            if pd.notna(b):
                ax.plot(b, i, marker="s", ms=5, color=ORANGE, mec="white", mew=0.6, zorder=3,
                        label="episodes that GT-C did not enforce" if (i == 0 and lv == "port") else None)
                ax.annotate(f"n={int(r.n_refused)}", (b, i), xytext=(0, -7), textcoords="offset points", ha="center", va="top",
                            fontsize=6, color=MUTED)
            rows.append((ds_name, lv, int(r.episodes), int(r.both), a, int(r.n_refused), b, r.fixed14_violA_where_gtc_refused))
        ax.set_xlim(-0.04, 1.04)
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1])
        ax.set_xticklabels(["0", "25", "50", "75", "100"])
        rows_axis(ax, [n for _, n in ALL_SETS], lv_name)
    axes[1].set_xlabel("episodes in which enforcing on day 14 exceeded the target in the next 14 active days (percent)")
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.08),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_discrimination")
    t = pd.DataFrame(rows, columns=["data", "level", "episodes", "enforced by both", "fixed 14 exceeds, GT-C enforced",
                                    "not enforced by GT-C (n)", "fixed 14 exceeds, GT-C did not enforce",
                                    "the same with the alert-day rate"])
    md.append("## Figure: fixed 14 days, judged apart on the episodes that GT-C enforced and on those it did not (target 0.3)\n")
    md.append("Every episode with 14 further active days is enforced on day 14. Exceedance here is that of the rate of new flow "
              "types. The last column gives the alert-day rate for the episodes that GT-C did not enforce. n: episodes that GT-C "
              "did not enforce. A cell with few such episodes carries little information.\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f", missingval="") + "\n")


def risk_coverage(md):
    rc = table("risk_coverage_H14.csv")
    rc = rc[(rc.target == 0.3) & rc.gran.isin(["svc", "net"])]
    sets = [(ds, n) for ds, n in DATASETS if ((rc.dataset == ds)).any()]
    fig, axes = plt.subplots(2, len(sets), figsize=(7.1, 3.5), sharex=True, sharey="row", squeeze=False)
    style = {"GT-C": (BLUE, "o", "GT-C"), "quiet streak": (AQUA, "^", "quiet streak"), "fixed": (ORANGE, "s", "fixed window")}
    nominal = {"GT-C": 0.3, "quiet streak": 0.3, "fixed": 14}
    rows = []
    for a, lv in enumerate(("svc", "net")):
        for b, (ds, ds_name) in enumerate(sets):
            ax = axes[a][b]
            for rule, (color, marker, label) in style.items():
                d = rc[(rc.dataset == ds) & (rc.gran == lv) & (rc.rule == rule)].sort_values("certified")
                d = d[d.violA.notna()]
                ax.plot(d.certified, d.violA, color=color, lw=1.1, marker=marker, ms=2.4, mec=color, zorder=2,
                        label=label if (a == 0 and b == 0) else None)
                n = d[d.theta == nominal[rule]]
                if len(n):
                    ax.plot(n.certified, n.violA, ls="none", marker=marker, ms=6.5, color=color, mec="white", mew=0.9, zorder=4)
                for r in d.itertuples():
                    rows.append((ds_name, lv, label, r.theta, r.certified, r.med_T, r.violA, r.viol))
            ax.grid(color=GRID, lw=0.5, zorder=0)
            ax.set_axisbelow(True)
            ax.set_xlim(-0.03, 1.03)
            ax.set_ylim(-0.03, 1.0 if lv == "net" else 0.5)
            ax.set_xticks([0, 0.5, 1])
            ax.set_xticklabels(["0", "50", "100"])
            ax.tick_params(axis="y", colors=MUTED)
            if a == 0:
                ax.set_title(ds_name, fontsize=8, color=INK, loc="left")
        axes[a][0].set_ylabel(f"{lv} level\nexceedance (percent)")
        axes[a][0].set_yticks([0, 0.25, 0.5] if lv == "svc" else [0, 0.25, 0.5, 0.75, 1])
        axes[a][0].set_yticklabels(["0", "25", "50"] if lv == "svc" else ["0", "25", "50", "75", "100"])
    fig.supxlabel("learning episodes enforced (percent)", fontsize=8, y=0.02)
    fig.legend(*axes[0][0].get_legend_handles_labels(), loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.04),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_risk_coverage")
    t = pd.DataFrame(rows, columns=["data", "level", "rule", "threshold", "enforced share", "median day", "exceedance", "the same for the type rate"])
    md.append("## Figure: exceedance against the share of episodes enforced (target 0.3, next 14 active days)\n")
    md.append("Every rule is run with a range of thresholds and judged against the one target 0.3. Threshold: for GT-C the bound "
              "that must not be exceeded, for the quiet streak 3 divided by the number of quiet days, for the fixed window the day. "
              "Exceedance: share of the enforced episodes whose alert-day rate was above the target. Large marks in the figure: the "
              "rules as the paper uses them (threshold 0.3, and day 14).\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f", missingval="") + "\n")


def alertday(md):
    a = table("alertday.csv")
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 0.6 + 0.42 * len(ALL_SETS)), sharey=True)
    rows = []
    for i, (ds, ds_name) in enumerate(ALL_SETS):
        for k, (lv, lv_name) in enumerate(LEVELS):
            r = a[(a.dataset == ds) & (a.gran == lv)]
            if r.empty:
                continue
            r = r.iloc[0]
            color, marker = LEVEL_STYLE[lv]
            y = i + (k - 1) * 0.24
            axes[0].plot([r.ra_lo, r.ra_hi], [y, y], color=color, lw=1.2, solid_capstyle="round", zorder=2)
            axes[0].plot(r.ratio_alert, y, marker=marker, ms=4.5, color=color, mec="white", mew=0.6, zorder=3,
                         label=lv_name if i == 0 else None)
            axes[1].plot(r.conf90_cover, y, marker=marker, ms=4.5, color=color, mec="white", mew=0.6, zorder=3)
            rows.append((ds_name, lv, int(r.devices), int(r.rows), r.alert_rate, r.pred_alert, r.ratio_alert, r.ra_lo, r.ra_hi,
                         r.conf90_cover, int(r.conf90_rows)))
    axes[0].axvline(1.0, color=MUTED, lw=0.6, ls=(0, (3, 3)), zorder=1)
    axes[1].axvline(0.90, color=MUTED, lw=0.6, ls=(0, (3, 3)), zorder=1)
    axes[0].set_xlim(0.4, 1.6)
    axes[1].set_xlim(0.84, 1.0)
    axes[1].set_xticks([0.85, 0.90, 0.95, 1.0])
    axes[1].set_xticklabels(["85", "90", "95", "100"])
    rows_axis(axes[0], [n for _, n in ALL_SETS], "alert days: realised / predicted by D(T)/T")
    rows_axis(axes[1], [n for _, n in ALL_SETS], "days within the 90 percent bound (percent)")
    axes[0].set_xlabel("1 = calibrated, above 1 = more alert days than predicted")
    axes[1].set_xlabel("nominal level: 90 percent")
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.07),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_alertday")
    t = pd.DataFrame(rows, columns=["data", "level", "devices", "device-days", "alert-day rate", "predicted", "ratio", "low", "high",
                                    "within the 90 percent bound", "days with a bound"])
    md.append("## Figure: the alert-day estimate and the order-statistic bound (first learning episode, T at least 7)\n")
    md.append("Alert-day rate: share of days on which the device showed a flow type it had never shown before. Predicted: mean of "
              "D(T)/T, where D(T) is the number of the first T days that carry a flow type seen on no other of those days. Ratio: "
              "realised alert days over predicted, with a 95 percent cluster bootstrap interval over devices. Within the bound: "
              "share of days whose number of new flow types did not exceed the 90 percent order-statistic bound (defined from "
              "T = 9 on).\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f") + "\n")


def fleet(md):
    c = pd.read_csv(f"{BASE}/fleet_coverage.csv")
    v = pd.read_csv(f"{BASE}/fleet_vs_solo.csv")
    order = ["port", "net", "host"]
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.4), gridspec_kw={"width_ratios": [1.25, 1]})
    ax = axes[0]
    ks = [1, 2, 3, 5, 8, 11]
    for lv in order:
        color, marker = LEVEL_STYLE[lv] if lv != "net" else (BLUE, "^")
        d = c[(c.gran == lv) & c.k.isin(ks)].sort_values("k")
        ax.plot(d.k, d.type_cov_mean, color=color, lw=1.6, marker=marker, ms=4.5, mec="white", mew=0.6)
        last = d.iloc[-1]
        ax.annotate(lv, (last.k, last.type_cov_mean), xytext=(6, 0), textcoords="offset points", va="center", fontsize=7.5, color=INK)
    ax.set_xticks(ks)
    ax.set_xticklabels(["1", "2", "3", "5", "8", "11"])
    ax.set_xlim(0.5, 12.6)
    ax.set_ylim(0.4, 1.0)
    ax.set_yticks([0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["40", "60", "80", "100"])
    ax.tick_params(axis="y", colors=MUTED)
    ax.grid(axis="y", color=GRID, lw=0.5)
    ax.set_axisbelow(True)
    ax.set_title("flow types of a further home already on the list (percent)", fontsize=8, color=INK, loc="left")
    ax.set_xlabel("homes whose observations are pooled into one list")
    ax = axes[1]
    for i, lv in enumerate(order):
        r = v[v.gran == lv].iloc[0]
        ax.plot([r.fleet, r.solo], [i, i], color=GRID, lw=1.6, solid_capstyle="round", zorder=1)
        ax.plot(r.solo, i, marker="s", ms=5, color=ORANGE, mec="white", mew=0.6, zorder=3, label="each home alone" if i == 0 else None)
        ax.plot(r.fleet, i, marker="o", ms=5, color=BLUE, mec="white", mew=0.6, zorder=3, label="one list for all homes" if i == 0 else None)
        ax.annotate(f"{r.reduction:.1f} times fewer", (r.fleet, i), xytext=(0, 7), textcoords="offset points", ha="left", va="bottom",
                    fontsize=6.5, color=MUTED)
    ax.set_xscale("log")
    ax.set_xlim(0.01, 40)
    ax.set_xticks([0.01, 0.1, 1, 10])
    ax.set_xticklabels(["0.01", "0.1", "1", "10"])
    rows_axis(ax, order, "new flow types per device and day")
    ax.legend(loc="lower right", fontsize=7, handletextpad=0.3)
    fig.subplots_adjust(wspace=0.32)
    save(fig, "fig_fleet")
    md.append("## Figure: one list for all homes that run the same device model (12 homes)\n")
    md.append("Left: a list is built from k homes and judged on a further home that runs the same device model (device models "
              "present in at least 8 homes, LAN peers reduced to one class so that rules carry over between homes). Right: new "
              "flow types per device and day after the learning period, with a list per home and with one list for all homes.\n")
    t = c.rename(columns={"gran": "level", "k": "homes pooled", "type_cov_mean": "flow types covered (mean)",
                          "type_cov_med": "flow types covered (median)", "rec_cov_med": "flow records covered (median)",
                          "rec_cov_p10": "flow records covered (10th percentile)"})
    md.append(t[["level", "homes pooled", "flow types covered (mean)", "flow types covered (median)", "flow records covered (median)",
                 "flow records covered (10th percentile)"]].to_markdown(index=False, floatfmt=".3f") + "\n")
    t = v.rename(columns={"gran": "level", "device_homes": "devices", "solo": "each home alone", "fleet": "one list for all homes",
                          "solo_alert": "alert-day rate, alone", "fleet_alert": "alert-day rate, one list", "reduction": "times fewer"})
    md.append(t.to_markdown(index=False, floatfmt=".3f") + "\n")


def capture_length(md):
    c = table("capture_length.csv", multi=True)
    sets = [(ds, n) for ds, n in DATASETS if ((c.dataset == ds) & (c.gran == "svc")).any()]
    fig, axes = plt.subplots(1, len(sets), figsize=(7.1, 1.9), sharey=True, squeeze=False)
    for ax, (ds, ds_name) in zip(axes[0], sets):
        d = c[(c.dataset == ds) & (c.gran == "svc")].sort_values("units")
        ax.plot(d.units, d.evaluable_H7, color=LIGHT, lw=1.6, marker="^", ms=4.5, mec="white", mew=0.6,
                label="7 further active days" if ds == sets[0][0] else None)
        ax.plot(d.units, d.evaluable_H14, color=DARK, lw=1.6, marker="o", ms=4.5, mec="white", mew=0.6,
                label="14 further active days (primary)" if ds == sets[0][0] else None)
        ax.set_title(ds_name, fontsize=8, color=INK, loc="left")
        ax.set_xticks([20, 28, 35, 42])
        ax.set_xlim(18, 44)
        ax.set_ylim(-0.03, 1.0)
        ax.set_yticks([0, 0.25, 0.5, 0.75, 1])
        ax.set_yticklabels(["0", "25", "50", "75", "100"])
        ax.tick_params(axis="y", colors=MUTED)
        ax.grid(axis="y", color=GRID, lw=0.5)
        ax.set_axisbelow(True)
    axes[0][0].set_ylabel("devices that can be\nevaluated (percent)")
    fig.supxlabel("length of the capture (active days of the device)", fontsize=8, y=-0.06)
    fig.legend(*axes[0][0].get_legend_handles_labels(), loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.13),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_capture_length")
    md.append("## Figure: how long a capture must be before the primary metric can be evaluated (svc level in the figure, target 0.3)\n")
    md.append("The first learning episode of every device is cut to its first active days. A device can be evaluated if GT-C "
              "enforces early enough to leave 14 (or 7) further active days inside the cut capture. Devices: those whose trace is "
              "at least as long as the cut.\n")
    t = c[c.gran.isin(["port", "svc", "net"])].copy()
    t["dataset"] = t.dataset.map(dict(ALL_SETS)).fillna(t.dataset)
    t = t.rename(columns={"dataset": "data", "gran": "level", "units": "active days", "certified_by_end": "enforced by the end",
                          "evaluable_H14": "evaluable, 14 days", "evaluable_H7": "evaluable, 7 days"})
    md.append(t.to_markdown(index=False, floatfmt=".3f") + "\n")


def main():
    md = ["# Numbers behind the figures\n",
          "Generated by `make_figures.py` from the stored result tables. Do not edit by hand.\n"]
    for f in (exceedance, certification, calibration, discrimination, risk_coverage, alertday, fleet, capture_length):
        f(md)
    with open(os.path.join(OUT, "results_tables.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print("written to", OUT)


if __name__ == "__main__":
    main()
