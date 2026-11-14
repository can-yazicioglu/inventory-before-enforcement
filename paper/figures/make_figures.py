#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Figures of the public-data results, drawn from the stored result tables.

Usage: make_figures.py [out_dir]
Reads  $IBE_DATA/v3/res_base/tables  (12 homes, UNSW 2016)  and  $IBE_DATA/val/res/tables  (UNSW 2025 v1, v2).
Writes fig_exceedance, fig_certification, fig_calibration as PDF and PNG, and results_tables.md with the
numbers behind every mark.
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

INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"          # validated: colour-blind safe as a set of three
DATASETS = [("homes", "12 homes"), ("unsw", "UNSW 2016"), ("unsw25v1", "UNSW 2025 v1"), ("unsw25v2", "UNSW 2025 v2")]
LEVELS = [("port", "port level"), ("svc", "svc level (primary)"), ("net", "net level")]
RULES = [("GT-C", "GT-C", BLUE, "o"), ("quiet streak", "quiet streak", AQUA, "^"), ("fixed 14", "fixed 14 days", ORANGE, "s")]

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "axes.linewidth": 0.6, "xtick.color": MUTED, "ytick.color": INK, "xtick.major.width": 0.6,
    "ytick.major.width": 0, "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.dpi": 300, "figure.facecolor": "white",
})


def save(fig, name):
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"))
    plt.close(fig)


def exceedance(md):
    seq = pd.concat([pd.read_csv(f"{BASE}/sequential_H14.csv"), pd.read_csv(f"{VAL}/sequential_H14.csv")])
    seq = seq[seq.eps == 0.3]
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 2.5), sharey=True)
    rows = []
    for ax, (lv, lv_name) in zip(axes, LEVELS):
        for i, (ds, ds_name) in enumerate(DATASETS):
            for k, (rule, rule_name, color, marker) in enumerate(RULES):
                r = seq[(seq.dataset == ds) & (seq.gran == lv) & (seq.rule == rule)].iloc[0]
                y = i + (k - 1) * 0.24
                ax.plot([r.violA_lo, r.violA_hi], [y, y], color=color, lw=1.2, solid_capstyle="round", zorder=2)
                ax.plot(r.violA, y, marker=marker, ms=4.5, color=color, mec="white", mew=0.6, zorder=3,
                        label=rule_name if (i == 0 and lv == "port") else None)
                rows.append((ds_name, lv, rule_name, int(r.episodes), r.stopped, r.med_T, r.violA, r.violA_lo, r.violA_hi))
        ax.axvline(0.10, color=MUTED, lw=0.6, ls=(0, (3, 3)), zorder=1)
        ax.set_title(lv_name, fontsize=8, color=INK, loc="left")
        ax.set_xlim(-0.03, 0.85)
        ax.set_xticks([0, 0.1, 0.25, 0.5, 0.75])
        ax.set_xticklabels(["0", "10", "25", "50", "75"])
        ax.grid(axis="x", color=GRID, lw=0.5, zorder=0)
        ax.set_axisbelow(True)
        ax.set_yticks(range(len(DATASETS)))
        ax.set_yticklabels([n for _, n in DATASETS])
        ax.set_ylim(len(DATASETS) - 0.5, -0.5)
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
    colors = {"port": "#86b6ef", "svc": BLUE, "net": "#104281"}     # one hue, light to dark: coarse to fine level
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
    md.append(t[["port", "svc", "net"]].to_markdown(floatfmt=".3f") + "\n")


def calibration(md):
    e = pd.concat([pd.read_csv(f"{BASE}/calibration_explicit.csv"), pd.read_csv(f"{VAL}/calibration_explicit.csv")])
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 2.3), sharey=True)
    rows = []
    for ax, (lv, lv_name) in zip(axes, LEVELS):
        for i, (ds, ds_name) in enumerate(DATASETS):
            r = e[(e.dataset == ds) & (e.gran == lv)]
            if r.empty:
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
        ax.set_title(lv_name, fontsize=8, color=INK, loc="left")
        ax.set_xlim(0, 2.2)
        ax.grid(axis="x", color=GRID, lw=0.5)
        ax.set_axisbelow(True)
        ax.set_yticks(range(len(DATASETS)))
        ax.set_yticklabels([n for _, n in DATASETS])
        ax.set_ylim(len(DATASETS) - 0.5, -0.5)
    axes[1].set_xlabel("realised new flow types / predicted, median over devices (1 = calibrated, above 1 = underestimate)")
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.08),
               handletextpad=0.3, columnspacing=1.6)
    save(fig, "fig_calibration")
    t = pd.DataFrame(rows, columns=["data", "level", "devices", "devices with a prediction", "median ratio", "low", "high",
                                    "median ratio corrected", "pooled ratio", "pooled low", "pooled high"])
    md.append("## Figure: calibration (first learning episode, T at least 7, no smoothing)\n")
    md.append(t.to_markdown(index=False, floatfmt=".3f") + "\n")


def main():
    md = ["# Numbers behind the figures\n",
          "Generated by `make_figures.py` from the stored result tables. Do not edit by hand.\n"]
    exceedance(md)
    certification(md)
    calibration(md)
    with open(os.path.join(OUT, "results_tables.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print("written to", OUT)


if __name__ == "__main__":
    main()
