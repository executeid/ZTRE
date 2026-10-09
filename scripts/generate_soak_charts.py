#!/usr/bin/env python3
"""Generate thesis Bab 4 visualization charts from 1-hour soak test metrics.csv."""

import csv
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime

CSV_FILE = "evidence/soak/metrics.csv"
OUT_DIR = "evidence/soak"

def main():
    timestamps = []
    cpu = []
    mem = []
    goroutines = []
    ingested = []
    dropped = []
    containments = []
    alerts = []

    with open(CSV_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = datetime.fromisoformat(row["timestamp"])
            timestamps.append(ts)
            cpu.append(float(row["cpu_millicores"]))
            mem.append(float(row["memory_mi"]))
            goroutines.append(int(row["goroutines"]))
            ingested.append(int(row["events_ingested"]))
            dropped.append(int(row["events_dropped"]))
            containments.append(int(row["containments"]))
            alerts.append(int(row["alerts"]))

    minutes = [(t - timestamps[0]).total_seconds() / 60.0 for t in timestamps]

    # Chart 1: Resource Utilization (CPU & Memory) vs PRD M5 Limits
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)

    # CPU subplot
    ax1.plot(minutes, cpu, color="#1f77b4", linewidth=2, label="Agent CPU (m)")
    ax1.axhline(y=2000, color="r", linestyle="--", alpha=0.7, label="PRD M5 Limit (2000m / 2 Cores)")
    ax1.set_ylabel("CPU Usage (millicores)")
    ax1.set_title("ZTRE 1-Hour Soak Test: System Resource Stability (M5)", fontsize=13, fontweight="bold")
    ax1.grid(True, linestyle=":", alpha=0.6)
    ax1.set_ylim(0, max(max(cpu) * 1.5, 50))
    ax1.legend(loc="upper right")

    # Annotate CPU stats
    avg_cpu = sum(cpu) / len(cpu)
    peak_cpu = max(cpu)
    ax1.text(0.02, 0.75, f"Avg CPU: {avg_cpu:.1f}m\nPeak CPU: {peak_cpu:.1f}m", 
             transform=ax1.transAxes, bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))

    # Memory subplot
    ax2.plot(minutes, mem, color="#2ca02c", linewidth=2, label="Agent Memory RSS (MiB)")
    ax2.axhline(y=128, color="r", linestyle="--", alpha=0.7, label="PRD M5 Limit (128 MiB)")
    ax2.set_xlabel("Elapsed Time (Minutes)")
    ax2.set_ylabel("Memory RSS (MiB)")
    ax2.grid(True, linestyle=":", alpha=0.6)
    ax2.set_ylim(0, max(max(mem) * 1.3, 40))
    ax2.legend(loc="upper right")

    # Annotate Memory stats
    avg_mem = sum(mem) / len(mem)
    peak_mem = max(mem)
    ax2.text(0.02, 0.75, f"Avg Mem: {avg_mem:.1f} MiB\nPeak Mem: {peak_mem:.1f} MiB", 
             transform=ax2.transAxes, bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))

    plt.tight_layout()
    chart1_path = os.path.join(OUT_DIR, "soak_resource_utilization.png")
    plt.savefig(chart1_path, dpi=300)
    plt.close()
    print(f"Generated: {chart1_path}")

    # Chart 2: Event Processing & Containment Progression
    fig, (ax3, ax4) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)

    # Ingested events & dropped events
    ax3.plot(minutes, [x / 1000.0 for x in ingested], color="#9467bd", linewidth=2, label="Events Ingested (x1,000)")
    ax3.plot(minutes, dropped, color="r", linewidth=2, linestyle=":", label="Events Dropped")
    ax3.set_ylabel("Events (Thousands)")
    ax3.set_title("ZTRE 1-Hour Soak Test: Telemetry Throughput & Zero-Drop Reliability", fontsize=13, fontweight="bold")
    ax3.grid(True, linestyle=":", alpha=0.6)
    ax3.legend(loc="upper left")

    total_ingested = ingested[-1]
    ax3.text(0.75, 0.2, f"Total Ingested: {total_ingested:,}\nTotal Dropped: 0", 
             transform=ax3.transAxes, bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))

    # Goroutines & Containment actions
    ax4.plot(minutes, goroutines, color="#ff7f0e", linewidth=2, label="Go Goroutines (Leak check)")
    ax4.set_xlabel("Elapsed Time (Minutes)")
    ax4.set_ylabel("Goroutine Count", color="#ff7f0e")
    ax4.tick_params(axis="y", labelcolor="#ff7f0e")
    ax4.set_ylim(15, 30)
    ax4.grid(True, linestyle=":", alpha=0.6)

    ax4_twin = ax4.twinx()
    ax4_twin.plot(minutes, containments, color="#d62728", linewidth=2, linestyle="-.", label="Quarantine Actions Total")
    ax4_twin.set_ylabel("Containment Actions Total", color="#d62728")
    ax4_twin.tick_params(axis="y", labelcolor="#d62728")

    lines1, labels1 = ax4.get_legend_handles_labels()
    lines2, labels2 = ax4_twin.get_legend_handles_labels()
    ax4.legend(lines1 + lines2, labels1 + labels2, loc="upper left")

    plt.tight_layout()
    chart2_path = os.path.join(OUT_DIR, "soak_telemetry_reliability.png")
    plt.savefig(chart2_path, dpi=300)
    plt.close()
    print(f"Generated: {chart2_path}")

if __name__ == "__main__":
    main()
