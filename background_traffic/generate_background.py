
import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

ATTACK_LINKS = "attack_links.csv"
TRAFFIC_DEMAND = "traffic_demand.csv"
LINK_LOAD = "as_link_load.csv"

SELECTED_OUTPUT = "selected_traffic.csv"
RATE_OUTPUT = "ns3_background.csv"
SUMMARY_OUTPUT = "background_summary.json"
VALIDATION_OUTPUT = "link_validation.csv"


def load_attack_links(filename):
    links = set()

    with open(filename, newline="") as f:
        for row in csv.DictReader(f):
            links.add((int(row["src_as"]), int(row["dst_as"])))

    if not links:
        raise ValueError("攻撃リンクがありません")

    return links


def extract():
    attack_links = load_attack_links(ATTACK_LINKS)

    link_counts = defaultdict(int)
    link_demands = defaultdict(float)

    total_demand = 0.0
    selected_demand = 0.0
    total_rows = 0
    positive_rows = 0
    selected_rows = 0

    with open(TRAFFIC_DEMAND, newline="") as fin, \
         open(SELECTED_OUTPUT, "w", newline="") as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(
            fout,
            fieldnames=reader.fieldnames
        )
        writer.writeheader()

        for row in reader:
            total_rows += 1
            demand = float(row["demand"])

            if not math.isfinite(demand) or demand < 0:
                raise ValueError(
                    f"不正な需要値: row={total_rows}, demand={demand}"
                )

            total_demand += demand

            if demand == 0.0:
                continue

            positive_rows += 1

            path = [int(x) for x in row["path"].split()]

            # 攻撃リンクと共有する有向リンクを抽出
            matched_links = set()

            for src, dst in zip(path, path[1:]):
                link = (src, dst)

                if link in attack_links:
                    matched_links.add(link)

            if not matched_links:
                continue

            # ASペアは1回だけ出力
            writer.writerow(row)
            selected_rows += 1
            selected_demand += demand

            # リンク別の検証用集計
            for link in matched_links:
                link_counts[link] += 1
                link_demands[link] += demand

            if total_rows % 10_000_000 == 0:
                print(
                    f"Processed: {total_rows:,}, "
                    f"Selected: {selected_rows:,}",
                    flush=True
                )

    summary = {
        "total_rows": total_rows,
        "positive_rows": positive_rows,
        "selected_rows": selected_rows,
        "total_demand": total_demand,
        "selected_demand": selected_demand,
        "selected_ratio": (
            selected_demand / total_demand
            if total_demand > 0 else 0.0
        )
    }

    with open(SUMMARY_OUTPUT, "w") as f:
        json.dump(summary, f, indent=2)

    validate_links(attack_links, link_counts, link_demands)

    print("\n=== Extraction Summary ===")
    for key, value in summary.items():
        print(f"{key}: {value}")


def validate_links(attack_links, counts, demands):
    reference = {}

    with open(LINK_LOAD, newline="") as f:
        for row in csv.DictReader(f):
            link = (int(row["src_as"]), int(row["dst_as"]))

            if link in attack_links:
                reference[link] = (
                    int(row["flow_count"]),
                    float(row["total_demand"])
                )

    with open(VALIDATION_OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "src_as", "dst_as",
            "expected_count", "actual_count",
            "expected_demand", "actual_demand",
            "count_match", "demand_match"
        ])

        for src, dst in sorted(attack_links):
            link = (src, dst)
            expected_count, expected_demand = reference.get(
                link, (0, 0.0)
            )
            actual_count = counts[link]
            actual_demand = demands[link]

            count_match = expected_count == actual_count
            demand_match = math.isclose(
                expected_demand,
                actual_demand,
                rel_tol=1e-8,
                abs_tol=1e-12
            )

            writer.writerow([
                src, dst,
                expected_count, actual_count,
                expected_demand, actual_demand,
                count_match, demand_match
            ])

            print(
                f"{src}->{dst}: "
                f"count={actual_count}/{expected_count}, "
                f"match={count_match}, "
                f"demand_match={demand_match}"
            )


def generate_rates(b_total_mbps):
    with open(SUMMARY_OUTPUT) as f:
        summary = json.load(f)

    total_demand = summary["total_demand"]

    if total_demand <= 0:
        raise ValueError("全体需要が0です")

    b_total_bps = b_total_mbps * 1_000_000
    generated_total_bps = 0.0
    generated_rows = 0

    with open(SELECTED_OUTPUT, newline="") as fin, \
         open(RATE_OUTPUT, "w", newline="") as fout:

        reader = csv.DictReader(fin)
        writer = csv.writer(fout)

        writer.writerow([
            "src_as", "dst_as",
            "demand", "rate_bps", "path"
        ])

        for row in reader:
            demand = float(row["demand"])
            rate_bps = b_total_bps * demand / total_demand

            writer.writerow([
                row["src_as"],
                row["dst_as"],
                row["demand"],
                format(rate_bps, ".17g"),
                row["path"]
            ])

            generated_total_bps += rate_bps
            generated_rows += 1

    print("\n=== Rate Summary ===")
    print(f"B_total: {b_total_mbps} Mbps")
    print(f"Total demand: {total_demand}")
    print(f"Generated AS pairs: {generated_rows:,}")
    print(f"Generated total rate: {generated_total_bps:.6f} bps")
    print(f"Output: {RATE_OUTPUT}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["extract", "rate", "all"],
        default="all"
    )
    parser.add_argument(
        "--b-total-mbps",
        type=float,
        default=100.0
    )
    args = parser.parse_args()

    if not math.isfinite(args.b_total_mbps) or args.b_total_mbps <= 0:
        parser.error("--b-total-mbps は正の有限値にしてください")

    if args.mode in ("extract", "all"):
        extract()

    if args.mode in ("rate", "all"):
        generate_rates(args.b_total_mbps)


if __name__ == "__main__":
    main()
