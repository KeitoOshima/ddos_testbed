
import csv
import heapq

src = "ns3_background.csv"
dst = "ns3_background_test.csv"

TOP_N = 1000
VICTIM_AS = 12975

top = []
victim = None
victim_rate = -1.0
counter = 0

with open(src, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        rate = float(row["rate_bps"])

        if rate < 1.0:
            continue

        # Victim AS宛ての最大レートのフローを記録
        if int(row["dst_as"]) == VICTIM_AS:
            if rate > victim_rate:
                victim = row
                victim_rate = rate

        # 上位1000件を最小ヒープで管理
        item = (rate, counter, row)
        counter += 1

        if len(top) < TOP_N:
            heapq.heappush(top, item)
        elif rate > top[0][0]:
            heapq.heapreplace(top, item)

# ヒープから行を取り出す
top_rows = [item[2] for item in top]

# Victim AS宛てのフローを必ず含める
if victim is not None and all(
    (r["src_as"], r["dst_as"]) !=
    (victim["src_as"], victim["dst_as"])
    for r in top_rows
):
    # 最もレートが小さいフローを置換
    min_index = min(
        range(len(top_rows)),
        key=lambda i: float(top_rows[i]["rate_bps"])
    )
    top_rows[min_index] = victim

# 通信レートの降順
top_rows.sort(
    key=lambda x: float(x["rate_bps"]),
    reverse=True
)

# CSV出力
with open(dst, "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "src_as", "dst_as", "demand", "rate_bps", "path"
        ]
    )
    writer.writeheader()
    writer.writerows(top_rows)

print(f"選択フロー数: {len(top_rows)}")
print(f"Victim AS: {VICTIM_AS}")

total_rate = sum(float(r["rate_bps"]) for r in top_rows)
print(f"合計送信レート: {total_rate / 1e9:.3f} Gbps")

for row in top_rows[:10]:
    print(
        row["src_as"],
        "->",
        row["dst_as"],
        row["rate_bps"],
        "bps"
    )
