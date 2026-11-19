import pandas as pd

df = pd.read_csv("ns3_background.csv")

rates = df["rate_bps"]

print("ASペア数:", len(rates))
print("合計レート:", rates.sum(), "bps")
print("最小レート:", rates.min(), "bps")
print("最大レート:", rates.max(), "bps")

for scale in [1, 100, 1000, 10000, 100000, 1000000]:
    scaled = rates * scale

    print(f"\n倍率: {scale}")
    print("1bps未満:", (scaled < 1).sum())
    print("1bps以上:", (scaled >= 1).sum())
    print("合計レート:", scaled.sum(), "bps")