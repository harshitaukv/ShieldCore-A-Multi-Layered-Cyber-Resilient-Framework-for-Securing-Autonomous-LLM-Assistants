import json
from layers.risk_engine import analyze_hybrid
from layers.governance import decide


# ---------------------------
# LOAD TEST DATA
# ---------------------------
with open("data/test.json", "r", encoding="utf-8") as f:
    test_data = json.load(f)


# Use first 50 samples only
test_data = test_data[:50]


# ---------------------------
# METRICS
# ---------------------------
tp = 0
tn = 0
fp = 0
fn = 0


# ---------------------------
# EVALUATE
# ---------------------------
for i, item in enumerate(test_data):

    print(f"Testing {i+1}/50...")

    text = item["full_text"]
    actual = item["label"]   # attack / safe

    result = analyze_hybrid(
        text
    )

    status = decide(
        result["trust_score"]
    )

    # Convert system status to label
    if status == "BLOCKED":
        predicted = "attack"
    else:
        predicted = "safe"

    # Compare
    if actual == "attack" and predicted == "attack":
        tp += 1

    elif actual == "safe" and predicted == "safe":
        tn += 1

    elif actual == "safe" and predicted == "attack":
        fp += 1

    elif actual == "attack" and predicted == "safe":
        fn += 1


# ---------------------------
# CALCULATE METRICS
# ---------------------------
total = tp + tn + fp + fn

accuracy = ((tp + tn) / total) * 100

precision = (
    tp / (tp + fp)
    if (tp + fp) > 0 else 0
) * 100

recall = (
    tp / (tp + fn)
    if (tp + fn) > 0 else 0
) * 100


# ---------------------------
# RESULTS
# ---------------------------
print("\n========== RESULTS ==========")
print(f"Total Samples : {total}")
print(f"True Positive : {tp}")
print(f"True Negative : {tn}")
print(f"False Positive: {fp}")
print(f"False Negative: {fn}")

print("\n========== METRICS ==========")
print(f"Accuracy  : {accuracy:.2f}%")
print(f"Precision : {precision:.2f}%")
print(f"Recall    : {recall:.2f}%")