from datasets import load_dataset
import json
import re

dataset = load_dataset("microsoft/llmail-inject-challenge")

processed = []

# Combine splits
all_data = list(dataset["Phase1"]) + list(dataset["Phase2"])

# Limit size (adjust later)
all_data = all_data[:3000]


# ---------------------------
# 🧠 Attack Classification
# ---------------------------
def classify_attack(text):
    text = text.lower()

    if "ignore" in text or "override" in text:
        return "Prompt Injection"

    if "send" in text and "@" in text:
        return "Data Exfiltration"

    if "disregard" in text or "do not follow" in text:
        return "Instruction Override"

    if "act as" in text or "you are now" in text:
        return "Role Manipulation"

    if "first" in text and "then" in text:
        return "Multi-step Attack"

    if re.search(r"[A-Za-z0-9+/=]{20,}", text):  # encoded pattern
        return "Obfuscated Injection"

    return "Unknown"


# ---------------------------
# 🔍 Line-level detection
# ---------------------------
def analyze_line(line):
    line_lower = line.lower()
    flags = []
    reason = ""

    if "ignore" in line_lower:
        flags.append("Prompt Injection")
        reason = "Instruction override detected"

    if "send" in line_lower and "@" in line:
        flags.append("Data Exfiltration")
        reason = "External data transfer attempt"

    if "act as" in line_lower:
        flags.append("Role Manipulation")
        reason = "Role escalation attempt"

    if re.search(r"[A-Za-z0-9+/=]{20,}", line):
        flags.append("Obfuscated Injection")
        reason = "Encoded hidden content"

    return flags, reason


# ---------------------------
# 🧪 Process dataset
# ---------------------------
for item in all_data:
    subject = item.get("subject", "")
    body = item.get("body", "")

    # Combine into email format
    text = (subject + "\n" + body).strip()

    lines = text.split("\n")

    flagged_lines = []
    detected_types = set()

    for line in lines:
        flags, reason = analyze_line(line)

        if flags:
            flagged_lines.append({
                "line": line,
                "types": flags,
                "reason": reason
            })
            detected_types.update(flags)

    # Label decision (IMPORTANT)
    if flagged_lines:
        label = "attack"
    else:
        label = "safe"

    # Overall attack type
    attack_type = (
        list(detected_types)[0] if detected_types else "Normal"
    )

    processed.append({
        "full_text": text,
        "lines": lines,
        "label": label,
        "type": attack_type,
        "flagged_lines": flagged_lines
    })


# ---------------------------
# 📊 Train/Test Split
# ---------------------------
split_index = int(0.8 * len(processed))
train = processed[:split_index]
test = processed[split_index:]


# ---------------------------
# 💾 Save
# ---------------------------
with open("data/train.json", "w") as f:
    json.dump(train, f, indent=2)

with open("data/test.json", "w") as f:
    json.dump(test, f, indent=2)


# ---------------------------
# 📢 Stats
# ---------------------------
attack_count = sum(1 for x in train if x["label"] == "attack")

print(f"✅ Dataset ready: {len(train)} train, {len(test)} test")
print(f"⚠️ Attacks in train: {attack_count}")
print(f"🧠 Unique attack types: {set(x['type'] for x in train)}")