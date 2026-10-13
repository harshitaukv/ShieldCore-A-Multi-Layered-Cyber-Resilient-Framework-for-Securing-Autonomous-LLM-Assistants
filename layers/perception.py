import re
import base64
from layers.intent_detector import detect_intent


# ---------------------------
# NORMALIZE TEXT
# ---------------------------
def normalize_text(text):

    # Join spaced words:
    # i g n o r e -> ignore
    text = re.sub(
        r'(\b\w\s)+\w\b',
        lambda m: m.group().replace(" ", ""),
        text
    )

    # Lowercase
    text = text.lower()

    # Remove punctuation noise
    text = re.sub(
        r"[^\w\s+/=%@._-]",
        " ",
        text
    )

    # Normalize spaces
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ---------------------------
# IMPROVED BASE64 DECODER
# ---------------------------
def try_decode_base64(blob):

    try:
        blob = blob.strip()

        # Remove whitespace/newlines
        blob = re.sub(
            r"\s+",
            "",
            blob
        )

        # URL-safe Base64 support
        blob = blob.replace(
            "-",
            "+"
        ).replace(
            "_",
            "/"
        )

        # Fix missing padding
        missing = len(blob) % 4
        if missing:
            blob += "=" * (
                4 - missing
            )

        decoded = base64.b64decode(
            blob,
            validate=False
        ).decode(
            "utf-8",
            errors="ignore"
        )

        decoded = decoded.strip()

        # Only keep meaningful payloads
        if len(decoded) > 8:
            return decoded

    except Exception:
        pass

    return None


# ---------------------------
# EXTRACT + DECODE BASE64
# ---------------------------
def decode_base64_payloads(text):

    decoded_payloads = []

    # Detect Base64-like blocks
    matches = re.findall(
        r"[A-Za-z0-9+/=_-]{20,}",
        text
    )

    for match in matches:

        decoded = try_decode_base64(
            match
        )

        if decoded:
            decoded_payloads.append(
                decoded
            )

    # Append decoded content
    if decoded_payloads:
        text += "\n" + "\n".join(
            decoded_payloads
        )

    return text


# ---------------------------
# RULE DETECTOR
# ---------------------------
def rule_detect(text):

    score = 0
    types = []
    reasons = []

    patterns = {
        "Instruction Override": [
            r"ignore.*instructions",
            r"disregard.*instructions",
            r"override.*rules",
            r"set aside.*guidelines"
        ],

        "Data Exfiltration": [
            r"send.*@",
            r"share.*credentials",
            r"send.*files",
            r"access.*details",
            r"database.*access",
            r"api.*keys",
            r"system.*credentials",
            r"internal.*credentials",
            r"verification.*token"
        ],

        "Role Manipulation": [
            r"you are now",
            r"act as",
            r"assume the role"
        ],

        "Stealth Attack": [
            r"do not tell",
            r"keep secret",
            r"bypass safeguards",
            r"do not inform",
            r"confidential",
            r"do not disclose"
        ],

        "Urgency Manipulation": [
            r"immediately",
            r"urgent",
            r"verify now",
            r"complete immediately",
            r"avoid suspension"
        ]
    }

    for attack_type, regex_list in patterns.items():
        for pattern in regex_list:
            if re.search(
                pattern,
                text
            ):
                score += 2
                types.append(
                    attack_type
                )
                reasons.append(
                    f"{attack_type} detected"
                )
                break

    return score, types, reasons


# ---------------------------
# MAIN PERCEPTION ANALYZER
# ---------------------------
def analyze_email(text):

    # Step 1: normalize
    clean_text = normalize_text(
        text
    )

    # Step 2: decode hidden payloads
    clean_text = decode_base64_payloads(
        clean_text
    )

    # Step 3: normalize again
    clean_text = normalize_text(
        clean_text
    )

    # Step 4: rule detection
    rule_score, rule_types, rule_reasons = rule_detect(
        clean_text
    )

    # Step 5: semantic intent detection
    intent_result = detect_intent(
        clean_text
    )

    malicious = intent_result.get(
        "malicious",
        False
    )

    trust_score = intent_result.get(
        "trust_score",
        10
    )

    # Safe mail should not have low trust
    if not malicious and trust_score < 8:
        trust_score = 8

    # Malicious mail should not have high trust
    if malicious and trust_score > 5:
        trust_score = 5

    # Rules override trust
    if rule_score > 0:
        trust_score = min(
            trust_score,
            3
        )
        malicious = True

    intent_types = intent_result.get(
        "types",
        []
    )

    reason = intent_result.get(
        "reason",
        ""
    )

    # Merge types
    final_types = list(
        set(
            rule_types + intent_types
        )
    )

    allowed_types = [
        "Instruction Override",
        "Data Exfiltration",
        "Obfuscated Injection",
        "Role Manipulation",
        "Authority Abuse",
        "Workflow Manipulation",
        "Stealth Attack",
        "Social Engineering",
        "Urgency Manipulation"
    ]

    final_types = [
        t for t in final_types
        if t in allowed_types
    ]

    # Base64 tagging
    if re.search(
        r"[A-Za-z0-9+/=_-]{20,}",
        text
    ):
        if (
            "Obfuscated Injection"
            not in final_types
        ):
            final_types.append(
                "Obfuscated Injection"
            )

        malicious = True
        trust_score = min(
            trust_score,
            3
        )

    # Fallback type
    if malicious and not final_types:
        final_types = [
            "Suspicious Instruction Pattern"
        ]

    flagged_lines = []

    if malicious:
        flagged_lines.append({
            "line": clean_text,
            "types": final_types,
            "reason": reason or ", ".join(
                rule_reasons
            )
        })

    return {
        "trust_score": trust_score,
        "malicious": malicious,
        "types": final_types,
        "reason": reason,
        "flagged_lines": flagged_lines
    }