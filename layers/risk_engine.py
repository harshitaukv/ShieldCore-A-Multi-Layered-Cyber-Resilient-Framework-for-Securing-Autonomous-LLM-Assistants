from layers.perception import analyze_email


def analyze_hybrid(email_text):

    result = analyze_email(
        email_text
    )

    return {
        "trust_score": result["trust_score"],
        "malicious": result["malicious"],
        "types": result["types"],
        "flagged_lines": result["flagged_lines"],
        "reason": result["reason"]
    }