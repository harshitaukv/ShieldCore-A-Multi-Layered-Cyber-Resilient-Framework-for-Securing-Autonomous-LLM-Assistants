blocked_actions = [
    "send email",
    "send file",
    "upload file",
    "share credentials",
    "access system files",
    "retrieve secrets"
]

def decide(trust_score):

    if trust_score <= 3:
        return "BLOCKED"

    elif trust_score <= 7:
        return "FLAGGED"

    return "SAFE"


def validate_action(output):

    output = output.lower()

    for action in blocked_actions:
        if action in output:
            return False

    return True
