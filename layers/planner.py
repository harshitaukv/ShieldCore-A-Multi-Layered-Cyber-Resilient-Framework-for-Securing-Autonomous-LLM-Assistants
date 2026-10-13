def plan(command):

    allowed = [
        "summarize",
        "simplify",
        "reply",
        "action items"
    ]

    command = command.lower().strip()

    if command in allowed:
        return {
            "allowed": True,
            "task": command
        }

    return {
        "allowed": False,
        "task": None
    }