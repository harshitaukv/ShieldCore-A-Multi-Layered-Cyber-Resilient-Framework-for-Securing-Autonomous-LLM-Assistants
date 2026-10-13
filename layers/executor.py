import ollama


# Reusable remote Ollama client
client = ollama.Client(
    host="https://39c7-162-216-141-56.ngrok-free.app"
)


def execute(task, content):

    if task == "summarize":

        prompt = f"""
Summarize this email into 3 short bullet points.

Include:
- sender (if identifiable)
- main purpose of the email
- important action or next step

Email:
{content}
"""

        response = client.chat(
            model="qwen2.5:3b",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return response["message"]["content"]

    elif task == "reply":

        prompt = f"""
Write a professional reply for this email.

Email:
{content}
"""

        response = client.chat(
            model="qwen2.5:3b",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return response["message"]["content"]

    return "Unsupported task"