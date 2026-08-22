# Deliberately vulnerable fixture for KAVACH self-test. DO NOT DEPLOY.
import subprocess

from flask import Flask, request
from openai import OpenAI

# VULN: hardcoded keys committed to source
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-proj-abc123ABC456def789GHI012jkl345"
RAZORPAY_SECRET = "rzp_live_ABCdef1234567890"

client = OpenAI(api_key=OPENAI_KEY)
app = Flask(__name__)


@app.route("/api/chat", methods=["POST"])
def chat():
    # VULN: unauthenticated LLM proxy + unbounded prompt
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": request.json["prompt"]}],
    )
    return resp.model_dump()


@app.route("/api/export")
def export():
    # VULN: command injection via user-controlled filename
    name = request.args.get("name")
    return subprocess.check_output(f"tar czf /tmp/{name}.tgz /data", shell=True)


if __name__ == "__main__":
    app.run(debug=True)
