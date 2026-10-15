"""
app.py - Flask server for the Password Strength Checker.

Security design:
  * The password is sent in the JSON *body* of a POST (never in the URL).
  * It is analysed in memory and thrown away. No database, no files, no logs.
  * No call to any external API or website.
  * Responses are marked "no-store" so browsers never cache them.
"""
import logging

from flask import Flask, jsonify, render_template, request

from analyzer import MAX_LENGTH, ZXCVBN_AVAILABLE, analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024  # reject oversized requests

# Werkzeug's access log only prints "POST /analyze 200" (never the body),
# but we silence it anyway so nothing about requests is written to disk.
logging.getLogger("werkzeug").setLevel(logging.ERROR)


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    return response


@app.route("/")
def index():
    return render_template("index.html", max_length=MAX_LENGTH,
                           zxcvbn_on=ZXCVBN_AVAILABLE)


@app.route("/analyze", methods=["POST"])
def analyze_route():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify(error="Password must be text."), 400
    return jsonify(analyze(password))


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large."), 413


if __name__ == "__main__":
    # debug=False: the debugger can display request data on error pages.
    app.run(host="127.0.0.1", port=8000, debug=False)
