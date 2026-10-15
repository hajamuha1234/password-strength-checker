# Password Strength Checker

A beginner-friendly web app that rates password strength, explains what is missing, and suggests improvements. Built with **Python, Flask, HTML, CSS and JavaScript**.

> Screenshot: add `docs/screenshot.png` and uncomment the next line.
> `![App screenshot](docs/screenshot.png)`

## Features

- Password field with Show / Hide and Reset buttons
- Five levels: Very Weak, Weak, Medium, Strong, Very Strong
- Colored five-segment strength meter and a 0-100 score
- Live checklist: length, uppercase, lowercase, numbers, special characters
- Detects common passwords, leetspeak swaps (`p@ssw0rd`), "common word + numbers" (`Hello123`), repeated characters, sequences, keyboard patterns and years
- Warnings for short or commonly used passwords
- Personalized recommendations
- Optional [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) second opinion and cracking-time estimate
- Dark, green, cybersecurity-style layout that works on phones

## Privacy and security

| Rule | How it is handled |
|---|---|
| Never save or log passwords | No database, no files, no `print`/logging of input. Request logging is silenced. |
| Never use external APIs | The app makes no outbound network calls. zxcvbn runs locally. |
| No browser storage | No `localStorage`, `sessionStorage` or cookies. Password is never in the URL. |
| No caching | Responses send `Cache-Control: no-store`. |
| Safe rendering | The UI uses `textContent`, never `innerHTML`. A strict Content-Security-Policy is set. |

**Important:** the password is sent from the page to the Flask server so Python can analyse it. Run the app on `127.0.0.1` (the default) so it never leaves your computer. If you ever deploy it publicly, you must use HTTPS. For a design where the password never leaves the browser, see *Future improvements*.

**The score is an estimate, not a guarantee** that a password cannot be cracked.

## Project structure

```
password-strength-checker/
├── app.py                 # Flask server and routes
├── analyzer.py            # Scoring and pattern detection (re + optional zxcvbn)
├── common_passwords.txt   # Small list of common passwords
├── requirements.txt
├── README.md
├── templates/index.html
├── static/style.css
├── static/script.js
└── tests/test_analyzer.py
```

## Installation

```bash
cd password-strength-checker
python -m venv venv

# Windows (PowerShell)
venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## How scoring works

- Length: 2.5 points per character, up to 20 characters (max 50)
- Variety: 10 points each for uppercase, lowercase, digit, special (max 40)
- Bonus: +10 for 12 or more characters
- Penalties: repeats, sequences, keyboard patterns, years, numbers-only, letters-only
- Caps: common passwords are capped at 5, leetspeak versions at 12, "common word + digits" at 25, and passwords under 8 characters at 30
- If zxcvbn is installed, its score can lower the final result but never raise it

Levels: 0-19 Very Weak, 20-39 Weak, 40-59 Medium, 60-79 Strong, 80-100 Very Strong.

## Example results (rules only)

| Password | Score | Level | Why |
|---|---|---|---|
| `123456` | 0 | Very Weak | Common, numbers only, sequence, too short |
| `password` | 5 | Very Weak | One of the most common passwords |
| `Hello123` | 25 | Weak | Common word plus `123`, only 8 characters |
| `Hello@2026Secure` | 85 | Very Strong | 16 characters, all four types, only a year as a weakness |

These are demonstrations only. Do not use them as real passwords.

## Troubleshooting

- **`python` not found:** try `python3`, or reinstall Python and tick "Add to PATH".
- **PowerShell blocks activation:** run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
- **`ModuleNotFoundError: flask`:** activate the virtual environment, then `pip install -r requirements.txt`.
- **Port 5000 in use (macOS AirPlay):** change `port=5000` to `5001` in `app.py`.
- **Page loads but nothing updates:** check the terminal for errors and hard-refresh (Ctrl+Shift+R).
- **zxcvbn fails to install:** the app still works without it. Remove it from `requirements.txt`.

## Future improvements

- Do all analysis in browser JavaScript so the password never leaves the page
- Larger common-password list (for example, a trimmed top-10,000 list)
- Passphrase generator and breach-check using k-anonymity (only a hash prefix leaves the device)
- Dark/light toggle, multiple languages, Docker image, CI tests

## Resume description

**Password Strength Checker** (Python, Flask, JavaScript, HTML/CSS): Built a privacy-focused web app that scores passwords on a five-level scale, detects common passwords, leetspeak substitutions and keyboard/sequence patterns, and gives live recommendations. Applied secure-by-design practices (no storage or logging, no-store caching, CSP headers, safe DOM rendering) and wrote automated unit tests. Responsive dark UI with an accessible strength meter.

## License

MIT
