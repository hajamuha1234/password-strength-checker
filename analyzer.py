"""
analyzer.py - password strength analysis.

Everything here runs locally in memory. This module never writes, logs,
stores or sends a password anywhere.
"""
import re
from pathlib import Path

try:  # zxcvbn is optional; the app works without it
    from zxcvbn import zxcvbn as _zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    _zxcvbn = None
    ZXCVBN_AVAILABLE = False

MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12
MAX_LENGTH = 128  # zxcvbn gets slow on huge inputs, so we cap what we analyse

# Load the list of common passwords once, when the module is imported.
_WORDLIST = Path(__file__).with_name("common_passwords.txt")
COMMON_PASSWORDS = {
    line.strip().lower()
    for line in _WORDLIST.read_text(encoding="utf-8").splitlines()
    if line.strip()
}

# "Leetspeak" substitutions attackers try first: p@ssw0rd -> password
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                          "0": "o", "$": "s", "5": "s", "7": "t"})

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]  # digits are covered by the sequence check
LETTERS = "abcdefghijklmnopqrstuvwxyz"

LEVELS = [(20, "Very Weak"), (40, "Weak"), (60, "Medium"), (80, "Strong"),
          (101, "Very Strong")]


def _has_run(text, alphabet, run=3):
    """True if `text` contains `run` consecutive characters of `alphabet`,
    going forwards or backwards (abc, cba, 123, 321, qwe, ewq ...)."""
    text = text.lower()
    for i in range(len(text) - run + 1):
        chunk = text[i:i + run]
        if chunk in alphabet or chunk[::-1] in alphabet:
            return True
    return False


def find_patterns(password):
    """Return a list of human-readable predictable patterns found."""
    found = []
    if re.search(r"(.)\1{2,}", password):
        found.append("Repeated characters (like 'aaa' or '111')")
    if _has_run(password, LETTERS) or _has_run(password, "0123456789"):
        found.append("Simple sequence (like 'abc' or '123')")
    if any(_has_run(password, row) for row in KEYBOARD_ROWS):
        found.append("Keyboard pattern (like 'qwerty')")
    if re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", password):
        found.append("A year or date-like number (like '1998' or '2026')")
    if password.isdigit():
        found.append("Numbers only")
    elif password.isalpha():
        found.append("Letters only")
    return found


def is_common(password):
    """Return (kind, message) if the password is predictable, else None.

    Checks: exact match, leetspeak match, and 'common word + digits/symbols'.
    """
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        return "exact", "This is a very commonly used password."
    if lower.translate(LEET_MAP) in COMMON_PASSWORDS:
        return "leet", ("This is a common password with predictable "
                        "character swaps (like @ for a).")
    base = re.sub(r"[\d\W_]+$", "", lower)  # strip trailing digits/symbols
    if base and base != lower and (
        base in COMMON_PASSWORDS or base.translate(LEET_MAP) in COMMON_PASSWORDS
    ):
        return "suffix", ("This is a common word with numbers or symbols "
                          "added at the end, which attackers try first.")
    return None


def classify(score):
    for limit, label in LEVELS:
        if score < limit:
            return label


def analyze(password, use_zxcvbn=True):
    """Analyse a password and return a dictionary of results."""
    password = password[:MAX_LENGTH]
    length = len(password)

    if length == 0:
        return {"empty": True}

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9\s]", password))

    checklist = [
        {"id": "length", "label": f"At least {MIN_LENGTH} characters", "passed": length >= MIN_LENGTH},
        {"id": "long", "label": f"{RECOMMENDED_LENGTH}+ characters (recommended)", "passed": length >= RECOMMENDED_LENGTH},
        {"id": "upper", "label": "Uppercase letter (A-Z)", "passed": has_upper},
        {"id": "lower", "label": "Lowercase letter (a-z)", "passed": has_lower},
        {"id": "digit", "label": "Number (0-9)", "passed": has_digit},
        {"id": "special", "label": "Special character (!@#$...)", "passed": has_special},
    ]

    # ---- Score out of 100 -------------------------------------------------
    score = min(length, 20) * 2.5                           # length: up to 50
    score += 10 * sum([has_upper, has_lower, has_digit, has_special])  # up to 40
    if length >= RECOMMENDED_LENGTH:
        score += 10                                          # long bonus

    patterns = find_patterns(password)
    penalty = {"Repeated": 10, "Simple": 15, "Keyboard": 15, "A year": 5,
               "Numbers": 10, "Letters": 10}
    for p in patterns:
        score -= next(v for k, v in penalty.items() if p.startswith(k))

    # ---- Common password caps ---------------------------------------------
    common = is_common(password)
    warnings = []
    if length < MIN_LENGTH:
        warnings.append(f"Too short: use at least {MIN_LENGTH} characters "
                        f"({RECOMMENDED_LENGTH}+ is better).")
        score = min(score, 30)
    if common:
        kind, message = common
        warnings.append(message)
        score = min(score, {"exact": 5, "leet": 12, "suffix": 25}[kind])

    # ---- Optional zxcvbn second opinion -----------------------------------
    zx = None
    if use_zxcvbn and ZXCVBN_AVAILABLE:
        result = _zxcvbn(password)  # runs locally, no network
        zx = {"score": result["score"],
              "crack_time": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]}
        score = min(score, {0: 15, 1: 35, 2: 55, 3: 79, 4: 100}[result["score"]])

    score = max(0, min(100, round(score)))

    # ---- Recommendations ----------------------------------------------------
    tips = []
    if length < RECOMMENDED_LENGTH:
        tips.append(f"Make it longer. Aim for {RECOMMENDED_LENGTH}+ characters, or a passphrase of 4+ random words.")
    if not has_upper:
        tips.append("Add an uppercase letter.")
    if not has_lower:
        tips.append("Add a lowercase letter.")
    if not has_digit:
        tips.append("Add a number.")
    if not has_special:
        tips.append("Add a special character such as ! @ # $ % or &.")
    if common:
        tips.append("Avoid common passwords and words. Pick something unique to you that is hard to guess.")
    if patterns:
        tips.append("Remove predictable patterns: " + "; ".join(patterns).lower() + ".")
    if not tips:
        tips.append("Great job! Use a unique password for every account and store it in a password manager.")
        tips.append("Turn on two-factor authentication (2FA) wherever it is offered.")

    return {
        "empty": False,
        "score": score,
        "label": classify(score),
        "length": length,
        "checklist": checklist,
        "patterns": patterns,
        "warnings": warnings,
        "recommendations": tips,
        "zxcvbn": zx,
        "disclaimer": ("This score is only an estimate. It does not guarantee "
                       "a password can't be cracked."),
    }
