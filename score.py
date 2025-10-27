import re
from smartpass.vault import Vault
from smartpass.generator import generate_password
def score_password(password: str) -> dict:
    """
    Scores the strength of a password on a scale of 0–5 and returns both score and label.
    """

    score = 0

    # --- Basic rules ---
    length = len(password)
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1

    # --- Character variety ---
    if re.search(r"[a-z]", password):   # lowercase
        score += 1
    if re.search(r"[A-Z]", password):   # uppercase
        score += 1
    if re.search(r"\d", password):      # digits
        score += 1
    if re.search(r"[^a-zA-Z0-9]", password):  # symbols
        score += 1

    # Cap score at 5 (so length + variety don’t exceed)
    score = min(score, 5)

    # --- Strength label ---
    if score <= 1:
        label = "Very Weak"
    elif score == 2:
        label = "Weak"
    elif score == 3:
        label = "Moderate"
    elif score == 4:
        label = "Strong"
    else:
        label = "Very Strong"

    return {
        "password": password,
        "score": score,
        "label": label
    }


if __name__ == "__main__":
    # For quick testing
    pwd = input("Enter password to test: ")
    result = score_password(pwd)
    print(f"Password Strength: {result['label']} (Score: {result['score']}/5)")
