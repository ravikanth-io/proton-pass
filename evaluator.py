"""
smartpass.evaluator

Password strength evaluator:
- estimate_entropy(password): conservative estimate of entropy (bits)
- detect patterns: dictionary words, leet substitutions, repeated sequences,
  sequential runs, keyboard patterns, years/dates
- score_password(password): returns dict with entropy, penalties, final_bits,
  score (0-100), label, explanations (list of strings), and suggestions (list)
"""

import math
import re
from typing import Dict, List, Tuple

# small built-in dictionary (offline). Expand later with a larger wordlist file.
COMMON_WORDS = {
    "password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou",
    "monkey", "dragon", "sunshine", "princess", "football", "baseball",
    "trustno1", "master", "hello", "freedom", "whatever", "secret", "password1"
}

# keyboard patterns to flag
KEYBOARD_PATTERNS = {"qwerty", "asdf", "zxcvbn", "yuiop", "hjkl", "zxcv", "1qaz", "qazwsx"}

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"

# leetspeak map for simple inverse substitution (digits/symbols -> letters)
LEET_MAP = str.maketrans("43015$", "aeois$")  # a simple mapping; can be expanded


def estimate_entropy(password: str) -> float:
    """
    Conservative entropy estimate:
    - Determine which character classes actually appear in the password.
    - Estimate pool size = sum of sizes of classes used.
    - Entropy bits = length * log2(pool_size)
    """
    if not password:
        return 0.0

    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in SYMBOLS for c in password):
        pool += len(SYMBOLS)
    # Fallback (rare): if no category matched, assume small pool
    pool = max(pool, 2)
    entropy = len(password) * math.log2(pool)
    return entropy


def _normalize_leet(s: str) -> str:
    """Return a "de-leeted" version for dictionary checks."""
    # note: this is simple; not exhaustive
    try:
        return s.translate(LEET_MAP)
    except Exception:
        return s


def detect_dictionary_substrings(password: str, min_word_len: int = 3) -> List[Tuple[str, int]]:
    """
    Return list of (word, start_index) for dictionary words found (case-insensitive).
    We check both raw password and a de-leeted variant.
    """
    found = []
    lower = password.lower()
    de_leet = _normalize_leet(lower)
    # check both variants
    for word in COMMON_WORDS:
        if len(word) < min_word_len:
            continue
        i = lower.find(word)
        if i != -1:
            found.append((word, i))
        else:
            j = de_leet.find(word)
            if j != -1:
                found.append((word, j))
    return found


def detect_repeated_sequences(password: str) -> List[str]:
    """
    Detect simple repeated patterns like 'aaa', 'ababab', '1212'.
    Return list of repeated substrings.
    """
    pw = password
    n = len(pw)
    found = []
    # detect single-char repeats length >=3
    m = re.search(r"(.)\1{2,}", pw)
    if m:
        found.append(m.group(0))
    # detect repeated block patterns (block size 1..n//2)
    for L in range(2, max(3, n // 2 + 1)):
        for start in range(0, n - 2 * L + 1):
            block = pw[start:start + L]
            if pw.count(block * 2) >= 1 and pw.find(block * 2) != -1:
                # found at least one immediate repetition
                found.append(block)
    return list(dict.fromkeys(found))  # unique-preserve-order


def detect_sequential_runs(password: str, min_len: int = 3) -> List[str]:
    """
    Detect ascending or descending sequential runs (letters or digits) of length >= min_len.
    E.g., 'abcd', '4321'
    """
    pw = password.lower()
    sequences = []
    # map characters to their ordinal where applicable
    # treat letters and digits
    seq_chars = [ord(c) if c.isalpha() or c.isdigit() else None for c in pw]
    n = len(seq_chars)
    i = 0
    while i < n - 1:
        run_start = i
        direction = 0  # +1 ascending, -1 descending, 0 unknown
        while i < n - 1 and seq_chars[i] is not None and seq_chars[i + 1] is not None:
            diff = seq_chars[i + 1] - seq_chars[i]
            if diff == 1:
                if direction in (0, 1):
                    direction = 1
                else:
                    break
            elif diff == -1:
                if direction in (0, -1):
                    direction = -1
                else:
                    break
            else:
                break
            i += 1
        run_len = i - run_start + 1
        if run_len >= min_len:
            sequences.append(pw[run_start:run_start + run_len])
        i = max(i + 1, run_start + 1)
    return sequences


def detect_keyboard_patterns(password: str) -> List[str]:
    """
    Detect usage of common keyboard patterns (qwerty, asdf, zxcvbn).
    """
    lower = password.lower()
    found = []
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            found.append(pattern)
    return found


def detect_years(password: str) -> List[str]:
    """
    Detect 4-digit year-like substrings between 1900 and 2099.
    Works even when years are adjacent to letters (e.g., 'born1978').
    """
    years = re.findall(r"(19\d{2}|20\d{2})", password)
    return years



def score_password(password: str) -> Dict:
    """
    Compute score and produce explanations + suggestions.

    Returns a dict:
    {
        "password": password,
        "entropy": float,
        "penalty": float,
        "final_bits": float,
        "score": int,  # 0..100
        "label": str,
        "explanations": [str],
        "suggestions": [str]
    }
    """
    entropy = estimate_entropy(password)
    explanations: List[str] = []
    suggestions: List[str] = []
    penalty = 0.0

    # Dictionary checks
    dict_matches = detect_dictionary_substrings(password)
    if dict_matches:
        explanations.append(f"Contains common word(s): {', '.join(w for w, _ in dict_matches)}")
        # penalize by approx 4 bits per matching char (conservative)
        penalty += sum(max(8, len(w) * 4) for w, _ in dict_matches)
        suggestions.append("Avoid using common words (e.g., 'password'). Use unrelated words or insert symbols/numbers between letters.")

    # Leet/obvious substitutions are handled by the dictionary detector implicitly via de-leet.
    # Repeated sequences
    repeats = detect_repeated_sequences(password)
    if repeats:
        explanations.append(f"Repeated pattern(s): {', '.join(repeats)}")
        penalty += 20 * len(repeats)
        suggestions.append("Break repeated sequences and introduce randomness (add random chars or shuffle).")

    # Sequential runs
    runs = detect_sequential_runs(password)
    if runs:
        explanations.append(f"Sequential run(s): {', '.join(runs)}")
        penalty += 15 * len(runs)
        suggestions.append("Avoid long ascending/descending sequences like 'abcd' or '1234'. Insert special chars or random letters.")

    # Keyboard patterns
    kb = detect_keyboard_patterns(password)
    if kb:
        explanations.append(f"Keyboard pattern(s): {', '.join(kb)}")
        penalty += 18 * len(kb)
        suggestions.append("Keyboard patterns (qwerty/asdf) are predictable — avoid them.")

    # Years/dates
    years = detect_years(password)
    if years:
        explanations.append(f"Year/date-like substring(s): {', '.join(years)}")
        penalty += 12 * len(years)
        suggestions.append("Avoid using years or dates (they are easy to guess).")

    # Short length penalty
    if len(password) < 8:
        explanations.append("Password is very short (<8 characters).")
        penalty += 30
        suggestions.append("Use at least 12-16 characters for strong security.")

    # Calculate final bits remaining after penalties
    final_bits = max(entropy - penalty, 0.0)

    # Normalize final_bits to a 0-100 score:
    # We treat ~80 bits as excellent (score 100). Lower bits scale linearly.
    score = int(min(100, round((final_bits / 80.0) * 100)))
    # floor at 0
    score = max(0, score)

    # Map score to label
    if score < 20:
        label = "Very Weak"
    elif score < 40:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Strong"
    else:
        label = "Excellent"

    # If no explanations (i.e., no detected weaknesses) provide positive feedback
    if not explanations:
        explanations.append("No obvious dictionary words, repeats, or sequences detected.")

    # Add concrete suggestion about length/entropy
    if final_bits < 60:
        # suggest how many extra characters to get near 60 bits (rule of thumb)
        # estimate per char bits = log2(pool_estimated)
        pool = 0
        if any(c.islower() for c in password): pool += 26
        if any(c.isupper() for c in password): pool += 26
        if any(c.isdigit() for c in password): pool += 10
        if any(c in SYMBOLS for c in password): pool += len(SYMBOLS)
        pool = max(pool, 2)
        bits_per_char = math.log2(pool)
        needed_bits = max(0, 60 - final_bits)
        # approximate chars needed (ceiling)
        chars_needed = math.ceil(needed_bits / bits_per_char) if bits_per_char > 0 else None
        if chars_needed:
            suggestions.append(f"Add ~{chars_needed} random characters (from chosen character sets) to improve entropy.")
        else:
            suggestions.append("Increase length and character variety to improve entropy.")

    return {
        "password": password,
        "entropy": entropy,
        "penalty": penalty,
        "final_bits": final_bits,
        "score": score,
        "label": label,
        "explanations": explanations,
        "suggestions": suggestions,
    }
