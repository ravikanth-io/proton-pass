"""
smartpass.suggestions

Turn evaluator output into concrete, prioritized suggestions and produce
example replacement passwords (using generator) to demonstrate stronger choices.
"""

from typing import List, Dict, Optional
import math

from .evaluator import score_password, SYMBOLS
from .generator import generate

def _bits_per_char_for_password(pw: str) -> float:
    """Estimate bits-per-char using the same pool logic as evaluator."""
    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(c in SYMBOLS for c in pw): pool += len(SYMBOLS)
    pool = max(pool, 2)
    return math.log2(pool)

def suggest_improvements(password: str, target_bits: int = 60) -> Dict:
    """
    Return a suggestion object derived from the evaluator plus concrete actions.
    {
        "score": int,
        "label": str,
        "suggestions": [str],  # human-readable prioritized suggestions
        "examples": [str],     # one or more generated example passwords using user's preferences
        "chars_needed": Optional[int]  # approximate chars to add to reach target_bits, or None
    }
    """
    eval_result = score_password(password)
    suggestions: List[str] = list(eval_result["suggestions"])  # start with evaluator suggestions
    examples: List[str] = []

    # If dictionary words were detected, show a transformation idea:
    # e.g., replace letters with symbol between letters, or join unrelated words.
    if any("common word" in s.lower() or "contains common" in s.lower() for s in eval_result["explanations"]):
        suggestions.insert(0, "Remove common words or break them up (insert symbols/numbers, or combine unrelated words).")
        # example: create a 16-char password with mixed sets
        try:
            examples.append(generate(length=16))
        except Exception:
            pass

    # If repeated sequences found
    if any("repeated" in s.lower() for s in eval_result["explanations"]):
        suggestions.insert(0, "Break repeated sequences — avoid 'aaaa', 'abab', etc.; insert randomness or shuffle characters.")
        try:
            examples.append(generate(length=16))
        except Exception:
            pass

    # If sequential runs or keyboard patterns
    if any("sequential" in s.lower() or "keyboard" in s.lower() for s in eval_result["explanations"]):
        suggestions.insert(0, "Avoid keyboard sequences like 'qwerty' or 'abcd' — use random characters or passphrases composed of unrelated words.")

    # Length/entropy-driven suggestion: estimate chars needed to reach target_bits (default 60)
    final_bits = eval_result["final_bits"]
    if final_bits < target_bits:
        bits_needed = max(0, target_bits - final_bits)
        bpc = _bits_per_char_for_password(password)
        chars_needed = None
        if bpc > 0:
            chars_needed = math.ceil(bits_needed / bpc)
            suggestions.append(f"Add about {chars_needed} random characters (from your chosen character sets) to raise entropy toward {target_bits} bits.")
        else:
            suggestions.append("Increase length and add character types (upper/lower/digits/symbols) to raise entropy.")
    else:
        suggestions.append("Your password meets the recommended entropy target. Good job!")

    # If no example was produced, provide a generic example
    if not examples:
        try:
            examples.append(generate(length=max(16, len(password) + 4)))
        except Exception:
            examples = []

    return {
        "password": password,
        "score": eval_result["score"],
        "label": eval_result["label"],
        "final_bits": final_bits,
        "suggestions": suggestions,
        "examples": examples,
        "chars_needed": chars_needed if 'chars_needed' in locals() else None,
    }
