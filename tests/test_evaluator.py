from smartpass.evaluator import (
    estimate_entropy,
    detect_dictionary_substrings,
    detect_repeated_sequences,
    detect_sequential_runs,
    detect_keyboard_patterns,
    detect_years,
    score_password,
)

def test_entropy_increases_with_length():
    e_short = estimate_entropy("Ab1!")
    e_long = estimate_entropy("Ab1!" * 4)
    assert e_long > e_short

def test_dictionary_detection():
    # contains common word "password"
    matches = detect_dictionary_substrings("MyPassword123")
    assert any("password" == w for w, _ in matches)

    result = score_password("password123")
    assert result["label"] in ("Very Weak", "Weak")
    assert "common word" in " ".join(result["explanations"]).lower() or any("password" in e.lower() for e in result["explanations"])

def test_repeats_and_sequences():
    repeats = detect_repeated_sequences("aaaabbbb")
    assert repeats  # should find 'aaaa' or 'bbbb' pattern

    runs = detect_sequential_runs("abcdef12345")
    assert runs  # should find sequences like 'abcd' or '12345'

def test_keyboard_and_year_detection():
    kb = detect_keyboard_patterns("myqwertypass")
    assert "qwerty" in kb

    yrs = detect_years("born1978!")
    assert "1978" in yrs

def test_strong_password_scores_high():
    # a reasonably long random-looking password
    pw = "X7f!9Lq@2Vb#tR4sYp"
    result = score_password(pw)
    assert result["score"] >= 60  # expect at least 'Strong' or 'Fair-Strong'
