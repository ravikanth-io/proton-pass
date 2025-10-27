from smartpass.suggestions import suggest_improvements

def test_suggest_for_common_password():
    s = suggest_improvements("password123")
    assert isinstance(s, dict)
    # expect suggestions to mention common words or adding characters
    joined = " ".join(s["suggestions"]).lower()
    assert "common" in joined or "add about" in joined or "avoid" in joined

def test_examples_produced():
    s = suggest_improvements("weak")
    assert s.get("examples")
    assert len(s["examples"]) >= 1
    # example passwords should be strings and not equal to the original weak input
    assert isinstance(s["examples"][0], str)
    assert s["examples"][0] != "weak"
