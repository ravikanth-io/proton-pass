from smartpass.generator import generate, DEFAULT_SYMBOLS

def test_length_and_classes():
    pw = generate(length=12)
    assert len(pw) == 12
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in DEFAULT_SYMBOLS for c in pw)

def test_no_symbols():
    pw = generate(length=10, use_symbols=False)
    assert len(pw) == 10
    assert not any(c in DEFAULT_SYMBOLS for c in pw)

def test_too_short_raises():
    try:
        generate(length=2, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
        raised = False
    except ValueError:
        raised = True
    assert raised
