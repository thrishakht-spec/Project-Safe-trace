from safetrace.sanitizer import Sanitizer, naive_redact

def test_repeated_values_same_label_and_context_preserved():
    s=Sanitizer(); out=s.sanitize('email a@example.com then a@example.com\nFile "/home/alice/app.py", line 42\nHTTP 401')
    assert out.text.count('EMAIL_1')==2
    assert 'line 42' in out.text and 'HTTP 401' in out.text
    assert 'alice' not in out.text

def test_distinct_values_get_distinct_labels():
    out=Sanitizer().sanitize('a@example.com b@example.com')
    assert 'EMAIL_1' in out.text and 'EMAIL_2' in out.text

def test_naive_redaction_replaces_detected_secret():
    assert '[REDACTED]' in naive_redact('password=verysecretvalue')

def test_empty_input():
    assert Sanitizer().sanitize('').text == ''
