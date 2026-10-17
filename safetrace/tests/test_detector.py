from safetrace.detector import detect_sensitive

def test_email_and_ip_detected():
    m=detect_sensitive('contact a@example.com from 192.168.1.25')
    assert {x.category for x in m} >= {'EMAIL','IP_ADDRESS'}

def test_assignment_and_bearer_detected():
    m=detect_sensitive('password=super-secret-77 Authorization: Bearer abcdefghijk12345')
    assert any(x.category=='ASSIGNMENT_SECRET' for x in m)
    assert any(x.category=='AUTH_TOKEN' for x in m)

def test_home_username_detected():
    m=detect_sensitive('/home/alice/project/main.py')
    assert any(x.category=='USERNAME' and x.value=='alice' for x in m)

def test_invalid_ipv4_ignored():
    m=detect_sensitive('999.999.999.999')
    assert not any(x.category=='IP_ADDRESS' for x in m)
