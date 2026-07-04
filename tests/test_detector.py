import pytest
from src.detector import analyze_payload_signatures

@pytest.mark.parametrize("payload, expected_attack_type", [
    # SQL Injection Schenarios
    ("admin' OR '1'='1", "SQL Injection (SQLi)"),
    ("UNION SELECT username, password FROM users", "SQL Injection (SQLi)"),
    
    # XSS Schenarios
    ("<script>alert(document.cookie)</script>", "Cross-Site Scripting (XSS)"),
    ("<img src=x onerror=alert(1)>", "Cross-Site Scripting (XSS)"),
    
    # Path Traversal Schenarios
    ("../../../etc/passwd", "Path Traversal"),
    ("c:\\windows\\system32\\cmd.exe", "Path Traversal"),
    
    # Command Injection Schenarios
    ("ping -c 4 8.8.8.8; cat /etc/shadow", "Command Injection"),
    ("127.0.0.1 && ps aux", "Command Injection")
])
def test_malicious_payloads(payload, expected_attack_type):
    """Sistemin bilinen saldırı imzalarını (DPI) kesin olarak yakaladığını test eder."""
    
    is_malicious, attack_type = analyze_payload_signatures(payload, src="192.168.1.10", dst="10.0.0.5")
    
    assert is_malicious is True
    assert attack_type == expected_attack_type


def test_benign_traffic():
    """Sistemin temiz ağ trafiğinde 'False Positive' (yanlış alarm) üretmediğini test eder."""
    
    clean_payload = "GET /api/v1/status HTTP/1.1\r\nHost: mycompany.com\r\nAccept: application/json"
    is_malicious, attack_type = analyze_payload_signatures(clean_payload, src="192.168.1.10", dst="10.0.0.5")
    
    assert is_malicious is False
    assert attack_type == ""