from .main import detect_sql_injection 

def test_tautology_injection():
    query = "SELECT * FROM users WHERE username = 'admin' OR 1=1 --';"
    result, patterns = detect_sql_injection(query)
    assert result == True
    assert r"(?i)OR\s+1=1" in patterns

def test_union_injection():
    query = "SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin_users --';"
    result, patterns = detect_sql_injection(query)
    assert result == True
    assert r"(?i)UNION\s+SELECT" in patterns

def test_safe_query():
    query = "SELECT * FROM users WHERE username = 'john';"
    result, patterns = detect_sql_injection(query)
    assert result == False
    assert len(patterns) == 0

def test_drop_table_injection():
    query = "DROP TABLE users; --"
    result, patterns = detect_sql_injection(query)
    assert result == True
    assert r"(?i)DROP\s+TABLE" in patterns