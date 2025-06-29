import re
import sqlparse
from colorama import Fore, Style

# Define suspicious SQL patterns
SQL_INJECTION_PATTERNS = [
    r"(?i)OR\s+1=1",    # Tautology-based injection
    r"(?i)'\s*--",      # Comment-based injection
    r"(?i)UNION\s+SELECT",  # UNION-based injection
    r"(?i)DROP\s+TABLE",    # Destructive queries
    r"(?i)INSERT\s+INTO",   # Potential malicious data insertion
    r"(?i)xp_cmdshell",     # Command execution in SQL Server
]

def detect_sql_injection(query):
    """
    Detects SQL injection based on predefined patterns.
    :param query: SQL query string
    :return: Boolean indicating detection, list of matched patterns
    """
    matches = []
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, query):
            matches.append(pattern)
    return len(matches) > 0, matches

def analyze_query(query):
    """
    Analyzes and formats the SQL query for better understanding.
    :param query: SQL query string
    :return: Formatted query
    """
    try:
        formatted_query = sqlparse.format(query, reindent=True, keyword_case='upper')
        return formatted_query
    except Exception as e:
        return f"Error parsing query: {str(e)}"

def main():
    print(Fore.GREEN + "SQL Injection Detection and Mitigation Tool" + Style.RESET_ALL)
    while True:
        query = input(Fore.YELLOW + "\nEnter SQL query (or type 'exit' to quit): " + Style.RESET_ALL)
        if query.lower() == 'exit':
            print(Fore.CYAN + "Exiting the tool. Stay secure!" + Style.RESET_ALL)
            break

        # Analyze the query
        formatted_query = analyze_query(query)
        print(Fore.BLUE + "\nFormatted SQL Query:" + Style.RESET_ALL)
        print(formatted_query)

        # Detect SQL Injection
        is_injection, patterns = detect_sql_injection(query)
        if is_injection:
            print(Fore.RED + "\nSQL Injection Detected!" + Style.RESET_ALL)
            print(Fore.RED + f"Malicious patterns found: {patterns}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "\nNo SQL Injection detected." + Style.RESET_ALL)

if __name__ == "__main__":
    main()