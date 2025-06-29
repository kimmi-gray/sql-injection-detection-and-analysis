import re
import requests
from urllib.parse import urlparse, urljoin, unquote
import argparse
import sys

class InjectionDetector:
    def __init__(self):
        # SQL injection patterns
        self.sql_injection_patterns = [
 
            # Improved tautology patterns
            r"['\"]\s*(OR|AND)\s*['\"]?\s*\d*\s*['\"]?\s*[=<>]+\s*['\"]?\s*\d*\s*['\"]?",
            r"['\"]\s*(OR|AND)\s*['\"]?\s*\w+\s*['\"]?\s*[=<>]+\s*['\"]?\s*\w+\s*['\"]?",
            r"['\"]\s*(OR|AND)\s*1\s*=\s*1",
            r"['\"]\s*(OR|AND)\s*['\d]+\s*=\s*['\d]+",
            # Add this pattern for basic SELECT statements
            r"\bselect\s+[\w\*]+\s+from\s+\w+\b",
            # Common SQL injection keywords
            r"\b(union[\s+]select|select\s+.+from|insert\s+into|update\s+.+set|delete\s+from)\b",
            r"\b(drop\s+table|alter\s+table|create\s+table|truncate\s+table)\b",
            r"\b(exec\s*\(|execute\s*\(|xp_cmdshell)\b",
            # SQL comments and query termination
            r"(--|#|\/\*[\s\S]*?\*\/)",
            r";\s*\w+",
            # Always true conditions
            r"\b(1\s*=\s*1|true\s*=\s*true)\b",
            # Time-based delays
            r"\b(waitfor\s+delay\s+|sleep\s*\(\s*|\benchmark\s*\(\s*)\b",
            # Error-based patterns
            r"\b(extractvalue|updatexml|geometrycollection|polygon)\s*\(\s*",
            # Concatenation for evasion
            r"\b(char|concat)\s*\(\s*"
            # In InjectionDetector.__init__():
            # In InjectionDetector.__init__():

            r"\/\*!\d+",  # MySQL-specific obfuscation
            r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*?\b(?:FROM|INTO|TABLE|WHERE)\b",
            r"--|\#|\/\*",  # Comments
            r";\s*\w+",  # Query stacking
            r"\b(?:WAITFOR\s+DELAY|SLEEP|BENCHMARK)\s*\([^)]*\)",

            # variable-based patterns
            r"['\"]\s*(AND|OR)\s*@\w+\s*=\s*@\w+",
            r"['\"]\s*(AND|OR)\s*\$\w+\s*=\s*\$\w+",
            r"['\"]\s*(AND|OR)\s*:\w+\s*=\s*:\w+",
            
        ]
        
        
        # Command injection patterns
        self.command_injection_patterns = [
        # Command separators followed by commands
        r"[;&|]\s*(ls|cat|rm|whoami|pwd|wget|curl|nc)\b",
        r"\|\s*\w+",
        r";\s*\w+",
        r"&\s*\w+",
        
        # Command substitutions
        r"\$\([^)]+\)",
        r"`[^`]+`",
        
        # Dangerous redirections
        r">\s*/dev/null",
        r">>\s*\w+",
        
        # Windows specific - only match after separators
        r"[;&|]\s*(dir|cd|copy|del|echo|set|type)\b",
        r"(%0A|%0D|\%0A\%0D|%0D%0A|%20)[\w\/]",  # URL encoded newlines/spaces
        r"(%3B|%26|%7C)",  # URL encoded ; & |

        # URL encoded command separators and spaces
        r"(?:%0A|%0D|%20|\%0A\%0D|%0D%0A|%3B|%26|%7C)",
            
        # Decoded command patterns
        r"[;&|]\s*(?:ls|cat|rm|whoami|pwd|wget|curl|nc|ping)\b",
        r"\$(?:\(|{)[^)}]+(?:\)|})",
        r"`[^`]+`",

        ]
        
        self.compiled_sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_injection_patterns]
        self.compiled_command_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.command_injection_patterns]



    def _decode_url_input(self, input_str):
        try:
            from urllib.parse import unquote
            return unquote(input_str)
        except:
            return input_str

    
    def detect_sql_injection(self, input_string):
        """Detect SQL injection with enhanced variable detection"""
        findings = []
        
        # First check for variable-based tautologies
        var_patterns = [
            r"@\w+\s*=\s*@\w+",  # MySQL/SQL Server variables
            r":\w+\s*=\s*:\w+",   # Oracle/PostgreSQL bind variables
            r"\$\w+\s*=\s*\$\w+"   # PostgreSQL/PHP variables
        ]
        
        for var_pattern in var_patterns:
            if re.search(r"['\"](?:\s*OR\s*|\s*AND\s*)" + var_pattern, input_string, re.IGNORECASE):
                findings.append(f"Variable-based tautology: {var_pattern}")
        
        # Check all other patterns
        for pattern in self.compiled_sql_patterns:
            if pattern.search(input_string):
                findings.append(pattern.pattern)
        
        return findings
    
    def detect_command_injection(self, input_string):
        """Detect command injection with URL decoding"""
        try:
            # Decode URL-encoded characters first
            decoded_input = unquote(input_string)
            findings = []
            
            for pattern in self.compiled_command_patterns:
                if pattern.search(decoded_input):
                    findings.append(pattern.pattern)
                # Also check original input in case double encoding was used
                if pattern.search(input_string):
                    findings.append(pattern.pattern)
            
            return list(set(findings))  # Remove duplicates
            
        except Exception as e:
            # Fallback to non-decoded check if decoding fails
            return [p.pattern for p in self.compiled_command_patterns 
                   if p.search(input_string)]
    
    def test_sql_injection_vulnerability(self, url, params=None, cookies=None, headers=None):
        """Test if a URL is vulnerable to SQL injection."""
        if params is None:
            params = {}
        
        # Test with basic SQL injection probes
        test_payloads = [
            "'", 
            "\"", 
            "' OR '1'='1", 
            "' OR 1=1 --", 
            "\" OR \"\"=\"", 
            "1 AND 1=1", 
            "1 AND 1=2", 
            "1' ORDER BY 1--", 
            "1' UNION SELECT null,null,null--"
        ]
        
        vulnerable = False
        results = []
        
        for payload in test_payloads:
            test_params = params.copy()
            for key in test_params:
                original_value = test_params[key]
                test_params[key] = original_value + payload
                
                try:
                    response = requests.get(url, params=test_params, cookies=cookies, headers=headers, timeout=10)
                    
                    # Check for common error messages that might indicate SQL injection
                    error_messages = [
                        "SQL syntax",
                        "MySQL server",
                        "ORA-",
                        "syntax error",
                        "unclosed quotation mark",
                        "Microsoft OLE DB Provider",
                        "PostgreSQL",
                        "JDBC Driver",
                        "ODBC Driver",
                        "SQLiteException"
                    ]
                    
                    for error in error_messages:
                        if error.lower() in response.text.lower():
                            results.append(f"Potential SQL injection vulnerability detected with payload: {payload} (found error: {error})")
                            vulnerable = True
                            break
                    
                    # Check for time delays (blind SQL injection)
                    if "sleep" in payload.lower() or "waitfor" in payload.lower():
                        # This would need more sophisticated timing analysis
                        pass
                    
                except requests.exceptions.RequestException as e:
                    results.append(f"Error testing payload {payload}: {str(e)}")
        
        if not vulnerable:
            results.append("No obvious SQL injection vulnerabilities detected with basic tests.")
        
        return results

def main():
    parser = argparse.ArgumentParser(description="SQL and Command Injection Detection Tool")
    parser.add_argument("-u", "--url", help="URL to test for SQL injection vulnerabilities")
    parser.add_argument("-p", "--params", help="Query parameters (comma-separated key=value pairs)")
    parser.add_argument("-c", "--cookies", help="Cookies (comma-separated key=value pairs)")
    parser.add_argument("-H", "--headers", help="Headers (comma-separated key=value pairs)")
    parser.add_argument("-s", "--string", help="Analyze a specific string for injection patterns")
    parser.add_argument("-f", "--file", help="File containing strings to analyze")
    
    args = parser.parse_args()
    
    detector = InjectionDetector()
    
    if args.string:
        print("\nAnalyzing string for injection patterns:")
        print(f"Input string: {args.string}")
        
        sql_findings = detector.detect_sql_injection(args.string)
        if sql_findings:
            print("\n[!] Potential SQL injection patterns detected:")
            for finding in sql_findings:
                print(f"- {finding}")
        else:
            print("\n[✓] No SQL injection patterns detected")
        
        cmd_findings = detector.detect_command_injection(args.string)
        if cmd_findings:
            print("\n[!] Potential command injection patterns detected:")
            for finding in cmd_findings:
                print(f"- {finding}")
        else:
            print("\n[✓] No command injection patterns detected")
    
    elif args.file:
        print(f"\nAnalyzing file {args.file} for injection patterns:")
        try:
            with open(args.file, 'r') as f:
                line_number = 0
                for line in f:
                    line_number += 1
                    line = line.strip()
                    if not line:
                        continue
                    
                    sql_findings = detector.detect_sql_injection(line)
                    cmd_findings = detector.detect_command_injection(line)
                    
                    if sql_findings or cmd_findings:
                        print(f"\nLine {line_number}: {line}")
                        if sql_findings:
                            print("[!] Potential SQL injection patterns:")
                            for finding in sql_findings:
                                print(f"- {finding}")
                        if cmd_findings:
                            print("[!] Potential command injection patterns:")
                            for finding in cmd_findings:
                                print(f"- {finding}")
                
            print("\n[✓] File analysis complete")
        except FileNotFoundError:
            print(f"[!] Error: File {args.file} not found")
            sys.exit(1)
    
    elif args.url:
        print(f"\nTesting URL {args.url} for SQL injection vulnerabilities:")
        
        # Parse parameters if provided
        params = {}
        if args.params:
            for pair in args.params.split(','):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key.strip()] = value.strip()
        
        # Parse cookies if provided
        cookies = {}
        if args.cookies:
            for pair in args.cookies.split(','):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        # Parse headers if provided
        headers = {}
        if args.headers:
            for pair in args.headers.split(','):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    headers[key.strip()] = value.strip()
        
        results = detector.test_sql_injection_vulnerability(args.url, params, cookies, headers)
        
        print("\nTest results:")
        for result in results:
            print(f"- {result}")
    
    else:
        parser.print_help()
        print("\nExamples:")
        print("  Analyze a string: python injection_detector.py -s \"admin' OR 1=1 --\"")
        print("  Test a URL: python injection_detector.py -u \"http://example.com/page.php\" -p \"id=1\"")
        print("  Analyze a file: python injection_detector.py -f input.txt")

if __name__ == "__main__":
    main()