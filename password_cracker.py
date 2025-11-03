#!/usr/bin/env python3
"""
Password Cracking Simulation Tool
Educational tool for demonstrating password strength analysis
"""

import hashlib
import time
import string
import itertools
import argparse
import json
from datetime import datetime, timedelta
import os

class PasswordCracker:
    def __init__(self):
        self.hash_types = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        self.attempts = 0
        self.start_time = None
        self.results = []
        
    def hash_password(self, password, hash_type='sha256'):
        """Generate hash for a password"""
        hash_func = self.hash_types.get(hash_type, hashlib.sha256)
        return hash_func(password.encode()).hexdigest()
    
    def dictionary_attack(self, target_hash, wordlist_file, hash_type='sha256'):
        """Perform dictionary attack"""
        print(f"\n[*] Starting Dictionary Attack")
        print(f"[*] Hash Type: {hash_type.upper()}")
        print(f"[*] Target Hash: {target_hash}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        try:
            with open(wordlist_file, 'r', encoding='latin-1') as f:
                for line in f:
                    password = line.strip()
                    self.attempts += 1
                    
                    if self.attempts % 10000 == 0:
                        print(f"[*] Attempts: {self.attempts:,}")
                    
                    hashed = self.hash_password(password, hash_type)
                    
                    if hashed == target_hash:
                        elapsed = time.time() - self.start_time
                        print(f"\n[+] PASSWORD FOUND: {password}")
                        print(f"[+] Attempts: {self.attempts:,}")
                        print(f"[+] Time: {elapsed:.2f} seconds")
                        return password
                        
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist_file}")
            return None
        
        elapsed = time.time() - self.start_time
        print(f"\n[-] Password not found")
        print(f"[-] Attempts: {self.attempts:,}")
        print(f"[-] Time: {elapsed:.2f} seconds")
        return None
    
    def brute_force_attack(self, target_hash, max_length=4, charset=None, hash_type='sha256'):
        """Perform brute force attack"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"\n[*] Starting Brute Force Attack")
        print(f"[*] Hash Type: {hash_type.upper()}")
        print(f"[*] Target Hash: {target_hash}")
        print(f"[*] Max Length: {max_length}")
        print(f"[*] Charset: {charset}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        for length in range(1, max_length + 1):
            print(f"\n[*] Trying length: {length}")
            for attempt in itertools.product(charset, repeat=length):
                password = ''.join(attempt)
                self.attempts += 1
                
                if self.attempts % 10000 == 0:
                    print(f"[*] Attempts: {self.attempts:,}")
                
                hashed = self.hash_password(password, hash_type)
                
                if hashed == target_hash:
                    elapsed = time.time() - self.start_time
                    print(f"\n[+] PASSWORD FOUND: {password}")
                    print(f"[+] Attempts: {self.attempts:,}")
                    print(f"[+] Time: {elapsed:.2f} seconds")
                    return password
        
        elapsed = time.time() - self.start_time
        print(f"\n[-] Password not found within max length")
        print(f"[-] Attempts: {self.attempts:,}")
        print(f"[-] Time: {elapsed:.2f} seconds")
        return None
    
    def analyze_password_strength(self, password):
        """Analyze password strength"""
        analysis = {
            'password': password,
            'length': len(password),
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(c in string.punctuation for c in password),
            'strength': 'WEAK',
            'score': 0,
            'estimated_crack_time': '',
            'recommendations': []
        }
        
        # Calculate score
        if analysis['length'] >= 8:
            analysis['score'] += 1
        if analysis['length'] >= 12:
            analysis['score'] += 1
        if analysis['length'] >= 16:
            analysis['score'] += 1
        
        if analysis['has_lowercase']:
            analysis['score'] += 1
        if analysis['has_uppercase']:
            analysis['score'] += 1
        if analysis['has_digits']:
            analysis['score'] += 1
        if analysis['has_special']:
            analysis['score'] += 1
        
        # Determine strength
        if analysis['score'] <= 2:
            analysis['strength'] = 'VERY WEAK'
            analysis['estimated_crack_time'] = 'Seconds to Minutes'
        elif analysis['score'] <= 4:
            analysis['strength'] = 'WEAK'
            analysis['estimated_crack_time'] = 'Minutes to Hours'
        elif analysis['score'] <= 6:
            analysis['strength'] = 'MODERATE'
            analysis['estimated_crack_time'] = 'Days to Weeks'
        else:
            analysis['strength'] = 'STRONG'
            analysis['estimated_crack_time'] = 'Months to Years'
        
        # Generate recommendations
        if analysis['length'] < 12:
            analysis['recommendations'].append("Increase length to at least 12 characters")
        if not analysis['has_uppercase']:
            analysis['recommendations'].append("Add uppercase letters")
        if not analysis['has_lowercase']:
            analysis['recommendations'].append("Add lowercase letters")
        if not analysis['has_digits']:
            analysis['recommendations'].append("Add numbers")
        if not analysis['has_special']:
            analysis['recommendations'].append("Add special characters (!@#$%^&*)")
        
        # Check for common patterns
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            analysis['recommendations'].append("Avoid common patterns and words")
        
        return analysis
    
    def generate_wordlist(self, output_file, word_count=1000):
        """Generate a sample wordlist"""
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', '12345678', '111111', '123123', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'master',
            'sunshine', 'princess', 'football', 'shadow', 'michael'
        ]
        
        # Add variations
        wordlist = set(common_passwords)
        
        for word in common_passwords[:10]:
            for year in range(2020, 2026):
                wordlist.add(f"{word}{year}")
            for num in range(10):
                wordlist.add(f"{word}{num}")
            wordlist.add(word.upper())
            wordlist.add(word.capitalize())
        
        # Add simple combinations
        for i in range(1000, 2000):
            wordlist.add(str(i))
        
        with open(output_file, 'w') as f:
            for word in sorted(wordlist)[:word_count]:
                f.write(word + '\n')
        
        print(f"[+] Generated wordlist: {output_file} ({word_count} entries)")
        return output_file
    
    def estimate_crack_time(self, password, hashes_per_second=1000000000):
        """Estimate time to crack password"""
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        
        possible_combinations = charset_size ** len(password)
        seconds = possible_combinations / hashes_per_second
        
        return self.format_time(seconds)
    
    def format_time(self, seconds):
        """Format seconds into readable time"""
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        else:
            return f"{seconds/31536000:.2f} years"
    
    def generate_report(self, passwords, output_dir='reports'):
        """Generate password strength report"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        report = {
            'scan_date': timestamp,
            'total_passwords': len(passwords),
            'analysis': []
        }
        
        print("\n" + "="*70)
        print("PASSWORD STRENGTH ANALYSIS REPORT")
        print("="*70 + "\n")
        
        for pwd in passwords:
            analysis = self.analyze_password_strength(pwd)
            report['analysis'].append(analysis)
            
            print(f"Password: {'*' * len(pwd)} (length: {len(pwd)})")
            print(f"Strength: {analysis['strength']}")
            print(f"Score: {analysis['score']}/7")
            print(f"Estimated Crack Time: {analysis['estimated_crack_time']}")
            
            if analysis['recommendations']:
                print("Recommendations:")
                for rec in analysis['recommendations']:
                    print(f"  - {rec}")
            print("-" * 70 + "\n")
        
        # Save JSON report
        json_file = f"{output_dir}/password_analysis_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Save text report
        txt_file = f"{output_dir}/password_report_{timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("PASSWORD STRENGTH ANALYSIS REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Scan Date: {timestamp}\n")
            f.write(f"Total Passwords Analyzed: {len(passwords)}\n\n")
            
            for analysis in report['analysis']:
                f.write(f"Password Length: {analysis['length']} characters\n")
                f.write(f"Strength: {analysis['strength']}\n")
                f.write(f"Score: {analysis['score']}/7\n")
                f.write(f"Estimated Crack Time: {analysis['estimated_crack_time']}\n")
                
                if analysis['recommendations']:
                    f.write("Recommendations:\n")
                    for rec in analysis['recommendations']:
                        f.write(f"  - {rec}\n")
                f.write("-" * 70 + "\n\n")
            
            f.write(self.get_security_recommendations())
        
        print(f"\n[+] Reports saved:")
        print(f"    - {json_file}")
        print(f"    - {txt_file}")
    
    def get_security_recommendations(self):
        """Get general security recommendations"""
        recommendations = """
========================================================================
GENERAL PASSWORD SECURITY RECOMMENDATIONS
========================================================================

1. PASSWORD COMPLEXITY REQUIREMENTS:
   - Minimum length: 12 characters (16+ recommended)
   - Include uppercase letters (A-Z)
   - Include lowercase letters (a-z)
   - Include numbers (0-9)
   - Include special characters (!@#$%^&*)
   - Avoid common words and patterns

2. PASSWORD MANAGEMENT BEST PRACTICES:
   - Use unique passwords for each account
   - Never reuse passwords across services
   - Change passwords regularly (every 90 days)
   - Use a password manager (e.g., Bitwarden, 1Password, LastPass)
   - Never share passwords via email or text

3. MULTI-FACTOR AUTHENTICATION (MFA):
   - Enable MFA on all critical accounts
   - Use authenticator apps (Google Authenticator, Authy)
   - Avoid SMS-based 2FA when possible
   - Keep backup codes in a secure location

4. ORGANIZATIONAL POLICIES:
   - Implement password expiration policies
   - Enforce password complexity requirements
   - Use account lockout after failed attempts
   - Monitor for compromised credentials
   - Conduct regular security awareness training

5. COMMON ATTACKS TO DEFEND AGAINST:
   - Dictionary Attacks: Use uncommon words and combinations
   - Brute Force: Increase password length and complexity
   - Credential Stuffing: Use unique passwords per service
   - Phishing: Verify URLs and enable MFA
   - Social Engineering: Never share passwords verbally

6. PASSWORD STORAGE:
   - Never store passwords in plain text
   - Use strong hashing algorithms (bcrypt, Argon2, scrypt)
   - Implement salting for password hashes
   - Use key derivation functions (KDFs)

7. INCIDENT RESPONSE:
   - Change passwords immediately if breach suspected
   - Check haveibeenpwned.com for compromised credentials
   - Review account activity logs
   - Report security incidents promptly

========================================================================
ESTIMATED CRACK TIMES (Modern GPU: 100 billion hashes/second)
========================================================================

8 character password:
  - Lowercase only: 2 seconds
  - Lowercase + Uppercase: 10 minutes
  - Alphanumeric: 1 hour
  - All characters: 3 days

12 character password:
  - Lowercase only: 1 year
  - Lowercase + Uppercase: 200 years
  - Alphanumeric: 2,000 years
  - All characters: 34,000 years

16 character password:
  - Lowercase only: 26 million years
  - Lowercase + Uppercase: 10 billion years
  - All characters: 1.7 trillion years

========================================================================
COMPLIANCE STANDARDS
========================================================================

NIST SP 800-63B Guidelines:
  - Minimum 8 characters for user-generated passwords
  - Check against known breached passwords
  - No periodic password changes without reason
  - Allow all printable ASCII characters

PCI DSS Requirements:
  - Minimum 7 characters (12+ recommended)
  - Alphanumeric complexity required
  - Change every 90 days
  - Remember last 4 passwords

HIPAA Recommendations:
  - Strong password policies
  - Regular password changes
  - Multi-factor authentication
  - Encrypted password storage

========================================================================
"""
        return recommendations

def main():
    parser = argparse.ArgumentParser(
        description='Password Cracking Simulation and Strength Analysis Tool'
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Dictionary attack
    dict_parser = subparsers.add_parser('dictionary', help='Dictionary attack')
    dict_parser.add_argument('hash', help='Target hash')
    dict_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file')
    dict_parser.add_argument('-t', '--type', default='sha256', 
                            choices=['md5', 'sha1', 'sha256', 'sha512'],
                            help='Hash type')
    
    # Brute force attack
    brute_parser = subparsers.add_parser('brute', help='Brute force attack')
    brute_parser.add_argument('hash', help='Target hash')
    brute_parser.add_argument('-l', '--length', type=int, default=4, help='Max password length')
    brute_parser.add_argument('-t', '--type', default='sha256',
                             choices=['md5', 'sha1', 'sha256', 'sha512'],
                             help='Hash type')
    
    # Analyze passwords
    analyze_parser = subparsers.add_parser('analyze', help='Analyze password strength')
    analyze_parser.add_argument('-p', '--passwords', nargs='+', help='Passwords to analyze')
    analyze_parser.add_argument('-f', '--file', help='File with passwords (one per line)')
    
    # Generate hash
    hash_parser = subparsers.add_parser('hash', help='Generate password hash')
    hash_parser.add_argument('password', help='Password to hash')
    hash_parser.add_argument('-t', '--type', default='sha256',
                            choices=['md5', 'sha1', 'sha256', 'sha512'],
                            help='Hash type')
    
    # Generate wordlist
    wordlist_parser = subparsers.add_parser('generate', help='Generate wordlist')
    wordlist_parser.add_argument('-o', '--output', default='wordlist.txt', help='Output file')
    wordlist_parser.add_argument('-n', '--count', type=int, default=1000, help='Number of words')
    
    args = parser.parse_args()
    cracker = PasswordCracker()
    
    if args.command == 'dictionary':
        cracker.dictionary_attack(args.hash, args.wordlist, args.type)
    
    elif args.command == 'brute':
        cracker.brute_force_attack(args.hash, args.length, hash_type=args.type)
    
    elif args.command == 'analyze':
        passwords = []
        if args.passwords:
            passwords = args.passwords
        elif args.file:
            with open(args.file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            print("[!] Provide passwords with -p or -f")
            return
        
        cracker.generate_report(passwords)
    
    elif args.command == 'hash':
        hashed = cracker.hash_password(args.password, args.type)
        print(f"\n[+] Password: {args.password}")
        print(f"[+] Hash Type: {args.type.upper()}")
        print(f"[+] Hash: {hashed}\n")
    
    elif args.command == 'generate':
        cracker.generate_wordlist(args.output, args.count)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
