"""
privacy_compliance_scanner.py version 1.0

Interactive scanner for privacy-relevant identifiers based on GDPR and CCPA.
Supports Python, C/C++, Java, JavaScript source files, skipping full-line and inline comments.
Scan the code files in a directory and print the report or save the report to .json/.txt file.
"""
import os
import re
import json
import sys

EXTENSIONS = ['.py', '.c', '.cpp', '.cc', '.h', '.hpp', '.java', '.js']

# Default GDPR/CCPA regex patterns
def default_patterns():
    return [
        {'pattern': r'\b(name|first_name|last_name|username)\b', 'description': 'PII: name (GDPR/CCPA)'},
        {'pattern': r'\b(email|email_address)\b', 'description': 'PII: email (GDPR/CCPA)'},
        {'pattern': r'\b(phone|telephone|mobile)\b', 'description': 'PII: phone number (GDPR/CCPA)'},
        {'pattern': r'\b(address|street|city|zip|postcode)\b', 'description': 'PII: address (GDPR/CCPA)'},
        {'pattern': r'\b(ssn|social_security_number)\b', 'description': 'PII: SSN (GDPR)'},
        {'pattern': r'\b(dob|date_of_birth)\b', 'description': 'PII: date of birth (GDPR/CCPA)'},
        {'pattern': r'\b(race|ethnicity)\b', 'description': 'PII: race/ethnicity (GDPR)'},
        {'pattern': r'\b(health|medical)\b', 'description': 'PII: health data (GDPR)'},
        {'pattern': r'\b(password|passwd)\b', 'description': 'PII: password (GDPR/CCPA)'},
        {'pattern': r'\b(purchase_history|transactions?)\b', 'description': 'PII: purchase history (CCPA)'},
        {'pattern': r'\b(browsing_history|history)\b', 'description': 'PII: browsing history (CCPA)'},
        {'pattern': r'\b(geolocation|latitude|longitude)\b', 'description': 'PII: geolocation (CCPA)'},
        {'pattern': r'\b(audio|video|call_recording)\b', 'description': 'PII: audio/visual info (CCPA)'},
        {'pattern': r'\b(employment|job_title|salary)\b', 'description': 'PII: employment info (CCPA)'},
        {'pattern': r'\b(education|school|degree)\b', 'description': 'PII: education info (CCPA)'},
        {'pattern': r'\b(inference|profile)\b', 'description': 'PII: inference/profile (CCPA)'},
        {'pattern': r'\b(biometric|fingerprint|faceprint)\b', 'description': 'PII: biometric (CCPA)'},
        {'pattern': r'\b(ip_address|device_id|mac_address)\b', 'description': 'PII: device/internet activity (CCPA)'}
    ]

# Load customized patterns from JSON file (in case of the developers do not want to use the default regex patterns
def load_patterns(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading patterns: {e}")
        return default_patterns()

# Determine line-comment delimiter based on file extension
def get_comment_delimiter(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == '.py':
        return '#'
    elif ext in ['.c', '.cpp', '.cc', '.h', '.hpp', '.java', '.js']:
        return '//'
    return None

# Strip comments from a line
def strip_comments(line, delimiter):
    if not delimiter:
        return line
    parts = line.split(delimiter, 1)
    return parts[0]

# Scan a single file for pattern matches and skipping comments
def scan_file(path, patterns):
    violations = []
    delimiter = get_comment_delimiter(path)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, raw_line in enumerate(f, start=1):
                # Remove inline comments
                code_line = strip_comments(raw_line, delimiter)
                # Skip lines that are purely comments or empty after stripping
                if not code_line.strip():
                    continue
                for pat in patterns:
                    if re.search(pat['pattern'], code_line, re.IGNORECASE):
                        violations.append({
                            'file': path,
                            'line': lineno,
                            'snippet': code_line.strip(),
                            'description': pat['description']
                        })
    except Exception as e:
        print(f"Error scanning {path}: {e}")
    return violations

# Scan directory tree
def scan_directory(directory, patterns):
    results = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if any(fname.lower().endswith(ext) for ext in EXTENSIONS):
                results.extend(scan_file(os.path.join(root, fname), patterns))
    return results

# Print formatted report with numbering
def print_report(violations):
    if not violations:
        print("No violations found.")
        return
    total = len(violations)
    files = {}
    for v in violations:
        files.setdefault(v['file'], 0)
        files[v['file']] += 1
    print(f"\nScan Report: {total} violations across {len(files)} files")
    for fpath, count in files.items():
        print(f"  {fpath}: {count}")
    print("\nDetails:")
    for idx, v in enumerate(violations, start=1):
        print(f"{idx}. {v['file']}:{v['line']} [{v['description']}] {v['snippet']}")

# Save report as JSON
def save_report_json(violations, path):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(violations, f, indent=2)
    except Exception as e:
        print(f"Error saving JSON report: {e}")

# Save report as TXT with numbering
def save_report_txt(violations, path):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            if not violations:
                f.write("No violations found.\n")
                return
            total = len(violations)
            files = {}
            for v in violations:
                files.setdefault(v['file'], 0)
                files[v['file']] += 1
            f.write(f"Scan Report: {total} violations across {len(files)} files\n")
            for fpath, count in files.items():
                f.write(f"  {fpath}: {count}\n")
            f.write("\nDetails:\n")
            for idx, v in enumerate(violations, start=1):
                f.write(f"{idx}. {v['file']}:{v['line']} [{v['description']}] {v['snippet']}\n")
    except Exception as e:
        print(f"Error saving TXT report: {e}")

# Interactive menu
def main():
    patterns = default_patterns()
    violations = []
    while True:
        print("\n===== Privacy Compliance Scanner ======")
        print("1) Scan code directory")
        print("2) Load custom patterns from JSON")
        print("3) View last scan report")
        print("4) Save report to JSON file")
        print("5) Save report to TXT file")
        print("6) Exit")
        choice = input("Select an option: ").strip()
        if choice == '1':
            dir_path = input("Enter directory to scan: ").strip()
            if os.path.isdir(dir_path):
                violations = scan_directory(dir_path, patterns)
                print(f"Scan complete: {len(violations)} violations found.")
            else:
                print("Invalid directory.")
        elif choice == '2':
            config = input("Enter JSON patterns file path: ").strip()
            patterns = load_patterns(config)
            print("Patterns loaded.")
        elif choice == '3':
            print_report(violations)
        elif choice == '4':
            if violations:
                out_path = input("Enter output JSON file path: ").strip()
                save_report_json(violations, out_path)
                print(f"JSON report saved to {out_path}")
            else:
                print("No report to save. Run a scan first.")
        elif choice == '5':
            if violations:
                out_path = input("Enter output TXT file path: ").strip()
                save_report_txt(violations, out_path)
                print(f"TXT report saved to {out_path}")
            else:
                print("No report to save. Run a scan first.")
        elif choice == '6':
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid selection; choose 1-6.")

if __name__ == '__main__':
    main()