"""
privacy_application_log_scanner.py

Scan the Vector tool's application logs (pygoat-logs.ndjson) for privacy instances.
Rules defined in a JSON file using privacy regulation and privacy-by-design principles.
Supports updating the rule JSON file by appending new rules without duplicates.
Reports privacy instances if detected.
Includes line-number mapping to locate the exact spot in the .ndjson file.
Save the scan results as JSON and TXT.
"""

import argparse
import json
import os
import re
import sys
import shutil
import textwrap

# Load rule definitions from a JSON file
def load_rules(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading rules file '{path}': {e}", file=sys.stderr)
        sys.exit(1)

# Append new rules from src into dst, skipping duplicates by 'id'
def save_rules(src, dst):
    if not os.path.exists(src):
        print(f"Error: source rules file not found: {src}", file=sys.stderr)
        sys.exit(1)

    new = load_rules(src)
    existing = load_rules(dst) if os.path.exists(dst) else []
    seen_ids = {r.get('id') for r in existing}
    added = 0
    for rule in new:
        if rule.get('id') not in seen_ids:
            existing.append(rule)
            added += 1
    try:
        with open(dst, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2)
        print(f"Appended {added} new rule(s) to {dst}")
    except Exception as e:
        print(f"Error saving merged rules to '{dst}': {e}", file=sys.stderr)
        sys.exit(1)

# Scan the NDJSON logfile
# Apply each regex rule to the 'log' field (or entire message) in each record
# Returns a list of match instances with recommendations
def scan_logs(logfile, rules):
    instances = []
    if not os.path.exists(logfile):
        print(f"Error: log file not found: {logfile}", file=sys.stderr)
        sys.exit(1)

    with open(logfile, encoding='utf-8') as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg = rec.get('message')
            if msg:
                try:
                    inner = json.loads(msg)
                    text = inner.get('log', '')
                except Exception:
                    text = msg
            else:
                text = rec.get('log', raw)

            for rule in rules:
                pat = rule.get('pattern', '')
                if pat and re.search(pat, text):
                    clean_text = text.replace('\n', ' ').strip()
                    instances.append({
                        'rule': rule.get('id'),
                        'description': rule.get('description'),
                        'recommendation': rule.get('recommendation', ''),
                        'line': lineno,
                        'value': clean_text
                    })
    return instances

# Save instances to a JSON file
def save_report_json(instances, path):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(instances, f, indent=2)
        print(f"JSON report saved to {path}")
    except Exception as e:
        print(f"Error writing JSON report '{path}': {e}", file=sys.stderr)

# Save instances to a TXT file
def save_report_txt(instances, path):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            if instances:
                f.write(f"{len(instances)} Privacy instance{'s' if len(instances)!=1 else ''} detected:\n\n")
                for i, inst in enumerate(instances, start=1):
                    f.write(f"{i:02d}. Rule [{inst['rule']}] (@line {inst['line']}): {inst['description']}\n")
                    f.write(f"    Value: '{inst['value']}'\n")
                    if inst.get('recommendation'):
                        f.write(f"    Recommendation: {inst['recommendation']}\n")
                    f.write("\n")
            else:
                f.write("No instances detected.\n")
        print(f"TXT report saved to {path}")
    except Exception as e:
        print(f"Error writing TXT report '{path}': {e}", file=sys.stderr)


# Main entrypoint for parsing args, run scan/update-rules, save outputs, and displaying the results
def main():
    p = argparse.ArgumentParser(prog='privacy_application_log_scanner.py',description='Scan Vector NDJSON logs for rule matches')
    p.add_argument("--update-rules", nargs=2, metavar=("SRC","DST"), help="Append rules from SRC into DST (no duplicates)")
    p.add_argument("--logs", default="pygoat-logs.ndjson", help="Path to the NDJSON log file")
    p.add_argument("--rules", "-r", default="rules.json", help="Path to primary rules JSON file")
    p.add_argument("--display", action="store_true", help="Print matches to the console")
    p.add_argument("--no-display", action="store_true", help="Suppress console output")
    p.add_argument("--output-json", "-o", metavar="FILE", help="Save instances as JSON to FILE")
    p.add_argument("--output-txt", "-t", metavar="FILE", help="Save instances as TXT to FILE")
    args = p.parse_args()

    # Merge new rules if requested and exit
    if args.update_rules:
        save_rules(args.update_rules[0], args.update_rules[1])
        sys.exit(0)
    if not os.path.exists(args.rules):
        print(f"Error: rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)
    
    # Load rules and scan logs
    rules = load_rules(args.rules)
    instances = scan_logs(args.logs, rules)

    # Display results to console with wrapping
    if args.display and not args.no_display:
        if instances:
            print(f"{len(instances)} Privacy instance{'s' if len(instances)!=1 else ''} detected:\n")
            console_width = shutil.get_terminal_size((80, 20)).columns
            indent = ' ' * 4
            val_label = 'Value: '
            rec_label = 'Recommendation: '
            for i, inst in enumerate(instances, start=1):
                print(f"{i:02d}. Rule [{inst['rule']}] (@line {inst['line']}): {inst['description']}")
                wrapped_val = textwrap.fill(
                    inst['value'],
                    width=console_width - len(indent) - len(val_label),
                    initial_indent=indent + val_label,
                    subsequent_indent=indent + ' ' * len(val_label)
                )
                wrapped_val = wrapped_val.replace(indent + val_label,
                                                  indent + val_label + "'", 1) + "'"
                print(wrapped_val)
                if inst.get('recommendation'):
                    wrapped_rec = textwrap.fill(
                        inst['recommendation'],
                        width=console_width - len(indent) - len(rec_label),
                        initial_indent=indent + rec_label,
                        subsequent_indent=indent + ' ' * len(rec_label)
                    )
                    print(wrapped_rec)
                print()
        else:
            print("No instances detected.")

    # Save reports if requested
    if args.output_json:
        save_report_json(instances, args.output_json)
    if args.output_txt:
        save_report_txt(instances, args.output_txt)

    sys.exit(1 if instances else 0)

if __name__ == "__main__":
    main()