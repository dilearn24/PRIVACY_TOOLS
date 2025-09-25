"""
privacy_thread_model_scanner.py

Scan Threat Data Flow Diagram (DFD) Model JSON (exported from OWASP Threat Dragon tool).
Rules defined in a JSON file using privacy regulation. 
Supports updating the rule JSON file by appending new rules without duplicates.
Reports “instances” of missing privacy controls in flows and stores (annotated with @line).
Includes line-number mapping to find the exact spot in threat model JSON file.
"""

import json
import sys
import argparse
import os

# Parse key=value lines from a Description field of model file (edtrack-model.json) into a dict
def parse_kv(s):
    out = {}
    for line in s.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out

# Read the model file, record line numbers for each cell, and separate nodes vs flows
def load_model(path):
    with open(path, 'r') as f:
        raw_lines = f.readlines()
    def find_line(cell_id):
        needle = f'"id": "{cell_id}"'
        for idx, line in enumerate(raw_lines, start=1):
            if needle in line:
                return idx
        return None
    model = json.loads(''.join(raw_lines))
    diagrams = model.get('detail', {}).get('diagrams', [])
    if not diagrams:
        return [], []
    cells = diagrams[0].get('cells', [])
    nodes, flows = [], []
    for c in cells:
        data = c.get('data', {})
        line_no = find_line(c.get('id'))
        if 'source' in c and 'target' in c:
            flows.append({
                'id':            c.get('id'),
                'name':          data.get('name', ''),
                'descr':         data.get('description', ''),
                'encrypted':     data.get('isEncrypted', False),
                'publicNetwork': data.get('isPublicNetwork', False),
                'protocol':      data.get('protocol', ''),
                'line':          line_no
            })
        else:
            nodes.append({
                'id':        c.get('id'),
                'name':      data.get('name', ''),
                'descr':     data.get('description', ''),
                'encrypted': data.get('isEncrypted', False),
                'isALog':    data.get('isALog', False),
                'signed':    data.get('isSigned', False),
                'line':      line_no
            })

    return nodes, flows

# Load rules from a rule JSON file.
def load_rules(path):
    return json.load(open(path))

# Append rules from one JSON file into another, skipping duplicates
def save_rules(src, dst):
    new_rules = load_rules(src)
    existing = load_rules(dst) if os.path.exists(dst) else []
    ids = {r['id'] for r in existing}
    added = 0
    for r in new_rules:
        if r['id'] not in ids:
            existing.append(r)
            added += 1
    with open(dst, 'w') as f:
        json.dump(existing, f, indent=2)
    print(f"Appended {added} new rule(s) to {dst}")

# Check if a given attribute dict satisfies a rule’s condition
def check_condition(attrs, cond):
    for k, v in cond.items():
        if v == "exists":
            if k not in attrs or not attrs[k]:
                return False
        else:
            if str(attrs.get(k)) != str(v):
                return False
    return True

# Apply all rules to flows and stores, collect any unmet instances
def detect(nodes, flows, rules):
    instances = []
    stores = {n['id']: n for n in nodes if 'Store' in n['name']}
    for rule in rules:
        tgt, cond = rule['target'], rule['condition']
        if tgt == 'flow':
            for f in flows:
                attrs = parse_kv(f['descr'])
                attrs.update({
                    'encrypted':     'true' if f['encrypted'] else 'false',
                    'publicNetwork': 'true' if f['publicNetwork'] else 'false',
                    **({'protocol': f['protocol']} if f['protocol'] else {})
                })
                if 'data_type' in cond and attrs.get('data_type') != cond['data_type']:
                    continue
                if not check_condition(attrs, cond):
                    instances.append({
                        'rule':      rule['id'],
                        'target':    'flow',
                        'name':      f['name'],
                        'line':      f['line'],
                        'condition': cond,
                        'attrs':     attrs
                    })
        elif tgt == 'store':
            for n in stores.values():
                attrs = parse_kv(n['descr'])
                attrs.update({
                    'encrypted': 'true' if n['encrypted'] else 'false',
                    'isALog':    'true' if n['isALog'] else 'false',
                    'signed':    'true' if n['signed'] else 'false'
                })
                if 'sensitivity' in cond and attrs.get('sensitivity') != cond['sensitivity']:
                    continue
                if not check_condition(attrs, cond):
                    instances.append({
                        'rule':      rule['id'],
                        'target':    'store',
                        'name':      n['name'],
                        'line':      n['line'],
                        'condition': cond,
                        'attrs':     attrs
                    })
    return instances

# Save instances to a JSON file
def save_report_json(instances, path):
    json.dump(instances, open(path, 'w'), indent=2)
    print(f"JSON report saved to {path}")

# Save instances to a TXT file using the display format
def save_report_txt(instances, path):
    """
    Write the privacy instances to a TXT file using the same format as --display.
    """
    with open(path, 'w') as f:
        if instances:
            total = len(instances)
            f.write(f"{total} Privacy instance{'s' if total!=1 else ''} detected:\n")
            for i, inst in enumerate(instances, 1):
                f.write(f"{i}. Rule [{inst['rule']}] failed on {inst['target']} “{inst['name']}” (@line {inst['line']}):\n")
                req = ", ".join(
                    f"{k}={v}" if v=="exists" else f"{k}={v}"
                    for k, v in inst['condition'].items()
                )
                f.write(f"  - Required: {req}\n")
                pres = ", ".join(
                    f"{k}={inst['attrs'][k]}" for k in sorted(inst['attrs'].keys())
                )
                f.write(f"  - Present:  {pres}\n\n")
        else:
            f.write("No instances detected.\n")
    print(f"TXT report saved to {path}")

# Main entrypoint for parsing args, handling update-rules, running scan, displaying the results
def main():
    parser = argparse.ArgumentParser(
        prog="privacy_thread_model_scanner.py",
        description="Scan a Threat Dragon DFD JSON for privacy-rule instances (with line numbers)."
    )
    parser.add_argument("--update-rules", nargs=2, metavar=("SRC", "DST"),
                        help="Append rules from SRC into DST")
    parser.add_argument("--model", "-m", help="Threat Dragon JSON model to scan")
    parser.add_argument("--rules", "-r", default="rules.json", help="Rules JSON file")
    parser.add_argument("--display", action="store_true", help="Print instances to console")
    parser.add_argument("--no-display", action="store_true", help="Suppress console output")
    parser.add_argument("--output-json", "-o", metavar="FILE", help="Save instances as JSON to FILE")
    parser.add_argument("--output-txt", "-t", metavar="FILE", help="Save instances as TXT to FILE")
    args = parser.parse_args()

    # Append new rules
    if args.update_rules:
        save_rules(args.update_rules[0], args.update_rules[1])
        sys.exit(0)

    # Validate inputs
    if not args.model:
        print("Error: --model is required", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.rules):
        print(f"Error: rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)

    # Load and scan
    nodes, flows = load_model(args.model)
    ruleset = load_rules(args.rules)
    instances = detect(nodes, flows, ruleset)

    # Display on console
    if args.display and not args.no_display:
        if instances:
            print(f"{len(instances)} Privacy instance{'s' if len(instances)!=1 else ''} detected:")
            for i, inst in enumerate(instances, 1):
                print(f"{i}. Rule [{inst['rule']}] failed on {inst['target']} “{inst['name']}” (@line {inst['line']}):")
                # Ensure the key is present and non‐empty (e.g., “timestamp" keywork must exist)
                req = ", ".join(f"{k}={v}" if v=="exists" else f"{k}={v}"
                                for k, v in inst['condition'].items())
                print(f"  - Required: {req}")
                pres = ", ".join(f"{k}={inst['attrs'][k]}" for k in sorted(inst['attrs'].keys()))
                print(f"  - Present:  {pres}")
                print()
        else:
            print("No instances detected.")

    # Save reports
    if args.output_json:
        save_report_json(instances, args.output_json)
    if args.output_txt:
        save_report_txt(instances, args.output_txt)

    sys.exit(1 if instances else 0)

if __name__ == "__main__":
    main()