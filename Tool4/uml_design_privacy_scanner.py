"""
uml_design_privacy_scanner.py

Scan a Modelio-exported UML/C4 XMI model (edtrack.xmi).
Rules defined in a JSON file using privacy-by-design principles.
Supports updating the rule JSON file by appending new rules without duplicates.
Reports “instances” of:
    - missing DataStore/DataFlow privacy entity in Nodes and Information Flows (@line)
    - rule-mismatches on annotated stores and flows (@line)
Includes line-number mapping to locate the exact spot in the XMI file.
Save the scan results as JSON and TXT.
"""

import sys, os
import argparse
import json
import re
import xml.etree.ElementTree as ET

# Strip XML namespace prefix from a tag or attribute name
def strip_ns(tag):
    return tag.split('}',1)[-1] if '}' in tag else tag

# Find the 1-based index of the first line in list_of_strings containing substring
def find_line(list_of_strings, substring):
    for idx, line in enumerate(list_of_strings, 1):
        if substring in line:
            return idx
    return None

# Retrieve the first attribute value that has localname is “id”
def get_id(attrib):
    for key, val in attrib.items():
        if strip_ns(key) == 'id':
            return val
    return None

# Parse the XMI model and return DataStore/Flow annotations and any missing privacy entity
def load_model_xmi(path):
    raw  = open(path, encoding='utf-8').read().splitlines()
    tree = ET.parse(path)
    root = tree.getroot()

    elements = {}
    for pe in root.iter():
        if strip_ns(pe.tag) != 'packagedElement':
            continue
        eid = get_id(pe.attrib)
        if not eid:
            continue
        etype = pe.get('xmi:type') or pe.get('{http://schema.omg.org/spec/XMI/2.1}type','')
        name  = pe.get('name','<unnamed>')
        elements[eid] = {'type':etype, 'name':name}

    stores, flows = [], []
    applied_s, applied_f = set(), set()

    for ann in root.iter():
        tag = strip_ns(ann.tag)
        if tag not in ('DataStore','DataFlow'):
            continue

        bases = [v for k,v in ann.attrib.items() if k.startswith('base_')]
        if not bases:
            continue
        base_id = bases[0]

        et = elements.get(base_id,{}).get('type','')
        if tag=='DataStore' and not et.endswith('Node'):
            continue
        if tag=='DataFlow'  and not et.endswith('InformationFlow'):
            continue

        attrs = {
            k:v for k,v in ann.attrib.items()
            if strip_ns(k)!='id' and not k.startswith('base_')
        }

        sid   = get_id(ann.attrib)
        line  = find_line(raw, f'id="{sid}"')
        name  = elements.get(base_id,{}).get('name','<unnamed>')

        rec = {'id':base_id, 'name':name, 'attrs':attrs, 'line':line}
        if tag=='DataStore':
            stores.append(rec);   applied_s.add(base_id)
        else:
            flows.append(rec);    applied_f.add(base_id)

    missing_s, missing_f = [], []
    for eid, info in elements.items():
        etype, name = info['type'], info['name']
        line = find_line(raw, f'id="{eid}"')
        if etype.endswith('Node') and eid not in applied_s:
            missing_s.append({'name':name,'line':line,'rule':'missing_datastore','target':'store'})
        if etype.endswith('InformationFlow') and eid not in applied_f:
            missing_f.append({'name':name,'line':line,'rule':'missing_dataflow','target':'flow'})

    return stores, flows, missing_s, missing_f

# Load the list of privacy rules from a JSON file
def load_rules(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)

# Merge new rules from one JSON into another, skipping duplicates by “id”
def save_rules(src, dst):
    new = load_rules(src)
    old = load_rules(dst) if os.path.exists(dst) else []
    seen = {r['id'] for r in old}
    added = 0
    for r in new:
        if r['id'] not in seen:
            old.append(r); added += 1
    with open(dst, 'w', encoding='utf-8') as f:
        json.dump(old, f, indent=2)
    print(f"Appended {added} rule(s) to {dst}")

# Check that all key to regex pairs in condition fully match the element’s attributes
def check_condition(attrs, cond):
    for key, patt in cond.items():
        val = str(attrs.get(key,'')) 
        if not re.fullmatch(str(patt), val):
            return False
    return True

# Apply each rule to its target elements and collect any mismatches
def detect_instances(stores, flows, rules):
    inst = []
    for r in rules:
        pool = stores if r['target']=='store' else flows
        cond = r.get('condition',{})
        raw_dt = cond.get('dataType')
        is_plain = bool(raw_dt and re.fullmatch(r'[A-Za-z0-9_]+', raw_dt))

        for e in pool:
            if is_plain and e['attrs'].get('dataType') != raw_dt:
                continue
            if not check_condition(e['attrs'], cond):
                inst.append({
                    'rule':        r['id'],
                    'target':      r['target'],
                    'name':        e['name'],
                    'line':        e['line'],
                    'condition':   cond,
                    'attrs':       e['attrs'],
                    'description': r.get('description','')
                })
    return inst

# Build the report string from missing and mismatches
def build_report_text(missing_s, missing_f, mismatches):
    lines = []
    total_missing = len(missing_s) + len(missing_f)
    lines.append(f"*** {total_missing} missing DataStore/DataFlow detected:\n")
    for i, m in enumerate(missing_f + missing_s, 1):
        lines.append(f"{i}. Rule [{m['rule']}] on {m['target']} “{m['name']}” (@line {m['line']})")
    lines.append("")
    lines.append(f"*** {len(mismatches)} applied privacy instance(s) are detected:\n")
    for i, v in enumerate(mismatches, 1):
        req = ", ".join(f"{k}={p}" for k, p in v['condition'].items()) or "<none>"
        pres = ", ".join(
            f"{k}={v['attrs'].get(k, '<missing>')}"
            for k in sorted(v['attrs'].keys())
        ) or "<none>"

        lines.append(f"{i}. Rule [{v['rule']}] on {v['target']} “{v['name']}” (@line {v['line']})")
        lines.append(f"   Required: {req}")
        lines.append(f"   Present:  {pres}")
        if v.get('description'):
            lines.append(f"   Description: {v['description']}")
        lines.append("")

    return "\n".join(lines)

# Main entrypoint for parsing args, run scan/update-rules, save outputs, and displaying the results
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--update-rules", nargs=2, metavar=("SRC","DST"), help="Merge new rules into your ruleset")
    p.add_argument("-m","--model", help="Path to edtrack.xmi")
    p.add_argument("-r","--rules", default="design_privacy_rules.json", help="Path to rules JSON file")
    p.add_argument("-o","--output-json", metavar="FILE", help="Save scan results as JSON")
    p.add_argument("-t","--output-txt", metavar="FILE", help="Save scan results as TXT")
    p.add_argument("--display", action="store_true", help="Print the report")
    p.add_argument("--no-display", action="store_true", help="Suppress console output when combined")
    args = p.parse_args()

    # Update‐rules mode
    if args.update_rules:
        save_rules(*args.update_rules)
        sys.exit(0)

    # Validate inputs
    if not args.model or not os.path.exists(args.model):
        print("Error: valid --model required", file=sys.stderr); sys.exit(1)
    if not os.path.exists(args.rules):
        print("Error: rules file not found", file=sys.stderr); sys.exit(1)

    # Load model and rules
    stores, flows, missing_s, missing_f = load_model_xmi(args.model)
    ruleset  = load_rules(args.rules)
    mismatches = detect_instances(stores, flows, ruleset)

    # Prepare result
    result = {"missing": missing_f + missing_s, "mismatches": mismatches}

    # Output JSON
    if args.output_json:
        with open(args.output_json, 'w', encoding='utf-8') as jf:
            json.dump(result, jf, indent=2)
        print(f"Saved JSON results to {args.output_json}")

    # Output TXT
    if args.output_txt:
        report_txt = build_report_text(missing_s, missing_f, mismatches)
        with open(args.output_txt, 'w', encoding='utf-8') as tf:
            tf.write(report_txt)
        print(f"Saved TXT report to {args.output_txt}")

    # Display on console
    if args.display and not args.no_display:
        print(build_report_text(missing_s, missing_f, mismatches))

    sys.exit(1 if (missing_s or missing_f or mismatches) else 0)

if __name__ == "__main__":
    main()