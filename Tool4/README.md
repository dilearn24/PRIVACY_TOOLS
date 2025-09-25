# UML Design Privacy Scanner
A Python command-line tool that scans design diagrams for privacy controls.

## Overview

The UML Design Privacy Scanner is a lightweight Python CLI tool that parses UML diagrams of design modeling tools (such as Modelio, Eclipse Papyrus, or Visual Paradigm), extracts privacy metadata controls from each Data Store and Data Flow (encryption flags, retention periods, purposes, etc.), and evaluates them against a privacy JSON rule set. It instantly flags missing privacy entities and misconfigured elements, bringing the automation to design phase privacy checks and ensuring compliance with GDPR, CCPA, HIPAA, and Privacy-by-Design principles.


## Key Features

- **Zero-dependency CLI**  
  Runs as a single script (`uml_design_privacy_scanner.py`) using only the Python standard library.

- **Configurable JSON Rules**  
  Define privacy-by-design or regulatory checks in `design_privacy_rules.json`.  
  Merge new rules via `--update-rules` without touching Python script.

- **Line-number Mapping**  
  Every reported instance includes `@line N` so that users can go straight to the XMI element in design modeling tools .

- **Actionable, Numbered Reports**  
  Console output, TXT and JSON exports all show a numbered list of missing privacy entities and rule-flags with “Required vs Present” details for easy triage.

## Requirements & Design

- **Environment**:  Python 3.6 or higher, using standard library modules (`os`, `sys`, `json`, `argparse`,`re`, `xml.etree.ElementTree`).
- **Input**:  
  - A Modelio UML XMI export (`--model edtrack.xmi`)  
  - A JSON rules file (`--rules design_privacy_rules.json`)  
- **Rules**: 
  ```json
  [
   {
    "id": "require_encrypt_store",
    "target": "store",
    "description": "All DataStores must have isEncrypted=true",
    "condition": {
      "isEncrypted": "true"
    }
  }
  ]
  ```
- **Output**:
  - Console (`--display`) with numbered instances,
  - Plain-text report (`--output-txt results.txt`),
  - JSON report (`--output-json results.json`).

## Usage Guide
```bash
# Append new rules into the default rules.json
python3 uml_design_privacy_scanner.py --update-rules extra_rules.json design_privacy_rules.json 

# Scan the uml design diagram for missing privacy controls
python3 uml_design_privacy_scanner.py --model edtrack.xmi --rules design_privacy_rules.json --display --output-json results.json --output-txt  results.txt
```
## Repository Resources

* **Code**: `uml_design_privacy_scanner.py`
* **Documentation**: `README.md`

## Resources

1.	"What is UML?," Visual Paradigm, Available:
https://www.visual-paradigm.com/guide/uml-unified-modeling-language/what-is-uml/
2.	"About UML 2.5," Object Management Group (OMG), Available:
https://www.omg.org/spec/UML/2.5/About-UML
3.	"C4 Model," C4 Model, Available:
https://c4model.com/
4.	"Comparison of C4 Model vs UML," IcePanel, Available:
https://icepanel.io/blog/2024-07-29-comparison-c4-model-vs-uml
5.	"Text UML Tools – Complete List," Modeling Languages, Available:
https://modeling-languages.com/text-uml-tools-complete-list/
6.	"Principles of Data Protection," Data Protection Commission, Available:
https://www.dataprotection.ie/en/individuals/data-protection-basics/principles-data-protection
7.	"The Seven Principles of Privacy by Design," Carbide Secure, Available:
https://carbidesecure.com/resources/the-seven-principles-of-privacy-by-design/
8.	"Modelio," GitHub, Available:
https://github.com/ModelioOpenSource/Modelio
9.	"Modelio Quick Start Guide," GitHub, Available:
https://github.com/ModelioOpenSource/Modelio/wiki/Quick-Start-Guide
10.	"Cryptographic Storage Cheat Sheet," OWASP Cheat Sheet Series, Available:
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
11.	"Sensitive Data Exposure," OWASP Top Ten 2017, Available:
https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
12.	"REST Security Cheat Sheet," OWASP Cheat Sheet Series, Available:
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
13.	"Article 5 GDPR," GDPR Info, Available:
https://gdpr-info.eu/art-5-gdpr/
14.	"How Long Can Data be Kept?," European Commission, Available:
https://commission.europa.eu/law/law-topic/data-protection/rules-business-and-organisations/principles-gdpr/how-long-can-data-be-kept-and-it-necessary-update-it_en
15.	"GDPR Article 5: Key Principles and Compliance Best Practices," Exabeam, Available:
https://www.exabeam.com/explainers/gdpr-compliance/gdpr-article-5-key-principles-and-6-compliance-best-practices
