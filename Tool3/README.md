# Privacy Threat Model Scanner

A Python command-line tool that quickly detects missing privacy controls in OWASP Threat Dragon data-flow diagrams (DFD).

## Overview

The Privacy Threat Model Scanner ingests the Threat Dragon JSON export, extracts metadata from each data flow and data store (encryption flags, retention policies, timestamps, etc.), and applies rules defined in a simple rules.json file to detect any missing controls. Users can append new rules without the script edits required.

## Key Features

- **Zero-dependency CLI**  
  Runs in one Python script (`privacy_thread_model_scanner.py`) using only the standard library.

- **Configurable JSON Rules**  
  Define the privacy-by-design or regulatory checks in `rules.json`. Append new rules on the fly with `--update-rules` (no script edits required).  

- **Line-number Mapping**  
  Every instance includes `@line N` that help users easily go straight to the offending cell in their `name-model.json` export.

- **Actionable, Numbered Reports**  
  Console output and TXT/JSON exports show “Required vs Present” for each missing control, prefaced by a numbered list and total count for easy triage.

## Requirements & Design

- **Environment**:  Python 3.6 or higher, using standard library modules (`os`, `json`, `sys`, `argparse`).
- **Input**:  
  - A Threat Dragon JSON export (`--model name-model.json`)  
  - A JSON rules file (`--rules rules.json`)  
- **Rules**:  
  ```json
  [
    {
        "id": "PII_IN_TRANSIT",
        "target": "flow",
        "condition": {
        "data_type": "personal_data",
        "encrypted": "true"
        }
    }
  ]
  ```
- **Output**:
  - Console (`--display`) with numbered instances,
  - Plain-text report (`--output-txt report.txt`),
  - JSON report (`--output-json report.json`).

## Usage Guide
```bash
# Append new rules into the default rules.json
python3 privacy_thread_model_scanner.py --update-rules new_rules.json rules.json

# Scan the DFD for missing privacy controls
python3 privacy_thread_model_scanner.py --model name-model.json --rules rules.json --display --output-txt report.txt --output-json report.json
```
## Repository Resources

* **Code**: `privacy_thread_model_scanner.py`
* **Documentation**: `README.md`

## Resources

1.	"OWASP Threat Model," OWASP, Available:
https://owasp.org/www-project-threat-model/
2.	"Threat Modeling," OWASP, Available:
https://owasp.org/www-community/Threat_Modeling
3.	"Threat Modeling Process," OWASP, Available:
https://owasp.org/www-community/Threat_Modeling_Process
4.	"Home Lab Threat Modeling with OWASP Threat Dragon," Medium, Available:
https://medium.com/@iamblacklight/home-lab-threat-modeling-with-owasp-threat-dragon-f985be261597
5.	"Threat Modeling with OWASP Threat Dragon – Part 2," Medium, Available:
https://medium.com/@iamblacklight/threat-modeling-with-owasp-threat-dragon-part-2-d0196a9bb545
6.	"GDPR Article 5," GDPR Info, Available:
https://gdpr-info.eu/art-5-gdpr/
7.	"Article 5 GDPR," GDPRhub, Available:
https://gdprhub.eu/Article_5_GDPR
8.	"Data Minimisation," ICO, Available:
https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/data-minimisation/
9.	"Article 5 GDPR," GDPR Text, Available:
https://gdpr-text.com/sv/read/article-5/?lang1=en
10.	"De-identification under HIPAA," HHS, Available:
https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html
11.	"45 CFR §164.514 - Other requirements relating to uses and disclosures of protected health information," Cornell Law School, Available:
https://www.law.cornell.edu/cfr/text/45/164.514
12.	"GDPR Article 5 Compliance," ISMS.online, Available:
https://www.isms.online/general-data-protection-regulation-gdpr/gdpr-article-5-compliance/
13.	"California Consumer Privacy Act (CCPA)," State of California DOJ, Available:
https://oag.ca.gov/privacy/ccpa
14.	"CCPA Requirements," CookieYes, Available:
https://www.cookieyes.com/blog/ccpa-requirements/
15.	"Principles of Data Protection," Data Protection Commission, Available:
https://www.dataprotection.ie/en/individuals/data-protection-basics/principles-data-protection
16.	"Understanding the 6 Data Protection Principles," IT Governance, Available:
https://www.itgovernance.eu/blog/en/the-gdpr-understanding-the-6-data-protection-principles
17.	"AC-3: Access Enforcement," NIST SP 800-53, Available:
https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-3/
18.	"AU-3: Content of Audit Records," NIST SP 800-53, Available:
https://csf.tools/reference/nist-sp-800-53/r4/au/au-3/

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.  

© 2025 Dinh Bui. All rights reserved.