# Privacy Application Log Scanner

A Python command‑line tool that scans application logs (Vector‑formatted NDJSON) for privacy‑sensitive data.

## Overview

The Privacy Application Log Scanner tool ingests live application logs collecting from tools such as Vector, Grafana Agent, or FluentBit, applies a JSON‑based rule set, and immediately reports any privacy instances (PII, cookies, endpoints, or error traces) with line numbers and actionable remediation tips. It helps to bring the automation to post-monitoring phase privacy checks and stay compliant with privacy regulations and privacy-by-design principles.

## Key Features

- **Zero‑dependency CLI**  
  Runs in one Python script (`privacy_application_log_scanner.py`) using only the standard library.

- **Configurable JSON Rules**  
  All detection patterns and user recommendations live in `rules.json`. Append new rules on the fly with `--update-rules` (no script edits required).

- **Line-number Mapping**  
  Every reported instance includes `@line N` so that users can view in the application-logs file (`pygoat-logs.ndjson`).

- **Instant, Actionable Reports**  
  Console output and TXT/JSON exports show the rule ID, description, exact NDJSON line number, raw log value, and a clear recommendation on how to remediate.

## Requirements & Design

* **Environment**: Python 3.6 or higher
* **Standard Library**: `os`, `sys`, `json`, `re`, `argparse`, `textwrap`, `shutil`
* **Input**:
  * NDJSON log file (`--logs pygoat-logs.ndjson`)
  * JSON rules file (`--rules rules.json`)
* **Rules**:
  ```json
  [
    {
    "id": "PRIVACY COOKIE",
    "description": "Cookie operation in logs",
    "field": "log",
    "pattern": "(?i)cookie",
    "recommendation": "Do not log full cookie values; log only the cookie name or an anonymized marker."
    }
  ]
  ```
* **Output**:
  * **Console**: `--display`
  * **TXT report**: `--output-txt results.txt`
  * **JSON report**: `--output-json results.json`

## Usage Guide
```bash
# Merge additional rules into primary rules.json
python3 privacy_application_log_scanner.py --update-rules extra_rules.json rules.json

# Quick scan and display results
python3 privacy_application_log_scanner.py --logs pygoat-logs.ndjson --rules rules.json --display

# Save both TXT and JSON results
python3 privacy_application_log_scanner.py --logs pygoat-logs.ndjson --rules rules.json --display --output-json results.json  --output-txt results.txt
```

## Repository Resources

* **Code**: `privacy_application_log_scanner.py`
* **Documentation**: `README.md`

## Resources

1.	"Vector in Action – An Open-Source Tool for Logs and Metrics Collection," Medium, Available:
https://medium.com/@greptime/vector-in-action-an-open-source-tool-for-logs-and-metrics-collection-435e71e076c4
2.	"Vector Documentation - Configuration," Vector.dev, Available:
https://vector.dev/docs/reference/configuration/
3.	"Vector Explained," Better Stack, Available:
https://betterstack.com/community/guides/logging/vector-explained/
4.	"Grafana Agent," Grafana, Available:
https://grafana.com/oss/agent/
5.	"Fluent Bit," GitHub, Available:
https://github.com/fluent/fluent-bit
6.	"What is Fluent Bit?," Fluent Bit Docs, Available:
https://docs.fluentbit.io/manual/about/what-is-fluent-bit
7.	"Vector 0.23.0 Upgrade Guide," Vector.dev, Available:
https://vector.dev/highlights/2022-07-07-0-23-0-upgrade-guide/
8.	"DataWeave Formats - NDJSON," MuleSoft, Available:
https://docs.mulesoft.com/dataweave/latest/dataweave-formats-ndjson
9.	"PyGoat," GitHub, Available:
https://github.com/adeyosemanputra/pygoat
10.	"Sensitive Data Exposure," OWASP Top Ten 2017, Available:
https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
11.	"Article 5 GDPR," GDPR Info, Available:
https://gdpr-info.eu/art-5-gdpr/
12.	"How Long Can Data Be Kept?," European Commission, Available:
https://commission.europa.eu/law/law-topic/data-protection/rules-business-and-organisations/principles-gdpr/how-long-can-data-be-kept-and-it-necessary-update-it_en
13.	"GDPR Article 5: Key Principles and Compliance Best Practices," Exabeam, Available:
https://www.exabeam.com/explainers/gdpr-compliance/gdpr-article-5-key-principles-and-6-compliance-best-practices
14.	"Logging Cheat Sheet," OWASP Cheat Sheet Series, Available:
https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
15.	"Cookie Theft Mitigation Cheat Sheet," OWASP Cheat Sheet Series, Available:
https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html
16.	"Error Handling Cheat Sheet," OWASP Cheat Sheet Series, Available:
https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
17.	"Privacy Framework," NIST, Available:
https://www.nist.gov/privacy-framework


## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.  

© 2025 Dinh Bui. All rights reserved.