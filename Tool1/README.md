# Privacy Compliance Scanner

An interactive Python tool for detecting privacy-sensitive identifiers in source code, aligned with GDPR and CCPA standards.

## Overview

The Privacy Compliance Scanner is a python command-line application that scans source code for potentially exposed personally identifiable information (PII) and protected health information (PHI). It supports Python, C/C++, Java, and JavaScript and generates actionable, numbered reports.

## Key Features

* **Multi-Language Scanning**: Single Python script covers `.py`, `.c/.cpp/.h`, `.java`, and `.js` files.
* **Interactive Menu**: Scan directories, load custom patterns, review numbered results, export JSON or text reports.
* **Regulation-Aligned Patterns**: Default rules map to GDPR and CCPA categories; easily extendable via JSON for HIPAA, LGPD, and more.
* **Comment Stripping**: Automatically removes inline and full-line comments to reduce false positives.

## Requirements & Design

* **Environment**: Python 3.6 or higher, using standard library modules (`os`, `re`, `json`, `sys`).
* **Modular Architecture**: Organized functions for file scanning (`scan_file`), directory traversal (`scan_directory`), comment stripping, pattern loading, and report generation. See image below for directory of the tool.
  
  ![image](https://github.com/user-attachments/assets/f3954a6e-3d0f-40fb-a4b7-aa9e3fb074f0)

* **Interactive CLI**: Menu-driven interface for scanning code, loading custom patterns, reviewing results, and exporting reports without complex flags.
* **Configurable Patterns**: JSON-based pattern files allow easy extension to additional privacy regulations (GDPR, CCPA, HIPAA, LGPD, etc.).
* **Multi-Language Support**: Automatic detection of file types by extension (`.py`, `.c`, `.cpp`, `.cc`, `.h`, `.hpp`, `.java`, `.js`) to apply comprehensive privacy checks.
* **Comment Suppression**: Inline (`//`) and full-line comment (`#`) removal logic ensures accurate matching by ignoring non-code text.
* **Reporting Options**: Generates numbered console listings, JSON output, and plain-text export for integration with code reviews, CI/CD pipelines, or dashboards.

## Usage Guide

Run the scanner:

```bash
python3 privacy_compliance_scanner.py
```

Choose an option:
```bash
===== Privacy Compliance Scanner ======
1) Scan code directory
2) Load custom patterns from JSON
3) View last scan report
4) Save report to JSON file
5) Save report to TXT file
6) Exit
```
Example:

Run as seen in the images below:

![image](https://github.com/user-attachments/assets/d5c6dbbf-0400-4b03-8c96-ec238fb1f072)

![image](https://github.com/user-attachments/assets/bd07a3a3-2a42-4c8b-8456-28953fcd8693)

![image](https://github.com/user-attachments/assets/1514c72d-e50a-4789-8cd2-adab38ded19c)

## Configuration and Patterns

Default patterns cover GDPR and CCPA categories. To add or override the default patterns:

1. Create a `patterns.json` with your custom rules:

   ```json
   [
     { "pattern": "\\b(patient_id|mrn|medical_record_number|record_number)\\b", "description": "PHI: medical record number" },
     { "pattern": "\\b(ssn|social_security_number)\\b", "description": "PHI: Social Security Number"}
   ]
   ```
2. In the menu, choose option 2 **Load custom patterns from JSON** and enter the path to your JSON file. It will scan using the custom patterns as shown below.
   
   ![image](https://github.com/user-attachments/assets/828f8b35-2026-47ae-a537-187d7a239ba0)

   ![image](https://github.com/user-attachments/assets/b01f7f3b-f237-4447-a0fd-f8d6c78cd579)

## Repository Resources

* **Code**: `privacy_compliance_scanner.py`
* **Documentation**: `README.md`
  
## Resources

1. “General Data Protection Regulation (GDPR) – legal text,” General Data Protection Regulation (GDPR), Apr. 22, 2024. Available: [https://gdpr-info.eu/](https://gdpr-info.eu/)
2. “California Consumer Privacy Act (CCPA),” State of California - Department of Justice - Office of the Attorney General, Jan. 28, 2025. Available: [https://oag.ca.gov/privacy/ccpa](https://oag.ca.gov/privacy/ccpa)
3. O. for C. Rights, “The HIPAA privacy rule,” HHS.gov, Sep. 27, 2024. Available: [https://www.hhs.gov/hipaa/for-professionals/privacy/index.html](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
4. “Brazilian General Data Protection Law (LGPD, English translation),” Oct. 01, 2020. Available: [https://iapp.org/resources/article/brazilian-data-protection-law-lgpd-english-translation/](https://iapp.org/resources/article/brazilian-data-protection-law-lgpd-english-translation/)
5. “re — Regular expression operations,” Python Documentation. Available: [https://docs.python.org/3/library/re.html](https://docs.python.org/3/library/re.html)
6. Atlassian, “Continuous integration vs. delivery vs. deployment | Atlassian,” Atlassian. Available: [https://www.atlassian.com/continuous-delivery/principles/continuous-integration-vs-delivery-vs-deployment](https://www.atlassian.com/continuous-delivery/principles/continuous-integration-vs-delivery-vs-deployment)
7. “Privacy is an afterthought in the software lifecycle. That needs to change. - Stack Overflow,” Jul. 19, 2021. Available: [https://stackoverflow.blog/2021/07/19/privacy-is-an-afterthought-in-the-software-lifecycle-that-needs-to-change/](https://stackoverflow.blog/2021/07/19/privacy-is-an-afterthought-in-the-software-lifecycle-that-needs-to-change/)
8. M. Tahaei, K. Vaniea, and A. Rashid, “Embedding privacy into design through software developers: Challenges and solutions,” IEEE Security & Privacy, vol. 21, no. 1, pp. 49–57, Sep. 2022. Available: [https://doi.org/10.1109/msec.2022.3204364](https://doi.org/10.1109/msec.2022.3204364)
