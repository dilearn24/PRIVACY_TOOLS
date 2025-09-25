# Privacy Testing Validator

The **Privacy Testing Validator** is a Python command-line tool that scans running web applications for privacy compliance issues during the **Testing phase** of the Software Development Life Cycle (SDLC). It executes a suite of automated checks (PII leakage, cookie practices, headers, forms, opt-out mechanisms, and more) to validate **Privacy-by-Design (PbD)** principles and regulatory requirements such as **GDPR, CCPA, and HIPAA**.

This tool helps bridge the gap between static analysis in development and manual audits in production by providing automated, reproducible privacy validation of live endpoints.

## Overview

- **Rules-Driven:** All detection patterns and user recommendations live in `rules.json`. Append new rules on the fly with `--update-rules` (no script edits required).  
- **Quantitative Metrics:** Reports counts of findings (e.g., missing headers, skipped endpoints, insecure cookies).  
- **Actionable Results:** Outputs both console results and structured TXT/JSON files with remediation guidance.  
- **Docker-Ready:** Packaged as a container for easy integration into CI/CD pipelines.  

## Key Features

- Detects **PII/PHI leakage** in response bodies  
- Validates presence of required **privacy/security headers**  
- Ensures no **cookies are set before consent**  
- Checks that **forms avoid over-collection** of sensitive data  
- Flags missing **opt-out mechanisms** (unsubscribe, “Do Not Sell”)  
- Validates **breach notification references** in privacy policies  
- Confirms **no debug/stack traces** are exposed in responses  
- Extended rules cover **cookie flags, no-store on sensitive pages, CSRF tokens, CORS policy, and server fingerprint minimization**  

## Requirements & Design

* **Rules-based architecture:** Detection patterns and recommendations live in `rules.json`.
* **Quantitative metrics:** Designed for mixed-methods research with both numerical counts and qualitative insights.
* **Consistency:** Aligns with other privacy scanning tools in this project (e.g., Privacy Application Log Scanner).
- **Environment:** 3.6 or higher  
- **Libraries:** `requests`, `json`, `re`, `argparse` (standard and lightweight dependencies)  
- **Containerized run:** via Docker  

## Input

- **Target base URL:** e.g., `http://localhost:8000` (set with `-e PRIVACY_TEST_BASE_URL`)  
- **Rules file:** `rules.json`  

## Output

- **Console:** immediate PASS/FAIL summary  
- **TXT report:** `out/privacy_test_results.txt`  
- **JSON report:** `out/privacy_test_results.json`  

## Example of Output:

```
Privacy Testing Validator – Results
Total: 15  Passed: 9  Failed: 5  Manual: 1  Pass rate: 60.0%
------------------------------------------------------------

\[FAIL] test\_privacy\_headers\_present – Privacy/security headers missing: 4
\[FAIL] test\_no\_store\_on\_sensitive\_paths – Non-compliant: 4
\[PASS] test\_no\_pii\_leakage – Items: 0  Skipped\_non200: 9

```

## Usage Guide

### Build the container
```bash
docker build -t privacy-validator -f Dockerfile.validator .
```

### Run against a local app (example: PyGoat on port 8000)

```bash
docker run --rm --add-host=host.docker.internal:host-gateway -e PRIVACY_TEST_BASE_URL=http://host.docker.internal:8000 -v "$PWD/out":/app/out -v "$PWD/rules.json":/app/rules.json:ro privacy-validator
```

### Update rules on the fly

```bash
python3 privacy_testing_validator.py --update-rules extra_rules.json rules.json
```

## Repository Resources

* **Code:** `privacy_testing_validator.py`
* **Documentation:** `README.md`

## Resources

1. "General Data Protection Regulation (GDPR)," GDPR Info, Available: [https://gdpr-info.eu](https://gdpr-info.eu)
2. "California Consumer Privacy Act (CCPA)," State of California, Available: [https://oag.ca.gov/privacy/ccpa](https://oag.ca.gov/privacy/ccpa)
3. "HIPAA Privacy Rule," U.S. Department of Health & Human Services, Available: [https://www.hhs.gov/hipaa/for-professionals/privacy/index.html](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
4. "Privacy by Design," Information and Privacy Commissioner of Ontario, Available: [https://www.ipc.on.ca/privacy/privacy-by-design/](https://www.ipc.on.ca/privacy/privacy-by-design/)
5. "OWASP Secure Headers Project," OWASP, Available: [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)
6. "OWASP Top Ten – Sensitive Data Exposure," OWASP, Available: [https://owasp.org/www-project-top-ten/2017/A3\_2017-Sensitive\_Data\_Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
7. "NIST Privacy Framework," NIST, Available: [https://www.nist.gov/privacy-framework](https://www.nist.gov/privacy-framework)
8. "PyGoat Project," GitHub, Available: [https://github.com/adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat)
9. "Docker Run Reference," Docker Documentation, Available: [https://docs.docker.com/reference/cli/docker/container/run/](https://docs.docker.com/reference/cli/docker/container/run/)
10. "Docker Build Reference," Docker Documentation, Available: [https://docs.docker.com/build/](https://docs.docker.com/build/)

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.  

© 2025 Dinh Bui. All rights reserved.