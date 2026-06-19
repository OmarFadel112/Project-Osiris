# 🔧 Pipeline Integration Guide

Project Osiris is designed to operate as a headless microservice within broader security orchestration workflows.

## Integrating with n8n

When using Osiris in an n8n workflow, utilize the **Execute Command** node.

1. **Node Setup:** Add an `Execute Command` node to your workflow.
2. **Command:** Point the node to the compiled binary or the Python script.
   ```bash
   # Standard online check
   /path/to/dist/osiris -p "{{ $json.password_input }}"
   
   # Or, if your n8n worker is in an air-gapped subnet:
   /path/to/dist/osiris -p "{{ $json.password_input }}" --offline
   ```
3. **Routing:** * n8n automatically captures the exit code of the executed command.
   * Add a `Switch` or `If` node immediately after.
   * Condition: If `exitCode == 0`, route to your "Account Creation" or "Allow" branch.
   * Condition: If `exitCode == 1`, route to your "Slack Alert" or "Reject" branch.

## Integrating with Python Gateways

If you are building a custom Zero-Trust API gateway in Python, you can import the core logic directly without the CLI overhead.

```python
from password_strength import PasswordStrengthChecker, HIBPChecker, check_password

# OPTION 1: Full protection (Online HIBP check with fallback)
checker = PasswordStrengthChecker(hibp_checker=HIBPChecker())
report = checker.check(user_input)

# OPTION 2: Functional Offline Wrapper (No network calls)
# report = check_password(user_input)

if not report.is_acceptable():
    # Log the specific failures for auditing
    print(f"Policy violations: {report.failed_checks}")
    
    # Check if it was rejected specifically due to a leak
    if report.is_leaked:
        print(f"CRITICAL: Identity in breach corpus. Seen {report.breach_count} times.")
        
    return {"status": "403 Forbidden", "reason": "Weak or Compromised Identity Credential"}
```