# Project Osiris: Defensive Identity Gatekeeper

In Zero-Trust architecture, identity is the new perimeter. Project Osiris is a defensive password evaluation microservice engineered for SOC automation, active-response pipelines, and secure API gateways. 

Much like its namesake weighing the heart before granting passage, Osiris acts as an unforgiving judge of cryptographic entropy—evaluating credentials against strict complexity rules, memory-safe execution standards, and known-leaked breach corpora (via the HaveIBeenPwned k-anonymity API) before allowing authentication traffic to proceed.

## 🛡️ Security Architecture & Mitigations

* **K-Anonymity Leak Detection:** Checks passwords against 900M+ real-world breach records using the HIBP API without ever transmitting the password. It sends only a 5-character SHA-1 prefix over the network and performs constant-time suffix matching locally.
* **Side-Channel Resistance:** Uses `Add-Padding: true` headers in API requests to prevent network observers from deducing prefix bucket sizes based on HTTP response lengths.
* **Algorithmic Efficiency ($O(n)$):** Utilizes Python's C-optimized Unicode layer and lazy generator expressions to evaluate passwords in linear time, avoiding memory-hogging string duplications.
* **Timing Attack Resistance:** Implements OpenSSL's constant-time comparison via `hmac.compare_digest()` for all credential and suffix comparisons, eliminating prefix-timing side-channels.
* **Memory Immutability Awareness:** Designed to mitigate RAM scraping (e.g., process dumps). The validation logic operates directly on the original string reference without generating unnecessary cleartext copies on the heap.
* **Fail-Open & Air-Gap Ready:** Automatically falls back to a local leaked-credential corpus if network errors occur, or can be forced into local-only mode for air-gapped environments.

## 🚀 Usage

### Option A: Python CLI
Run the script directly via terminal.

```bash
# Standard evaluation (Queries HIBP securely)
python3 osiris.py -p "MyP@ssw0rd!"

# Verbose breakdown
python3 osiris.py -p "MyP@ssw0rd!" -v

# Offline / Air-Gapped mode (Skips network API, uses local corpus)
python3 osiris.py -p "MyP@ssw0rd!" -o
```

### Option B: Standalone Executable
For zero-dependency environments, compile the tool using PyInstaller.

```bash
python -m PyInstaller --onefile --name osiris --clean --strip --log-level WARN osiris.py
```

Run the compiled binary:

```bash
./dist/osiris -p "MyP@ssw0rd!" -v
```

## ⚙️ SOC Pipeline & Orchestration Integration

This tool utilizes strict `sys.exit()` codes to communicate seamlessly with orchestration engines like **n8n** or **Wazuh**, acting as an automated gatekeeper.

* `Exit 0`: **STRONG** — Credential meets all complexity requirements and is completely clean in breach databases.
* `Exit 1`: **WEAK/MEDIUM** — Credential failed complexity validation OR was found in a leaked corpus (returns breach counts if online).

### Integration Examples

**Bash / Shell Pipelines:**

```bash
./osiris -p "$USER_INPUT" && echo "Credential Accepted" || echo "Alert: Policy Violation"
```

**Wazuh Active Response (ossec.conf):**

```xml
<command>
    <name>osiris-eval</name>
    <executable>osiris</executable>
    <extra_args>-o</extra_args> 
</command>
<active-response>
    <command>osiris-eval</command>
    <location>local</location>
</active-response>
```

## 👨‍💻 Author
**Omar Elwahy**
Cybersecurity & Networks / Computer Science
