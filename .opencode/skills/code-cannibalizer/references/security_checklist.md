# Security Checklist

Security patterns to detect when scanning repositories.

## Critical Issues

### Code Injection
- `eval()` with base64 or encoded input
- `exec()` with dynamic code
- `__import__()` with variable module names
- `subprocess` with `shell=True`
- `os.system()` with variable input

### Remote Code Execution
- `curl | bash` patterns
- `wget | sh` patterns
- Dynamic import from user-controlled URLs

### Data Destruction
- `rm -rf /` or similar recursive deletes
- Unbounded file operations

## High Issues

### Hardcoded Secrets
- Passwords in code: `password = "xxx"`
- API keys: `api_key = "xxx"`
- Tokens: `token = "xxx"`
- Private keys: `private_key = "xxx"`

### Sensitive File Exposure
- `.env` files committed
- `credentials.json` files
- SSH keys (`id_rsa`, `id_ed25519`)
- Service account keys

### Permission Issues
- `chmod 777` (world-writable)
- Running as root without justification

## Medium Issues

### Shell Execution
- `subprocess.call()` with shell=True
- `os.popen()` usage
- `os.system()` usage

### Suspicious Dependencies
- `eval` package (npm)
- `shelljs` (npm)
- `subprocess32` (pip)

### Configuration Issues
- Debug mode enabled in production
- Verbose error messages exposed
- CORS misconfigurations

## Low Issues

### Suspicious Files
- Binary files (`.exe`, `.dll`, `.so`)
- Script files (`.sh`, `.bat`, `.ps1`)
- Temporary files

### Code Quality
- Large files (>500 lines)
- God classes (>20 methods)
- Deep nesting (>4 levels)

## Scanning Commands

### Manual Scan
```bash
# Search for hardcoded secrets
grep -rn "password\s*=" --include="*.py" .
grep -rn "api_key\s*=" --include="*.py" .
grep -rn "secret\s*=" --include="*.py" .

# Search for dangerous patterns
grep -rn "eval\s*(" --include="*.py" .
grep -rn "exec\s*(" --include="*.py" .
grep -rn "subprocess.*shell=True" --include="*.py" .
```

### Using Security Scanner
```bash
# Full scan
python3 scripts/security_scanner.py /path/to/repo

# Output to specific file
python3 scripts/security_scanner.py /path/to/repo -o security_report.json
```

## Risk Scoring

| Severity | Points | Examples |
|----------|--------|----------|
| Critical | 30 | Code injection, RCE |
| High | 15 | Hardcoded secrets |
| Medium | 5 | Shell execution, risky deps |
| Low | 1 | Suspicious files |

**Risk Levels:**
- 0-10: info
- 10-30: low
- 30-50: medium
- 50-70: high
- 70+: critical

## License Compatibility

Check for compatible licenses:
- **Permissive**: MIT, Apache-2.0, BSD, ISC
- **Weak Copyleft**: MPL-2.0, LGPL
- **Strong Copyleft**: GPL-2.0, GPL-3.0

**Blocked**: AGPL-3.0 (unless specifically needed)

## Before Synthesis

1. All critical issues must be resolved
2. High issues should be resolved or documented
3. Medium issues should be reviewed
4. License compatibility verified
