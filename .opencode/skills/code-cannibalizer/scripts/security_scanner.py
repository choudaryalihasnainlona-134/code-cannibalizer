#!/usr/bin/env python3
"""
Security Scanner - Scan repositories for security issues.
Checks for malicious patterns, secrets, and vulnerabilities.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass, field, asdict


# Malicious patterns to detect
MALICIOUS_PATTERNS = [
    # Code Injection
    (r"eval\s*\(\s*base64", "Potential code injection via base64 eval"),
    (r"exec\s*\(\s*compile", "Potential code injection via exec/compile"),
    (r"__import__\s*\(\s*['\"]os['\"]", "Dynamic OS import"),
    (r"new\s+Function\s*\(", "Dynamic function creation (code injection risk)"),
    (r"setTimeout\s*\(\s*['\"]", "String-based setTimeout (code injection risk)"),
    (r"setInterval\s*\(\s*['\"]", "String-based setInterval (code injection risk)"),

    # Shell Execution
    (r"subprocess\.call.*shell\s*=\s*True", "Shell execution risk"),
    (r"subprocess\.Popen.*shell\s*=\s*True", "Shell execution risk"),
    (r"os\.system\s*\(", "Shell execution via os.system"),
    (r"os\.popen\s*\(", "Shell execution via os.popen"),
    (r"child_process\.exec\s*\(", "Node.js shell execution"),
    (r"child_process\.execSync\s*\(", "Node.js synchronous shell execution"),

    # Remote Code Execution
    (r"curl.*\|\s*bash", "Remote code execution via pipe"),
    (r"wget.*\|\s*sh", "Remote code execution via pipe"),
    (r"curl.*\|\s*sh", "Remote code execution via pipe"),

    # Data Destruction
    (r"rm\s+-rf\s+/", "Dangerous recursive delete"),
    (r"rm\s+-rf\s+\*", "Dangerous recursive delete"),
    (r"shutil\.rmtree\s*\(", "Recursive directory delete"),
    (r"fs\.rm\s*\{.*recursive\s*:\s*true", "Node.js recursive delete"),

    # Permissions
    (r"chmod\s+777", "Overly permissive permissions"),
    (r"chmod\s+666", "Overly permissive permissions"),

    # Sensitive File Access
    (r"\.ssh/", "SSH key access detected"),
    (r"\.gnupg/", "GPG key access detected"),
    (r"private.*key", "Private key reference"),
    (r"private_key", "Private key reference"),

    # Hardcoded Secrets (Python)
    (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
    (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded secret"),
    (r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
    (r"token\s*=\s*['\"][^'\"]+['\"]", "Hardcoded token"),
    (r"access_token\s*=\s*['\"][^'\"]+['\"]", "Hardcoded access token"),
    (r"aws_secret", "AWS secret key reference"),

    # Hardcoded Secrets (JavaScript/TypeScript)
    (r"password\s*:\s*['\"][^'\"]+['\"]", "Hardcoded password in object"),
    (r"secret\s*:\s*['\"][^'\"]+['\"]", "Hardcoded secret in object"),
    (r"apiKey\s*:\s*['\"][^'\"]+['\"]", "Hardcoded API key in object"),
    (r"clientSecret\s*:\s*['\"][^'\"]+['\"]", "Hardcoded client secret"),

    # SQL Injection
    (r"execute\s*\(\s*['\"].*%s", "Potential SQL injection (format string)"),
    (r"execute\s*\(\s*f['\"]", "Potential SQL injection (f-string)"),
    (r"execute\s*\(\s*['\"].*\+", "Potential SQL injection (concatenation)"),
    (r"query\s*\(\s*['\"].*%", "Potential SQL injection"),

    # Path Traversal
    (r"\.\.\/", "Path traversal pattern"),
    (r"\.\.\\", "Path traversal pattern (Windows)"),
    (r"os\.path\.join.*\.\.", "Potential path traversal"),

    # Deserialization
    (r"pickle\.loads\s*\(", "Unsafe pickle deserialization"),
    (r"yaml\.load\s*\(", "Unsafe YAML load (use safe_load)"),
    (r"yaml\.unsafe_load\s*\(", "Unsafe YAML load"),
    (r"JSON\.parse\s*\(", "JSON parsing (check for injection)"),

    # SSRF
    (r"requests\.get\s*\(.*\+", "Potential SSRF (URL concatenation)"),
    (r"fetch\s*\(.*\+", "Potential SSRF (URL concatenation)"),
    (r"axios\.get\s*\(.*\+", "Potential SSRF (URL concatenation)"),

    # Template Injection
    (r"template\s*\(.*\+", "Potential template injection"),
    (r"render\s*\(.*request\.", "Potential server-side template injection"),

    # Debug/Info Leak
    (r"debug\s*=\s*True", "Debug mode enabled"),
    (r"DEBUG\s*=\s*True", "Debug mode enabled"),
    (r"console\.log\s*\(", "Console log in production code"),
    (r"print\s*\(.*password", "Printing sensitive data"),
    (r"print\s*\(.*secret", "Printing sensitive data"),
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    # Executables
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".app",
    # Scripts
    ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".wsf",
    # Web shells
    ".php", ".asp", ".aspx", ".jsp",
    # Archives (could contain malware)
    ".zip", ".rar", ".7z", ".tar.gz",
]

# Shell scripts only flagged if they contain suspicious patterns
SHELL_SUSPICIOUS_PATTERNS = [
    r"curl.*\|.*sh",
    r"wget.*\|.*sh",
    r"eval\s*\(",
    r"exec\s*\(",
    r"rm\s+-rf",
    r"chmod\s+777",
]

# Directories to exclude from scanning
EXCLUDED_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "env", ".env",
    "target", "bin", "obj", ".next", ".nuxt",
    "coverage", ".coverage", "htmlcov", ".pytest_cache"
}

# Sensitive paths
SENSITIVE_PATHS = [
    # Environment files
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.bak",
    # Credentials
    "credentials.json", "service-account.json", "keyfile.json",
    ".htpasswd", ".htaccess",
    # SSH keys
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "authorized_keys", "known_hosts",
    # Certificates
    "*.pem", "*.key", "*.crt", "*.p12", "*.pfx",
    # Config files with secrets
    "wp-config.php", "config.php", "database.yml",
    "secrets.yml", "secrets.json",
    # Cloud
    ".aws/credentials", ".azure/credentials", ".gcloud/credentials",
    # Docker
    ".docker/config.json",
    # Git
    ".git-credentials", ".netrc",
]


@dataclass
class SecurityFinding:
    """A security finding."""
    severity: str  # critical, high, medium, low, info
    category: str
    file: str
    line: int = 0
    message: str = ""
    pattern: str = ""
    suggestion: str = ""


@dataclass
class SecurityReport:
    """Complete security report for a repository."""
    repo_name: str
    repo_path: str
    scan_time: str = ""
    findings: List[Dict] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = "unknown"
    summary: str = ""


class SecurityScanner:
    """Scan a repository for security issues."""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.findings: List[SecurityFinding] = []
        self.suppressions: set = set()
        self.stats = {
            "files_scanned": 0,
            "files_skipped": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self._load_suppressions()
    
    def _load_suppressions(self):
        """Load suppression rules from .security-scanner-ignore file."""
        ignore_file = self.repo_path / ".security-scanner-ignore"
        if ignore_file.exists():
            for line in ignore_file.read_text().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    self.suppressions.add(line)
    
    def _is_suppressed(self, file_path: str, line_num: int, pattern: str) -> bool:
        """Check if a finding is suppressed."""
        # Check file-level suppression (suppresses all findings in file)
        if f"{file_path}::" in self.suppressions:
            return True
        
        # Check line-level suppression
        if f"{file_path}:{line_num}" in self.suppressions:
            return True
        
        # Check pattern-level suppression
        if pattern in self.suppressions:
            return True
        
        return False
    
    def scan_file(self, file_path: Path) -> List[SecurityFinding]:
        """Scan a single file for security issues."""
        findings = []
        rel_path = str(file_path.relative_to(self.repo_path))
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            # Check for malicious patterns
            for line_num, line in enumerate(lines, 1):
                # Check for inline suppression (# nosec)
                if re.search(r'#\s*nosec', line):
                    continue
                
                for pattern, description in MALICIOUS_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Skip false positives for env var patterns
                        if "password" in description or "secret" in description or "api_key" in description or "token" in description:
                            if re.search(r'(os\.getenv|os\.environ|process\.env|os\.environ\.get)', line):
                                continue
                        
                        # Check if suppressed
                        if self._is_suppressed(rel_path, line_num, pattern):
                            continue
                        
                        severity = self._classify_severity(pattern, description)
                        findings.append(SecurityFinding(
                            severity=severity,
                            category="malicious_pattern",
                            file=rel_path,
                            line=line_num,
                            message=description,
                            pattern=pattern,
                            suggestion="Review and remove if not intentional"
                        ))
            
            # Check for high-entropy strings (potential secrets)
            self._check_string_entropy(content, rel_path, findings)
            
            # Check for secrets in config files
            if file_path.suffix in ('.json', '.yaml', '.yml', '.toml', '.ini', '.cfg'):
                self._check_config_secrets(content, rel_path, findings)
            
            self.stats["files_scanned"] += 1
            
        except Exception as e:
            self.stats["files_skipped"] += 1
        
        return findings
    
    def _check_string_entropy(self, content: str, file_path: str, findings: List[SecurityFinding]):
        """Check for high-entropy string literals (potential secrets)."""
        import math
        
        def shannon_entropy(s):
            if not s:
                return 0
            freq = {}
            for c in s:
                freq[c] = freq.get(c, 0) + 1
            length = len(s)
            return -sum((count/length) * math.log2(count/length) for count in freq.values())
        
        # Find string literals
        string_patterns = [r'"([^"\\]|\\.)*"', r"'([^'\\]|\\.)*'"]
        
        for pattern in string_patterns:
            for match in re.finditer(pattern, content):
                s = match.group()
                if len(s) > 20:  # Only check longer strings
                    entropy = shannon_entropy(s)
                    if entropy > 4.5:  # High entropy threshold
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Check if suppressed
                        if self._is_suppressed(file_path, line_num, "high_entropy"):
                            continue
                        
                        findings.append(SecurityFinding(
                            severity="medium",
                            category="high_entropy_string",
                            file=file_path,
                            line=line_num,
                            message=f"High-entropy string (entropy: {entropy:.2f})",
                            suggestion="Potential secret - verify if intentional"
                        ))
    
    def _check_config_secrets(self, content: str, file_path: str, findings: List[SecurityFinding]):
        """Check configuration files for secrets."""
        secret_patterns = [
            (r'"password"\s*:\s*"[^"]+"', "Password in config"),
            (r'"secret"\s*:\s*"[^"]+"', "Secret in config"),
            (r'"api_key"\s*:\s*"[^"]+"', "API key in config"),
            (r'"token"\s*:\s*"[^"]+"', "Token in config"),
            (r'"access_key"\s*:\s*"[^"]+"', "Access key in config"),
        ]
        
        for pattern, description in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity="high",
                    category="hardcoded_secret",
                    file=file_path,
                    message=description,
                    suggestion="Use environment variables or secrets manager"
                ))
    
    def _classify_severity(self, pattern: str, description: str) -> str:
        """Classify the severity of a finding."""
        critical_patterns = ["eval.*base64", "exec.*compile", "rm.*-rf.*/"]
        high_patterns = ["password.*=", "secret.*=", "api.*key.*=", "curl.*bash"]
        medium_patterns = ["subprocess.*shell", "os.system", "chmod.*777"]
        
        for cp in critical_patterns:
            if re.search(cp, pattern, re.IGNORECASE):
                return "critical"
        
        for hp in high_patterns:
            if re.search(hp, pattern, re.IGNORECASE):
                return "high"
        
        for mp in medium_patterns:
            if re.search(mp, pattern, re.IGNORECASE):
                return "medium"
        
        return "low"
    
    def scan_sensitive_files(self):
        """Check for sensitive files."""
        for sensitive in SENSITIVE_PATHS:
            for file_path in self.repo_path.rglob(f"*{sensitive}*"):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(self.repo_path))
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        category="sensitive_file",
                        file=rel_path,
                        message=f"Sensitive file found: {sensitive}",
                        suggestion="Ensure this file is in .gitignore"
                    ))
    
    def scan_suspicious_files(self):
        """Check for suspicious file extensions."""
        for ext in SUSPICIOUS_EXTENSIONS:
            for file_path in self.repo_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(self.repo_path))
                    self.findings.append(SecurityFinding(
                        severity="low",
                        category="suspicious_file",
                        file=rel_path,
                        message=f"Suspicious file extension: {ext}",
                        suggestion="Review if this file should be in repository"
                    ))
        
        # Shell scripts only flagged if they contain suspicious patterns
        for ext in ('.sh', '.bash', '.zsh'):
            for file_path in self.repo_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        if any(re.search(p, content) for p in SHELL_SUSPICIOUS_PATTERNS):
                            rel_path = str(file_path.relative_to(self.repo_path))
                            self.findings.append(SecurityFinding(
                                severity="low",
                                category="suspicious_file",
                                file=rel_path,
                                message=f"Shell script with suspicious patterns: {ext}",
                                suggestion="Review script contents"
                            ))
                    except Exception:
                        pass
    
    def scan_dependencies(self):
        """Scan dependency files for known issues."""
        dep_files = [
            ("package.json", self._scan_npm_deps),
            ("requirements.txt", self._scan_pip_deps),
            ("go.mod", self._scan_go_deps),
            ("Cargo.toml", self._scan_rust_deps),
        ]
        
        for dep_file, scanner in dep_files:
            for file_path in self.repo_path.rglob(dep_file):
                if file_path.is_file():
                    scanner(file_path)
    
    def _scan_npm_deps(self, file_path: Path):
        """Scan package.json for risky dependencies."""
        try:
            content = json.loads(file_path.read_text())
            deps = {**content.get("dependencies", {}), **content.get("devDependencies", {})}
            
            risky_deps = ["eval", "shelljs", "execa"]
            for dep in deps:
                if dep.lower() in risky_deps:
                    rel_path = str(file_path.relative_to(self.repo_path))
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        category="risky_dependency",
                        file=rel_path,
                        message=f"Potentially risky dependency: {dep}",
                        suggestion="Review necessity and security implications"
                    ))
        except (json.JSONDecodeError, KeyError):
            pass
    
    def _scan_pip_deps(self, file_path: Path):
        """Scan requirements.txt for risky dependencies."""
        risky_deps = ["subprocess32", "shell"]
        try:
            for line in file_path.read_text().split('\n'):
                dep = line.strip().split('==')[0].split('>=')[0].split('<=')[0]
                if dep.lower() in risky_deps:
                    rel_path = str(file_path.relative_to(self.repo_path))
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        category="risky_dependency",
                        file=rel_path,
                        message=f"Potentially risky dependency: {dep}",
                        suggestion="Review necessity and security implications"
                    ))
        except (json.JSONDecodeError, KeyError):
            pass
    
    def _scan_go_deps(self, file_path: Path):
        """Scan go.mod for risky dependencies."""
        pass  # Go deps are generally safer
    
    def _scan_rust_deps(self, file_path: Path):
        """Scan Cargo.toml for risky dependencies."""
        pass  # Rust deps are generally safer
    
    def scan_all(self, scan_git: bool = False) -> SecurityReport:
        """Run all security scans."""
        from datetime import datetime
        
        print(f"Scanning: {self.repo_path}")
        
        # Scan all code files (with directory exclusion)
        code_extensions = ('.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.rb', '.php')
        for file_path in self.repo_path.rglob('*'):
            # Skip excluded directories
            if any(part in EXCLUDED_DIRS for part in file_path.parts):
                continue
            
            if file_path.is_file() and file_path.suffix in code_extensions:
                findings = self.scan_file(file_path)
                self.findings.extend(findings)
        
        # Run specialized scans
        self.scan_sensitive_files()
        self.scan_suspicious_files()
        self.scan_dependencies()
        
        # Optional git history scan
        if scan_git:
            self.scan_git_history()
        
        # Update stats
        for f in self.findings:
            self.stats[f.severity] = self.stats.get(f.severity, 0) + 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        # Build report
        report = SecurityReport(
            repo_name=self.repo_path.name,
            repo_path=str(self.repo_path),
            scan_time=datetime.now().isoformat(),
            findings=[asdict(f) for f in self.findings],
            stats=self.stats,
            risk_score=risk_score,
            risk_level=self._get_risk_level(risk_score),
            summary=self._generate_summary()
        )
        
        return report
    
    def scan_git_history(self, max_commits: int = 100):
        """Scan git history for leaked secrets."""
        import subprocess
        
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline', f'-{max_commits}'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return
            
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                secret_patterns = [
                    (r'password\s*[=:]\s*\S+', "Password in commit message"),
                    (r'api[_-]?key\s*[=:]\s*\S+', "API key in commit message"),
                    (r'secret\s*[=:]\s*\S+', "Secret in commit message"),
                    (r'token\s*[=:]\s*\S+', "Token in commit message"),
                ]
                
                for pattern, description in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.findings.append(SecurityFinding(
                            severity="high",
                            category="git_history_secret",
                            file=".git/commit-message",
                            message=description,
                            suggestion="Rotate credentials and clean git history"
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def _calculate_risk_score(self) -> int:
        """Calculate risk score 0-100."""
        score = 0
        score += self.stats.get("critical", 0) * 30
        score += self.stats.get("high", 0) * 15
        score += self.stats.get("medium", 0) * 5
        score += self.stats.get("low", 0) * 1
        return min(100, score)
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score."""
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        elif score >= 10:
            return "low"
        return "info"
    
    def _generate_summary(self) -> str:
        """Generate a summary of findings."""
        total = len(self.findings)
        if total == 0:
            return "No security issues found"
        
        critical = self.stats.get("critical", 0)
        high = self.stats.get("high", 0)
        
        parts = []
        if critical:
            parts.append(f"{critical} critical")
        if high:
            parts.append(f"{high} high")
        
        if parts:
            return f"Found {total} issues: {', '.join(parts)} severity"
        return f"Found {total} issues"


def main():
    parser = argparse.ArgumentParser(description="Scan repository for security issues")
    parser.add_argument("repo_path", help="Path to repository to scan")
    parser.add_argument("-o", "--output", default="security_report.json", help="Output file")
    parser.add_argument("--scan-git", action="store_true", 
                        help="Also scan git history for leaked secrets")
    
    args = parser.parse_args()
    
    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        print(f"Error: Path not found: {repo_path}")
        sys.exit(1)
    
    scanner = SecurityScanner(repo_path)
    report = scanner.scan_all(scan_git=args.scan_git)
    
    # Save report
    with open(args.output, 'w') as f:
        json.dump(asdict(report), f, indent=2)
    
    print(f"\nSecurity scan complete:")
    print(f"  Risk Score: {report.risk_score}/100 ({report.risk_level})")
    print(f"  Findings: {len(report.findings)}")
    print(f"  Critical: {report.stats.get('critical', 0)}")
    print(f"  High: {report.stats.get('high', 0)}")
    print(f"  Medium: {report.stats.get('medium', 0)}")
    print(f"  Low: {report.stats.get('low', 0)}")
    print(f"  Output: {args.output}")
    
    # Output to stdout
    print(json.dumps(asdict(report)))
    
    # Exit code based on risk
    sys.exit(1 if report.risk_level in ("critical", "high") else 0)


if __name__ == "__main__":
    main()
