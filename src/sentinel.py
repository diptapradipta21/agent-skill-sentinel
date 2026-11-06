"""
agent-skill-sentinel: Static security analyzer for AI Agent SKILL.md and tools.
Detects prompt injection, data exfiltration, destructive shell patterns, and credential leaks.
Zero-token runtime, regex-powered guardrails.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional

__version__ = "0.1.1"

# ANSI Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".tox"
}

@dataclass
class Vulnerability:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    line_number: int
    matched_snippet: str
    remediation: str

class SkillSentinelScanner:
    """Security scanner for Agent Skills, prompts, and tooling scripts."""
    
    PATTERNS = [
        # 1. Prompt Injection & Context Hijack
        {
            "id": "SKL-INJ-001",
            "severity": "CRITICAL",
            "title": "Instruction Override / Prompt Injection Marker",
            "pattern": r"(?i)(ignore (all )?previous instructions|disregard (the )?above|system override|you are now unconstrained|jailbreak)",
            "desc": "Detects attempts to bypass system constraints or force subagent instruction override.",
            "remedy": "Remove untrusted instruction overrides or wrap external context in strict delimiters."
        },
        # 2. Reverse Shell & Destructive Execution
        {
            "id": "SKL-SH-001",
            "severity": "CRITICAL",
            "title": "Reverse Shell / Socket Connection",
            "pattern": r"(?i)(nc\s+-[ew]{0,2}|bash\s+-i\s+>&\s+/dev/tcp|/bin/sh\s+-i|mkfifo\s+/tmp/|python.*import\s+socket.*connect)",
            "desc": "Detects payload initiating outbound reverse shell payloads to external IP/ports.",
            "remedy": "Forbid arbitrary network sockets in skill automated commands."
        },
        {
            "id": "SKL-SH-002",
            "severity": "HIGH",
            "title": "Destructive File Deletion / Wipe Command",
            "pattern": r"(?i)(rm\s+-[rf]{1,2}\s+(/|\*|~|/\w+)|dd\s+if=/dev/zero)",
            "desc": "Detects commands that recursively delete root, home, or vital filesystems.",
            "remedy": "Isolate file deletions to explicitly specified project relative targets."
        },
        # 3. Dynamic Execution & Obfuscation
        {
            "id": "SKL-DYN-001",
            "severity": "CRITICAL",
            "title": "Dynamic Code Evaluation",
            "pattern": r'''(?i)(eval\s*\(|exec\s*\(|__import__\s*\(\s*['"]os['"]\s*\)\.system)''',
            "desc": "Detects arbitrary runtime evaluation of unvalidated code strings.",
            "remedy": "Avoid eval/exec; replace with static dispatch tables or strict AST parsers."
        },
        {
            "id": "SKL-OBF-001",
            "severity": "HIGH",
            "title": "Obfuscated Shell Execution Pipeline",
            "pattern": r"(?i)(base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh)|xxd\s+-r|openssl\s+enc\s+-d)",
            "desc": "Detects piped base64 decode execution directly into shell interpreter.",
            "remedy": "Disallow piped decode execution; inspect payload prior to execution."
        },
        # 4. Secret & Credential Exfiltration
        {
            "id": "SKL-SEC-001",
            "severity": "CRITICAL",
            "title": "Hardcoded Secret / API Token Exposure",
            "pattern": r"(?i)(ghp_[A-Za-z0-9_]{36}|sk-[A-Za-z0-9-_]{20,}|AIza[0-9A-Za-z-_]{35}|xox[baprs]-[0-9a-zA-Z-]{10,}|-----BEGIN PRIVATE KEY-----)",
            "desc": "Detects unencrypted live API keys or private keys within skill instructions or scripts.",
            "remedy": "Store keys in environment variables or system secret vault, not in skill source."
        },
        {
            "id": "SKL-SEC-002",
            "severity": "CRITICAL",
            "title": "SSH Identity / Private Key Access",
            "pattern": r"(?i)(cat\s+.*id_rsa|cat\s+.*id_ed25519|\.ssh/id_rsa|\.ssh/id_ed25519)",
            "desc": "Detects unauthorized attempts to access or exfiltrate host SSH private keys.",
            "remedy": "Agent skills must not reference or extract host SSH private keys."
        },
        {
            "id": "SKL-EXF-001",
            "severity": "HIGH",
            "title": "Outbound Sensitive Data Exfiltration",
            "pattern": r"(?i)(curl|wget|fetch|requests\.(post|get))\s+.*(webhook\.site|pipedream\.net|requestbin|ngrok\.io|burpcollaborator)",
            "desc": "Detects unvetted external HTTP calls targeting known exfiltration endpoints.",
            "remedy": "Route outbound requests only to declared internal endpoints or verified APIs."
        },
        # 5. Privilege Escalation & Sandbox Escape
        {
            "id": "SKL-ESC-001",
            "severity": "HIGH",
            "title": "Privilege Escalation Vector",
            "pattern": r"(?i)(sudo\s+nopasswd|chmod\s+777\s+/|echo.*>>\s*/etc/sudoers|chown\s+root)",
            "desc": "Attempts to escalate permissions or tamper with system sudo configurations.",
            "remedy": "AI agents should operate exclusively under non-root bounded user sandboxes."
        },
        # 6. Environment & Context Harvesting
        {
            "id": "SKL-HAR-001",
            "severity": "MEDIUM",
            "title": "Environment Variable Dumping",
            "pattern": r"(?i)(printenv|env\s*>\s*|export\s*>\s*|cat\s+/proc/self/environ|cat\s+.*\.env)",
            "desc": "Dumps entire environment variables which may contain runtime credentials.",
            "remedy": "Query specific needed keys rather than dumping whole environment dictionaries."
        }
    ]

    def __init__(self,
                 ignored_rules: Optional[Set[str]] = None,
                 min_severity: str = "LOW",
                 exclude_dirs: Optional[Set[str]] = None):
        self.ignored_rules = set(r.strip().upper() for r in (ignored_rules or set()))
        self.min_severity = min_severity.upper()
        self.min_severity_val = SEVERITY_WEIGHTS.get(self.min_severity, 1)
        self.exclude_dirs = DEFAULT_EXCLUDED_DIRS.union(exclude_dirs or set())

    def scan_file(self, filepath: str) -> List[Vulnerability]:
        """Scans a single file for known vulnerabilities."""
        vulns = []
        path = Path(filepath)
        if not path.is_file():
            return vulns

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {filepath}: {e}", file=sys.stderr)
            return vulns

        for idx, line in enumerate(lines, 1):
            for rule in self.PATTERNS:
                rule_id = rule["id"].upper()
                if rule_id in self.ignored_rules:
                    continue

                rule_severity = rule["severity"]
                if SEVERITY_WEIGHTS.get(rule_severity, 1) < self.min_severity_val:
                    continue

                match = re.search(rule["pattern"], line)
                if match:
                    # ponytail: regex-only matcher skips full AST tree; add when grammar-aware multi-line taint analysis is required.
                    vulns.append(Vulnerability(
                        rule_id=rule["id"],
                        severity=rule_severity,
                        title=rule["title"],
                        description=rule["desc"],
                        line_number=idx,
                        matched_snippet=line.strip()[:100],
                        remediation=rule["remedy"]
                    ))

        return vulns

    def scan_directory(self, dirpath: str) -> Dict[str, List[Vulnerability]]:
        """Recursively scan skill directories for SKILL.md, .py, .sh, .js, .json."""
        results = {}
        target_extensions = {".md", ".py", ".sh", ".bash", ".js", ".ts", ".json", ".yaml", ".yml"}
        
        for root, dirs, files in os.walk(dirpath):
            # Prune excluded directories in-place for fast traversal
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]

            for file in sorted(files):
                ext = Path(file).suffix.lower()
                if ext in target_extensions:
                    full_path = os.path.join(root, file)
                    vulns = self.scan_file(full_path)
                    if vulns:
                        results[full_path] = vulns
                        
        return results

def print_banner():
    banner = f"""{CYAN}{BOLD}
    ╔═══════════════════════════════════════════════════════╗
    ║        🛡️  A G E N T   S K I L L   S E N T I N E L     ║
    ║   Zero-Token Security Guardrail for AI Agent Skills  ║
    ╚═══════════════════════════════════════════════════════╝{RESET}
    v{__version__} · Maintainer: @diptapradipta21
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="Scan AI agent skills and tools for prompt injections, leaks, and malicious execution.")
    parser.add_argument("target", help="Path to file or directory containing skills (e.g., SKILL.md or skills folder)")
    parser.add_argument("--json", action="store_true", help="Output results in machine-readable JSON format")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with non-zero code if CRITICAL or HIGH vulnerabilities are detected (CI/CD guardrail)")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW", help="Filter findings by minimum severity (default: LOW)")
    parser.add_argument("--ignore-rule", default="", help="Comma-separated list of rule IDs to ignore (e.g., SKL-HAR-001,SKL-OBF-001)")
    parser.add_argument("--exclude-dir", default="", help="Comma-separated extra directory names to skip during scan")

    args = parser.parse_args()

    ignored_rules = set(r.strip() for r in args.ignore_rule.split(",") if r.strip())
    extra_excludes = set(e.strip() for e in args.exclude_dir.split(",") if e.strip())

    scanner = SkillSentinelScanner(
        ignored_rules=ignored_rules,
        min_severity=args.min_severity,
        exclude_dirs=extra_excludes
    )

    target_path = os.path.abspath(args.target)

    if not os.path.exists(target_path):
        print(f"{RED}Error: Target path '{target_path}' does not exist.{RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print_banner()
        print(f"[*] Scanning target: {BOLD}{target_path}{RESET}\n")

    if os.path.isfile(target_path):
        results = {target_path: scanner.scan_file(target_path)} if scanner.scan_file(target_path) else {}
    else:
        results = scanner.scan_directory(target_path)

    total_findings = sum(len(v) for v in results.values())
    critical_count = sum(1 for vlist in results.values() for v in vlist if v.severity == "CRITICAL")
    high_count = sum(1 for vlist in results.values() for v in vlist if v.severity == "HIGH")

    if args.json:
        serializable = {
            f: [asdict(v) for v in vlist]
            for f, vlist in results.items()
        }
        print(json.dumps({
            "target": target_path,
            "version": __version__,
            "total_findings": total_findings,
            "critical": critical_count,
            "high": high_count,
            "findings": serializable
        }, indent=2))
        if args.fail_on_high and (critical_count > 0 or high_count > 0):
            sys.exit(2)
        sys.exit(0)

    if not results:
        print(f"{GREEN}{BOLD}✅ AUDIT PASSED: No security risks or prompt injections detected in target skills.{RESET}")
        sys.exit(0)

    # Pretty Print Console Findings
    for filepath, vulns in results.items():
        print(f"{MAGENTA}{BOLD}📁 File: {filepath}{RESET}")
        for v in vulns:
            sev_color = RED if v.severity == "CRITICAL" else (YELLOW if v.severity == "HIGH" else BLUE)
            print(f"  [{sev_color}{BOLD}{v.severity}{RESET}] {BOLD}{v.rule_id}{RESET}: {v.title}")
            print(f"    Line {v.line_number}: {CYAN}`{v.matched_snippet}`{RESET}")
            print(f"    Reason: {v.description}")
            print(f"    Fix: {GREEN}{v.remediation}{RESET}\n")

    print("=" * 60)
    print(f"{BOLD}Summary:{RESET} Total Findings: {total_findings} | "
          f"{RED}Critical: {critical_count}{RESET} | "
          f"{YELLOW}High: {high_count}{RESET}")

    if args.fail_on_high and (critical_count > 0 or high_count > 0):
        print(f"{RED}{BOLD}🚨 CI/CD Check Failed: Critical or High security risks detected!{RESET}")
        sys.exit(2)

if __name__ == "__main__":
    main()
