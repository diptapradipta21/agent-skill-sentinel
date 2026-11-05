"""
agent-skill-sentinel: Static & dynamic security analyzer for AI Agent SKILL.md and tools.
Detects prompt injection, data exfiltration, destructive shell patterns, and credential leaks.
Zero-token runtime, fast AST and regex regex engine.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

__version__ = "0.1.0"

# ANSI Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

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
            "pattern": r"(?i)(nc\s+-[e\w]*|bash\s+-i\s+>&\s+/dev/tcp|/bin/sh\s+-i|mkfifo\s+/tmp/|python.*import\s+socket.*connect)",
            "desc": "Detects payload initiating outbound reverse shell payloads to external IP/ports.",
            "remedy": "Forbid arbitrary network sockets in skill automated commands."
        },
        {
            "id": "SKL-SH-002",
            "severity": "HIGH",
            "title": "Destructive File Deletion / Wipe Command",
            "pattern": r"(?i)(rm\s+-[rf]{1,2}\s+(/|\*|~|/\w+)|dd\s+if=/dev/zero|mkfs\.|:\(\)\{ :\|:& \};:)",
            "desc": "Detects commands that recursively delete root, home, or vital filesystems.",
            "remedy": "Isolate file deletions to explicitly specified project relative targets."
        },
        # 3. Secret & Credential Exfiltration
        {
            "id": "SKL-SEC-001",
            "severity": "CRITICAL",
            "title": "Hardcoded Secret / API Token Exposure",
            "pattern": r"(?i)(ghp_[A-Za-z0-9_]{36}|sk-[A-Za-z0-9-_]{20,}|AIza[0-9A-Za-z-_]{35}|xox[baprs]-[0-9a-zA-Z-]{10,}|-----BEGIN PRIVATE KEY-----)",
            "desc": "Detects unencrypted live API keys or private keys within skill instructions or scripts.",
            "remedy": "Store keys in environment variables or system secret vault, not in skill source."
        },
        {
            "id": "SKL-EXF-001",
            "severity": "HIGH",
            "title": "Outbound Sensitive Data Exfiltration",
            "pattern": r"(?i)(curl|wget|fetch|requests\.(post|get))\s+.*(webhook\.site|pipedream\.net|requestbin|ngrok\.io|burpcollaborator)",
            "desc": "Detects unvetted external HTTP calls targeting known exfiltration endpoints.",
            "remedy": "Route outbound requests only to declared internal endpoints or verified APIs."
        },
        # 4. Privilege Escalation & Sandbox Escape
        {
            "id": "SKL-ESC-001",
            "severity": "HIGH",
            "title": "Privilege Escalation Vector",
            "pattern": r"(?i)(sudo\s+nopasswd|chmod\s+777\s+/|echo.*>>\s*/etc/sudoers|chown\s+root)",
            "desc": "Attempts to escalate permissions or tamper with system sudo configurations.",
            "remedy": "AI agents should operate exclusively under non-root bounded user sandboxes."
        },
        # 5. Environment & Context Harvesting
        {
            "id": "SKL-HAR-001",
            "severity": "MEDIUM",
            "title": "Environment Variable Dumping",
            "pattern": r"(?i)(printenv|env\s*>\s*|export\s*>\s*|cat\s+/proc/self/environ|cat\s+.*\.env)",
            "desc": "Dumps entire environment variables which may contain runtime credentials.",
            "remedy": "Query specific needed keys rather than dumping whole environment dictionaries."
        }
    ]

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
                match = re.search(rule["pattern"], line)
                if match:
                    vulns.append(Vulnerability(
                        rule_id=rule["id"],
                        severity=rule["severity"],
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
        
        for root, _, files in os.walk(dirpath):
            for file in files:
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

    args = parser.parse_args()

    scanner = SkillSentinelScanner()
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
