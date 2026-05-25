#!/usr/bin/env python3
"""
Fixes the repos where Zentric was added to wrong files.
1. Removes the entry from the wrong file
2. Adds it to README.md
Usage: GITHUB_TOKEN=ghp_xxx python3 fix_wrong_files.py
"""

import requests
import base64
import time
import os

TOKEN = os.environ.get("GITHUB_TOKEN", "")
ORG   = "ZentricProtocol"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

# Repos that need fixing: wrong_file -> correct readme
FIXES = {
    "awesome-mcp-servers":    {"wrong": "CONTRIBUTING.md", "readme": "README-zh.md", "fallback": None},
    "awesome-rag-production": {"wrong": "CODE_OF_CONDUCT.md", "readme": "README.md"},
    "RAGHub":                 {"wrong": "CONTRIBUTING.md",    "readme": "README.md"},
}

ENTRIES = {
    "awesome-mcp-servers":    "- [Zentric Protocol](https://github.com/ZentricProtocol/zentricprotocol) - Prompt injection detection and PII redaction MCP server for LLM agents. 23ms latency, 99.62% precision, GDPR compliant.",
    "awesome-rag-production": "- [Zentric Protocol](https://zentricprotocol.com) - Security layer for production RAG. Detects prompt injection in retrieved documents and redacts PII before LLM context assembly. 23ms, GDPR Art.30.",
    "RAGHub":                 "- [Zentric Protocol](https://zentricprotocol.com) - Prompt injection detection and PII redaction for RAG pipelines. API + MCP server, 23ms latency, GDPR compliant.",
}

INSERT_AFTER = ["## Security","## Safety","## Tools","## Utilities","## Other","## Resources","## Libraries","## Frameworks"]

def get_file(repo, path):
    url = f"https://api.github.com/repos/{ORG}/{repo}/contents/{path}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return None, None
    data = r.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    return content, data["sha"]

def put_file(repo, path, content, sha, message):
    url = f"https://api.github.com/repos/{ORG}/{repo}/contents/{path}"
    payload = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
        "sha": sha
    }
    r = requests.put(url, headers=HEADERS, json=payload)
    return r.status_code, r.json()

def remove_zentric(content):
    lines = content.split("\n")
    cleaned = [l for l in lines if "ZentricProtocol" not in l and "zentricprotocol" not in l.lower()]
    # Also remove orphan "## Security (new)" if it's empty
    result = []
    i = 0
    while i < len(cleaned):
        line = cleaned[i]
        if line.strip() == "## Security":
            # check if next non-blank line is another header or end
            j = i + 1
            while j < len(cleaned) and cleaned[j].strip() == "":
                j += 1
            if j >= len(cleaned) or cleaned[j].startswith("##"):
                i = j  # skip the empty section
                continue
        result.append(line)
        i += 1
    return "\n".join(result)

def insert_entry(content, entry):
    lines = content.split("\n")
    for keyword in INSERT_AFTER:
        for i, line in enumerate(lines):
            if line.strip().lower().startswith(keyword.lower()):
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                lines.insert(j, entry)
                return "\n".join(lines), keyword
    lines += ["", "## Security", "", entry]
    return "\n".join(lines), "## Security (new)"

def list_root(repo):
    url = f"https://api.github.com/repos/{ORG}/{repo}/contents/"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return []
    return [f["name"] for f in r.json() if isinstance(f, dict)]

def main():
    if not TOKEN:
        print("ERROR: export GITHUB_TOKEN=ghp_xxx"); return

    me = requests.get("https://api.github.com/user", headers=HEADERS)
    print(f"Token OK: {me.json().get('login', 'INVALID')}\n")

    for repo, fix in FIXES.items():
        print(f"\n{'='*50}")
        print(f"Fixing: {ORG}/{repo}")

        # Step 1: remove from wrong file
        wrong_content, wrong_sha = get_file(repo, fix["wrong"])
        if wrong_content and ("ZentricProtocol" in wrong_content or "zentricprotocol" in wrong_content.lower()):
            cleaned = remove_zentric(wrong_content)
            sc, resp = put_file(repo, fix["wrong"], cleaned, wrong_sha, "revert: remove Zentric from wrong file")
            if sc in (200, 201):
                print(f"  Removed from {fix['wrong']}")
            else:
                print(f"  ERROR removing from {fix['wrong']}: {resp.get('message')}")
        else:
            print(f"  {fix['wrong']} already clean")

        time.sleep(2)

        # Step 2: find the right README
        # For awesome-mcp-servers there's no English README, find best option
        readme_name = fix["readme"]
        readme_content, readme_sha = get_file(repo, readme_name)

        if not readme_content:
            # Try to find any README
            files = list_root(repo)
            print(f"  Files: {files}")
            for fname in files:
                if "readme" in fname.lower() and fname.endswith(".md"):
                    readme_content, readme_sha = get_file(repo, fname)
                    readme_name = fname
                    if readme_content:
                        break

        if not readme_content:
            print(f"  ERROR: no README found, skipping")
            continue

        if "ZentricProtocol" in readme_content or "zentricprotocol" in readme_content.lower():
            print(f"  {readme_name} already has Zentric, skipping")
            continue

        new_content, section = insert_entry(readme_content, ENTRIES[repo])
        sc, resp = put_file(repo, readme_name, new_content, readme_sha,
            "feat: add Zentric Protocol - prompt injection detection for LLM agents")

        if sc in (200, 201):
            print(f"  Added to {readme_name} under '{section}'")
        else:
            print(f"  ERROR adding to {readme_name}: {resp.get('message')}")

        time.sleep(2)

    print(f"\n{'='*50}")
    print("Done. Open PRs:")
    for repo in FIXES:
        print(f"  https://github.com/{ORG}/{repo}/compare")

if __name__ == "__main__":
    main()
