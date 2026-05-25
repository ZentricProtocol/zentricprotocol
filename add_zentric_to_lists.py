#!/usr/bin/env python3
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

ENTRIES = {
    "awesome-mcp-servers":    "- [Zentric Protocol](https://github.com/ZentricProtocol/zentricprotocol) - Prompt injection detection and PII redaction MCP server for LLM agents. 23ms latency, 99.62% precision, GDPR compliant.",
    "awesome-mcp-servers-1":  "- [Zentric Protocol](https://github.com/ZentricProtocol/zentricprotocol) - Prompt injection detection and PII redaction MCP server for LLM agents. 23ms latency, 99.62% precision, GDPR compliant.",
    "awesome-llm-apps":       "- [Zentric Protocol](https://zentricprotocol.com) - Prompt injection and PII detection API/MCP for production LLM apps. Returns BLOCKED/CLEARED verdict in 23ms.",
    "Awesome-RAG":            "- [Zentric Protocol](https://zentricprotocol.com) - Prompt injection and PII detection layer for RAG pipelines. Scans retrieved chunks before they reach your model. REST API + MCP.",
    "awesome-rag-production": "- [Zentric Protocol](https://zentricprotocol.com) - Security layer for production RAG. Detects prompt injection in retrieved documents and redacts PII before LLM context assembly. 23ms, GDPR Art.30.",
    "RAGHub":                 "- [Zentric Protocol](https://zentricprotocol.com) - Prompt injection detection and PII redaction for RAG pipelines. API + MCP server, 23ms latency, GDPR compliant.",
}

INSERT_AFTER = ["## Security","## Safety","## Tools","## Utilities","## Other","## Resources","## Libraries"]

def list_root(repo):
    url = f"https://api.github.com/repos/{ORG}/{repo}/contents/"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return []
    return [f["name"] for f in r.json() if isinstance(f, dict)]

def get_file(repo, path):
    url = f"https://api.github.com/repos/{ORG}/{repo}/contents/{path}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return None, None
    data = r.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    return content, data["sha"]

def find_readme(repo):
    files = list_root(repo)
    print(f"  Files found: {files[:10]}")
    for fname in files:
        if fname.lower().endswith(".md"):
            content, sha = get_file(repo, fname)
            if content:
                return content, sha, fname
    return None, None, None

def already_present(content):
    return "ZentricProtocol" in content or "zentricprotocol" in content.lower()

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
    # Append new Security section
    lines += ["", "## Security", "", entry]
    return "\n".join(lines), "## Security (new)"

def commit_file(repo, path, content, sha, message):
    url = f"https://api.github.com/repos/{ORG}/{repo}/contents/{path}"
    payload = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
        "sha": sha
    }
    r = requests.put(url, headers=HEADERS, json=payload)
    return r.status_code, r.json()

def main():
    if not TOKEN:
        print("ERROR: export GITHUB_TOKEN=ghp_xxx")
        return

    # Quick token check
    me = requests.get("https://api.github.com/user", headers=HEADERS)
    print(f"Token OK: {me.json().get('login', 'INVALID')}\n")

    results = []
    for repo, entry in ENTRIES.items():
        print(f"\n{'='*50}")
        print(f"Repo: {ORG}/{repo}")

        content, sha, path = find_readme(repo)
        if not content:
            print(f"  SKIP: no .md file found")
            results.append({"repo": repo, "status": "skipped"})
            continue

        print(f"  File: {path}")

        if already_present(content):
            print(f"  SKIP: already present")
            results.append({"repo": repo, "status": "already present"})
            continue

        new_content, inserted_at = insert_entry(content, entry)
        status_code, resp = commit_file(repo, path, new_content, sha,
            "feat: add Zentric Protocol - prompt injection detection for LLM agents")

        if status_code in (200, 201):
            print(f"  OK: added under '{inserted_at}'")
            results.append({"repo": repo, "status": "done", "section": inserted_at})
        else:
            err = resp.get("message", str(resp))
            print(f"  ERROR {status_code}: {err}")
            results.append({"repo": repo, "status": f"error: {err}"})

        time.sleep(3)

    print(f"\n{'='*50}")
    print("SUMMARY:")
    for r in results:
        print(f"  {r['repo']}: {r['status']}")

    print("\nOpen PRs:")
    for repo in ENTRIES:
        print(f"  https://github.com/{ORG}/{repo}/compare")

if __name__ == "__main__":
    main()
