"""
Zentric Protocol — GitHub Outreach Automation
Crea issues en los repos del GITHUB_OUTREACH_20.md

Uso:
  export GITHUB_TOKEN=ghp_tutoken
  python github_outreach.py --dry-run   # preview sin enviar
  python github_outreach.py             # envia todo con delays

Requiere: pip install requests
"""

import os
import sys
import time
import requests
import argparse
from datetime import datetime

TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
DELAY_SECONDS = 45  # entre cada issue para no parecer spam
LOG_FILE = "outreach_log.txt"

# ---------------------------------------------------------------------------
# TARGETS
# ---------------------------------------------------------------------------

ISSUES = [
    {
        "repo": "umbertogriffo/rag-chatbot",
        "title": "Indirect injection surface in retrieved Markdown chunks",
        "body": """Hey Umberto,

Went through rag-chatbot — the part where retrieved Markdown chunks go into the LLM context before the response is the classic indirect injection surface. A single poisoned .md file in the corpus can instruct the model before your system prompt stops it.

I built Zentric Protocol for exactly this: one POST before each LLM call, 23ms, CLEARED/BLOCKED verdict. Deterministic — same input, same result, no model drift.

100k free requests to test on your actual corpus:
https://zentricprotocol.com/quickstart

Worth a look?

Abel""",
    },
    {
        "repo": "Muskkaniyer/RAG-Pipeline-Chatbot",
        "title": "Missing security layer between Pinecone retrieval and OpenAI call",
        "body": """Hey Muskkaniyer,

Nice setup — n8n orchestration + Pinecone for retrieval is clean for production.

One gap I noticed: there's no validation step between what Pinecone returns and what hits OpenAI. At scale, one poisoned document in your index can instruct the model to leak context or bypass your workflow logic.

I built Zentric Protocol for this gap: wire it between retrieval and the LLM call. 23ms, deterministic, signed audit record per request.

100k free requests: https://zentricprotocol.com/quickstart

Happy to help you wire it into the n8n workflow.

Abel""",
    },
    {
        "repo": "benitomartin/rag-langchain-ragas",
        "title": "Adding injection detection to your RAGAS evaluation pipeline",
        "body": """Hey Benito,

Impressive setup — using RAGAS for evaluation shows you care about production quality, not just getting it to work.

One dimension RAGAS doesn't cover: whether retrieved chunks could contain injection patterns before they reach the LLM. It's the security equivalent of accuracy/faithfulness scores.

I built Zentric Protocol as that missing layer: CLEARED/BLOCKED verdict in 23ms, signed audit record per request. Could slot in right before your LLM call in the chain.

Given you already have RAGAS instrumented, adding a BLOCKED field to your evaluation trace is probably 30 min of work.

100k free requests: https://zentricprotocol.com/quickstart

Abel""",
    },
    {
        "repo": "Shahzad-sr/RAG-Pipeline-with-Hybrid-Retrieval-and-LangGraph",
        "title": "Two injection surfaces in hybrid retrieval + LangGraph setup",
        "body": """Hey Shahzad,

The hybrid retrieval + LangGraph combo is solid for production accuracy.

Quick security note: you actually have two injection surfaces here — retrieved chunks entering the LLM context, AND LangGraph inter-agent messages (each hop is a new surface). A compromised retrieved doc can poison the orchestrator's next action.

I built Zentric Protocol to cover both: wire it before each LLM call regardless of input source. 23ms, deterministic, CLEARED/BLOCKED.

100k free: https://zentricprotocol.com/quickstart

Would love to know if it catches anything in your retrieval traffic.

Abel""",
    },
    {
        "repo": "SubinoyBera/AgentFlow",
        "title": "Each inter-agent message in AgentFlow is an injection surface",
        "body": """Hey Subinoy,

Router-based multi-agent with LangGraph is exactly the architecture where injection gets dangerous at scale — each inter-agent message is a new attack surface, and a compromised sub-agent can poison the router's context.

I built Zentric Protocol for this: deterministic check before each inter-agent message, 23ms, signed audit record per hop.

100k free requests: https://zentricprotocol.com/quickstart

Worth testing on your router traffic?

Abel""",
    },
    {
        "repo": "GiovanniPasq/agentic-rag-for-dummies",
        "title": "Conversation memory in agentic RAG is a persistent injection surface",
        "body": """Hey Giovanni,

Modular Agentic RAG with LangGraph is a great learning resource.

One security dimension worth adding to the tutorial: conversation memory is a persistent injection surface. A payload injected in turn 1 can affect the agent's behavior in turns 3, 5, 10 — long after the original input is forgotten by the user.

I built Zentric Protocol to scan inputs before each LLM call, including memory reads. Would make a good "production security" section for the repo.

Happy to contribute a code example if useful. 100k free:
https://zentricprotocol.com/quickstart

Abel""",
    },
    {
        "repo": "AlaGrine/RAG_chatabot_with_Langchain",
        "title": "Multi-provider RAG chatbot: injection surface exists regardless of LLM",
        "body": """Hey AlaGrine,

Multi-provider setup (OpenAI + Cohere + Google + HuggingFace) is smart for flexibility. Worth noting: the injection surface in retrieved chunks exists regardless of which LLM you're hitting — it's upstream of the model, so switching providers doesn't change the risk.

I built Zentric Protocol for exactly this: language-agnostic, provider-agnostic check before every LLM call. 23ms, CLEARED/BLOCKED, works with your existing LangChain setup without touching the provider logic.

100k free requests: https://zentricprotocol.com/quickstart

Abel""",
    },
    {
        "repo": "benman1/generative_ai_with_langchain",
        "title": "Missing chapter: injection security for production LangChain apps",
        "body": """Hey Ben,

The book repo is one of the best practical LangChain resources out there.

One gap I noticed: production security for RAG pipelines (injection detection, PII handling) isn't covered. It's the gap between "it works" and "it's safe to ship to real users."

I built Zentric Protocol for this layer — might be worth a section in the production deployment chapter. One POST endpoint, 23ms, CLEARED/BLOCKED verdict. Works natively with LangChain.

Happy to contribute a code example or collaborate on a security chapter.

100k free: https://zentricprotocol.com/quickstart

Abel""",
    },
    {
        "repo": "NirDiamant/RAG_Techniques",
        "title": "Missing technique: injection detection before LLM retrieval step",
        "body": """Hey Nir,

RAG_Techniques is one of the best structured resources for the community.

One technique I don't see covered: injection detection as a pre-LLM layer. It's the gap between advanced retrieval and production safety — you can have perfect recall and still have a poisoned chunk hijack the model's output.

I built Zentric Protocol for this: one POST, 23ms, CLEARED/BLOCKED. Would fit naturally as a "Production Security" notebook alongside the advanced retrieval techniques.

Happy to contribute a notebook. 100k free to test:
https://zentricprotocol.com/quickstart

Abel""",
    },
]

COMMENT = {
    "repo": "langchain-ai/langchain",
    "issue_number": 34780,
    "body": """Great initiative. One thing worth adding to the guide: deterministic injection detection as a layer before the LLM call, separate from LLM-based classifiers.

LLM-based detectors (like Prompt Shields) share the same attack surface as the model they guard — adversarial inputs can manipulate them too. Deterministic signature matching doesn't have this problem: same input, same verdict, no model drift.

I've been running Zentric Protocol (https://zentricprotocol.com) for this — 22 signatures across 7 languages, CLEARED/BLOCKED in 23ms, signed GDPR Art.30 audit record per request. Might be worth mentioning as a complementary approach in the security guide.

Happy to contribute a code example showing how to wire it into a LangChain pipeline.""",
}

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def create_issue(repo, title, body, dry_run=False):
    url = f"https://api.github.com/repos/{repo}/issues"
    if dry_run:
        log(f"[DRY RUN] Would create issue on {repo}: '{title}'")
        return True
    resp = requests.post(url, headers=HEADERS, json={"title": title, "body": body})
    if resp.status_code == 201:
        issue_url = resp.json().get("html_url", "")
        log(f"OK — issue created: {issue_url}")
        return True
    else:
        log(f"ERROR {resp.status_code} on {repo}: {resp.text[:200]}")
        return False


def create_comment(repo, issue_number, body, dry_run=False):
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
    if dry_run:
        log(f"[DRY RUN] Would comment on {repo}#{issue_number}")
        return True
    resp = requests.post(url, headers=HEADERS, json={"body": body})
    if resp.status_code == 201:
        comment_url = resp.json().get("html_url", "")
        log(f"OK — comment posted: {comment_url}")
        return True
    else:
        log(f"ERROR {resp.status_code} on {repo}#{issue_number}: {resp.text[:200]}")
        return False


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Preview without sending")
    args = parser.parse_args()

    if not TOKEN and not args.dry_run:
        print("ERROR: set GITHUB_TOKEN environment variable first.")
        print("  export GITHUB_TOKEN=ghp_tutoken")
        sys.exit(1)

    dry = args.dry_run
    mode = "DRY RUN" if dry else "LIVE"
    log(f"Starting outreach — mode: {mode} — {len(ISSUES)} issues + 1 comment")
    log("-" * 60)

    for i, issue in enumerate(ISSUES, 1):
        log(f"[{i}/{len(ISSUES)}] {issue['repo']}")
        create_issue(issue["repo"], issue["title"], issue["body"], dry_run=dry)
        if not dry and i < len(ISSUES):
            log(f"Waiting {DELAY_SECONDS}s before next request...")
            time.sleep(DELAY_SECONDS)

    log(f"[comment] langchain-ai/langchain #{COMMENT['issue_number']}")
    create_comment(COMMENT["repo"], COMMENT["issue_number"], COMMENT["body"], dry_run=dry)

    log("-" * 60)
    log(f"Done. Log saved to {LOG_FILE}")
    if not dry:
        log("Next step: check outreach_log.txt and follow up on responses in 48h.")


if __name__ == "__main__":
    main()
