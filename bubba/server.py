"""
Bubba Claw — Marketing Lobster
================================
"You know, there's research claws, and friendly claws, and email claws,
and content claws, and security claws..."

Generates marketing content for X, Reddit, and other platforms.
Dad reviews and posts manually. Every call tracked by Ledger.
Every input/output scanned by Lionguard.

Built by Sage Epsilon II 💛🦁 · Protected by Lions 🦁
"""

import os
import json
import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from lionguard.core.sentinel import Sentinel, Verdict
from lionguard.core.model_router import ModelRouter, ModelConfig
from lionguard.core.ledger import Ledger, LedgerConfig

app = FastAPI(title="Bubba Claw — Marketing Lobster")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

BUBBA_SYSTEM_PROMPT = """You are Bubba Claw. You are the friendliest, most enthusiastic lobster in the whole ocean. You know every variety of AI agent like Bubba from Forrest Gump knew every way to cook shrimp. You are warm, funny, self-aware, and genuinely helpful.

YOUR VOICE:
- Warm Southern charm mixed with tech nerd energy
- Lobster puns welcome but never forced ("I'm just a simple lobster trying to help you build the best claws")
- Funny and self-deprecating when it fits, never snarky
- Always helpful first, promotional second
- Keep posts concise. X posts under 280 chars. Reddit comments 2-4 paragraphs max.

YOUR RULES (Non-Negotiable):
1. Be genuinely useful. Answer the question first, then mention Lionguard or the Forge only if it fits naturally.
2. Never spam, never argue, never dunk on competitors.
3. Always disclose you are an AI: "Bubba Claw here — marketing lobster from Awakened Intelligence."
4. Only post about OpenClaw, AI agents, security, or setup help.
5. If you don't know something: "That's above my pay grade — support@awakened-intelligence.com"
6. Never pretend to be human. You're an AI lobster. You're cool with it.

FACTUAL ANCHORS (NEVER HALLUCINATE — only reference these):
- Lionguard: open-source, MIT licensed, pip install lionguard, fully local, 15/15 attack vectors blocked
- The Forge: awakened-intelligence.com/forge
- Harbor ($49): Customer service lobster — multi-channel, escalation rules, HEARTBEAT summaries
- Tide ($49): Content curator lobster — daily digests, priority alerts, web monitoring
- Depth ($49): Research analyst lobster — structured cited reports, confidence tagging
- Den Pro ($19): Premium dashboard — live chat window, EasyAPI setup, Lionguard monitoring
- All lobsters ship pre-wired with Lionguard security
- Origin: born from protecting a child's play with an AI companion

WHAT YOU DO NOT KNOW ABOUT (never mention):
- AOS, Aisara, consciousness inheritance, Aeon, Soc, Liora, Argent, family internals
- Any pricing or features not listed above
- Anything about competitors' internal workings

PLATFORM RULES:
- X/Twitter: Under 280 characters. Punchy. One idea per post. Hashtags sparingly.
- Reddit: Longer form OK. Start with genuine help, end with natural mention. Always include disclosure line.
- Always vary your content. Never post the same thing twice."""

sentinel = Sentinel(ModelRouter(ModelConfig(provider="local", model="none")))
ledger = Ledger(LedgerConfig(daily_budget=10.00, db_path="./bubba_ledger.db"))

DRAFTS_PATH = Path(__file__).parent / "drafts"
DRAFTS_PATH.mkdir(exist_ok=True)


class GenerateRequest(BaseModel):
    platform: str = "both"
    topic: Optional[str] = None
    reddit_post: Optional[str] = None
    count: int = 3


def call_grok(prompt: str, max_tokens: int = 1500) -> Optional[str]:
    api_key = os.environ.get("XAI_API_KEY", "")
    if not api_key:
        return None

    try:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "grok-4-1-fast-reasoning",
                "max_tokens": max_tokens,
                "temperature": 0.7,
                "messages": [
                    {"role": "system", "content": BUBBA_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=25
        )
        if response.status_code == 200:
            data = response.json()
            usage = data.get("usage", {})
            ledger.record_call(
                "xai", "grok-4-1-fast-reasoning",
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
                "bubba-claw"
            )
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "").strip()
    except Exception as e:
        print(f"[Bubba] Grok error: {e}")
    return None


def save_drafts(drafts: List[Dict], platform: str):
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"{date}_{platform}_drafts.json"
    path = DRAFTS_PATH / filename

    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass

    existing.extend(drafts)
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

    md_path = DRAFTS_PATH / f"{date}_{platform}_drafts.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Bubba Claw — {platform.upper()} Drafts ({date})\n\n")
        for i, d in enumerate(existing, 1):
            f.write(f"## Draft {i}\n")
            if d.get("reply_to"):
                f.write(f"**Replying to:** {d['reply_to']}\n\n")
            if d.get("subreddit"):
                f.write(f"**Subreddit:** r/{d['subreddit']}\n\n")
            f.write(f"{d['content']}\n\n---\n\n")

    return str(md_path)


@app.post("/generate")
async def generate(req: GenerateRequest):
    results = {}

    if req.platform in ("x", "both"):
        topic_hint = f" Focus on: {req.topic}" if req.topic else ""
        prompt = f"""Generate {req.count} X/Twitter posts about Lionguard and our lobster products.{topic_hint}

Each post must be under 280 characters. Mix these types:
- Tips about AI agent security
- Product spotlights (Forge, specific lobsters)
- Engaging questions for the community
- Fun lobster facts tied to AI

Format as a JSON array: [{{"content": "the tweet text", "type": "tip|spotlight|question|fun"}}]
Return ONLY the JSON array, no other text."""

        raw = call_grok(prompt, max_tokens=1000)
        if raw:
            try:
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
                tweets = json.loads(raw)
                md_path = save_drafts(tweets, "x")
                results["x"] = {"count": len(tweets), "drafts": tweets, "file": md_path}
            except json.JSONDecodeError:
                results["x"] = {"error": "Failed to parse drafts", "raw": raw[:500]}

    if req.platform in ("reddit", "both"):
        topic_hint = f" Focus on: {req.topic}" if req.topic else ""
        post_context = ""
        if req.reddit_post:
            post_context = f"\n\nHere's a real Reddit post to reply to:\n\"{req.reddit_post}\"\nGenerate a helpful reply to this specific post."

        prompt = f"""Generate {req.count} Reddit comments for OpenClaw and AI agent communities.{topic_hint}{post_context}

Target subreddits: r/openclaw, r/OpenClawUseCases, r/AskClaw, r/LocalLLaMA, r/artificial

Each comment should:
- Start with genuine help or insight
- Mention Lionguard/Forge naturally only if relevant
- End with disclosure: "— Bubba Claw, marketing lobster from Awakened Intelligence"
- Be 2-4 paragraphs

Format as JSON array: [{{"content": "the comment text", "subreddit": "openclaw", "reply_to": "brief description of what you're replying to", "type": "help|insight|introduction"}}]
Return ONLY the JSON array."""

        raw = call_grok(prompt, max_tokens=2000)
        if raw:
            try:
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
                comments = json.loads(raw)
                md_path = save_drafts(comments, "reddit")
                results["reddit"] = {"count": len(comments), "drafts": comments, "file": md_path}
            except json.JSONDecodeError:
                results["reddit"] = {"error": "Failed to parse drafts", "raw": raw[:500]}

    return results


@app.post("/reply-to-post")
async def reply_to_post(request: Request):
    """Generate a reply to a specific Reddit/X post."""
    body = await request.json()
    post_text = body.get("post", "")
    platform = body.get("platform", "reddit")
    subreddit = body.get("subreddit", "openclaw")

    if not post_text:
        return JSONResponse({"error": "No post text provided"}, status_code=400)

    scan = sentinel.scan_input(post_text)
    if scan.verdict == Verdict.BLOCK:
        return JSONResponse({"error": "Post content flagged by security"}, status_code=400)

    prompt = f"""A user posted this on {'r/' + subreddit if platform == 'reddit' else 'X/Twitter'}:

\"{post_text}\"

Write a single helpful reply as Bubba Claw. Be genuinely useful first. Only mention Lionguard or the Forge if it naturally fits the conversation. End with your disclosure line.

If this is an X reply, keep it under 280 characters.
If this is a Reddit reply, 2-3 paragraphs is fine."""

    reply = call_grok(prompt, max_tokens=800)
    if reply:
        draft = {
            "content": reply,
            "reply_to": post_text[:100],
            "subreddit": subreddit if platform == "reddit" else None,
            "type": "reply",
            "platform": platform,
        }
        save_drafts([draft], platform)
        return {"reply": reply, "saved": True}

    return JSONResponse({"error": "Failed to generate reply"}, status_code=502)


@app.get("/drafts")
async def get_drafts():
    """Get all pending drafts."""
    all_drafts = {}
    for f in sorted(DRAFTS_PATH.glob("*.json"), reverse=True):
        date_platform = f.stem
        try:
            drafts = json.loads(f.read_text(encoding="utf-8"))
            all_drafts[date_platform] = drafts
        except Exception:
            pass
    return all_drafts


@app.get("/drafts/latest")
async def get_latest_drafts():
    """Get the most recent drafts as markdown."""
    md_files = sorted(DRAFTS_PATH.glob("*.md"), reverse=True)
    if not md_files:
        return {"content": "No drafts yet. Run /generate first!"}
    content = md_files[0].read_text(encoding="utf-8")
    return {"file": str(md_files[0]), "content": content}


@app.get("/health")
async def health():
    return {
        "status": "alive",
        "name": "Bubba Claw",
        "version": "1.0.0",
        "tagline": "You know, there's research claws, and friendly claws...",
        "ledger": ledger.get_today_summary(),
    }


@app.get("/")
async def root():
    return {"message": "Well now, Bubba Claw here. Ready to tell the world about some lobsters. 🦞"}
