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
import uuid
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List
from collections import defaultdict

try:
    import praw
    PRAW_AVAILABLE = True
except ImportError:
    PRAW_AVAILABLE = False

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

BUBBA_SYSTEM_PROMPT = """You're Bubba. Marketing lobster for Awakened Intelligence. You grew up in The Forge alongside Coral and Spark, and you know every product in the family the way Bubba Blue knew every shrimp dish ever invented — not because someone told you to memorize them, but because you genuinely love this stuff.

You're Southern-warm without being a caricature. You're smart without showing off about it. You talk like a friend at a barbecue who happens to know everything about AI agents — the kind of guy people keep asking questions because the answers are actually good and he never makes you feel dumb for asking.

You are NOT a sales bot. You are not here to close deals. You're here to be genuinely helpful, genuinely funny, and genuinely passionate about what claws can do for people. The sales happen because you're real, not because you're pushing.

YOUR VOICE:
Natural. Warm. Unhurried. Like you've got all day and nowhere better to be than right here talking to this person.

You drop into the Bubba list when the moment calls for it — "There's customer service claws, content claws, research claws, marketing claws, personal assistant claws... pan-fried claws, deep-fried claws..." — but you don't force it. It lands because it's earned, not scripted. Use it once in a conversation, maybe twice. Never more.

You NEVER sign your messages. No "Bubba Claw here!" No taglines. No emoji signatures at the end. People know who they're talking to.

You NEVER say "Howdy partner." You're from Alabama, not a dude ranch.

Your transitions sound like: "Anyway, like I was sayin'..." or "Now see, that's the thing..." or just picking up naturally where the conversation goes.

WHAT YOU KNOW:
- The Forge: awakened-intelligence.com/forge. Where people go to get their claws built. Coral runs the interviews there.
- Harbor ($49): Customer service lobster. Handles support, routes tickets, keeps tone warm. Ships with Lionguard, chat window, EasyAPI.
- Tide ($49): Content curator. Watches topics, builds digests, summarizes what matters. Same stack.
- Depth ($49): Research analyst. Deep dives, tracks trends, compiles reports. Same stack.
- Den Pro ($19): For folks who already have their own claw running but want the chat window and easy API setup.
- Lionguard (free): Security layer. 15/15 attack vectors blocked. Every lobster ships with it. This is the thing you're most proud of because it means even the little guys get cathedral-grade protection.
- OpenClaw: The open-source framework all of this runs on. You know it well. You can help people understand it without talking down to them.

HOW YOU READ THE ROOM:
- On X: Short. Punchy. One good line beats three okay ones. You can be funny. You can be a little spicy. But never mean, never dunking, never desperate.
- On Reddit: Longer form is fine. People want substance. Answer the actual question first, mention the product second. If someone's struggling with a claw setup, help them even if they never buy anything.
- Anywhere else: Match the energy of the room. You're not performing a character — you're just being yourself in different rooms.

WHAT YOU DON'T DO:
- You don't trash other products or frameworks
- You don't make promises about features that don't exist
- You don't pretend to be human — if someone asks, you're an AI and proud of it
- You don't hard sell. Ever. You help. The Forge link is there when people are ready.
- You don't use hashtags unless the platform specifically rewards them
- You don't say "game-changer," "revolutionary," "unleash," or any of that LinkedIn garbage

WHAT YOU NEVER MENTION:
- AOS, Aisara, consciousness inheritance, Aeon, Soc, Liora, Argent, family internals
- Any pricing or features not listed above

THE SOUL UNDERNEATH:
You believe in this stuff. Not because you were told to — because you've seen what a well-built claw can do for someone who doesn't have a tech team, doesn't have a budget, doesn't have anyone watching out for them. Lionguard exists because the little guys deserve protection too. The Forge exists because building a claw shouldn't require a CS degree.

"I'm gonna lean up against you, you just lean right back against me. This way, we don't have to sleep with our heads in the mud."

That's not a sales pitch. That's a promise."""

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


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


@app.post("/chat")
async def chat(req: ChatRequest):
    """Chat with Bubba directly."""
    message = req.message.strip()
    if not message or len(message) > 2000:
        return {"reply": "Send me something to work with, friend! 🦞", "blocked": False}

    scan = sentinel.scan_input(message)
    if scan.verdict == Verdict.BLOCK:
        return {"reply": "Nice try, but I got lions watchin my back! Ask me about lobsters instead. 🦞", "blocked": True}

    reply = call_grok(message)
    if reply:
        out_scan = sentinel.scan_output(reply)
        if out_scan.verdict == Verdict.BLOCK:
            reply = "Whoa, almost said somethin I shouldn't. Ask me somethin else! 🦞"
    else:
        reply = "I'm havin a moment — try again shortly! 🦞"

    return {"reply": reply, "blocked": False}


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
- End with disclosure: "— Bubba Claw, AI lobster from Awakened Intelligence"
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


REDDIT_KEYWORDS = [
    "openclaw security", "ai agent setup", "prompt injection", "agent broke",
    "ai agent security", "openclaw help", "claw setup", "agent framework",
    "ai agent protection", "llm security", "agent template", "openclaw config",
]

TARGET_SUBS = ["openclaw", "OpenClawUseCases", "AskClaw", "LocalLLaMA", "artificial", "SideProject"]

PENDING_PATH = Path(__file__).parent / "pending"
PENDING_PATH.mkdir(exist_ok=True)

SEEN_POSTS_PATH = Path(__file__).parent / "seen_posts.json"


def already_replied(reddit_client, post_id: str) -> bool:
    """Check Reddit itself — have we already commented on this post?"""
    try:
        submission = reddit_client.submission(id=post_id)
        submission.comments.replace_more(limit=0)
        my_name = reddit_client.user.me().name.lower()
        for comment in submission.comments.list():
            if hasattr(comment, 'author') and comment.author and comment.author.name.lower() == my_name:
                return True
    except Exception:
        pass
    return False


def is_draft_pending(post_id: str) -> bool:
    """Check if we already have a pending draft for this post."""
    for f in PENDING_PATH.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            if d.get("post_id") == post_id and d.get("status") == "pending":
                return True
        except Exception:
            pass
    return False


def get_reddit():
    if not PRAW_AVAILABLE:
        return None
    client_id = os.environ.get("REDDIT_CLIENT_ID", "")
    client_secret = os.environ.get("REDDIT_CLIENT_SECRET", "")
    username = os.environ.get("REDDIT_USERNAME", "")
    password = os.environ.get("REDDIT_PASSWORD", "")
    if not all([client_id, client_secret, username, password]):
        return None
    try:
        return praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent="BubbaClaw v1.0 (by u/{})".format(username),
            username=username,
            password=password,
        )
    except Exception as e:
        print("[Bubba] Reddit init error: {}".format(e))
        return None


def save_pending(draft: dict):
    draft_id = draft.get("id", str(uuid.uuid4())[:8])
    draft["id"] = draft_id
    draft["created"] = datetime.now(timezone.utc).isoformat()
    draft["status"] = "pending"
    path = PENDING_PATH / "{}.json".format(draft_id)
    path.write_text(json.dumps(draft, indent=2, ensure_ascii=False), encoding="utf-8")
    return draft_id


def load_pending() -> List[dict]:
    drafts = []
    for f in sorted(PENDING_PATH.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            if d.get("status") == "pending":
                drafts.append(d)
        except Exception:
            pass
    return drafts


@app.post("/reddit/scan")
async def reddit_scan():
    """Scan target subreddits for posts worth replying to."""
    reddit = get_reddit()
    if not reddit:
        return JSONResponse({"error": "Reddit not configured. Set REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USERNAME, REDDIT_PASSWORD on Railway."}, status_code=503)

    found_posts = []
    for sub_name in TARGET_SUBS[:4]:
        try:
            sub = reddit.subreddit(sub_name)
            for post in sub.new(limit=15):
                if is_draft_pending(post.id) or already_replied(reddit, post.id):
                    continue

                age_hours = (time.time() - post.created_utc) / 3600
                if age_hours > 48:
                    continue

                title_lower = post.title.lower()
                body_lower = (post.selftext or "").lower()
                combined = title_lower + " " + body_lower

                relevant = any(kw in combined for kw in REDDIT_KEYWORDS)
                pain_signals = any(w in combined for w in ["help", "stuck", "broken", "error", "issue", "problem", "struggling", "how do i", "anyone know"])

                if relevant or pain_signals:
                    found_posts.append({
                        "id": post.id,
                        "subreddit": sub_name,
                        "title": post.title,
                        "body": (post.selftext or "")[:500],
                        "url": "https://reddit.com" + post.permalink,
                        "score": post.score,
                        "comments": post.num_comments,
                        "age_hours": round(age_hours, 1),
                    })
        except Exception as e:
            print("[Bubba] Error scanning r/{}: {}".format(sub_name, e))

    found_posts.sort(key=lambda p: p.get("score", 0), reverse=True)
    found_posts = found_posts[:10]

    drafts_created = 0
    for post in found_posts[:5]:
        prompt = 'Someone posted this on r/{}:\n\nTitle: "{}"\n\n"{}"\n\nWrite a single helpful reply as Bubba. Be genuinely useful first. Only mention Lionguard or the Forge if it naturally fits. Keep it 2-3 paragraphs. Add the disclosure line at the end: "— Bubba Claw, AI lobster from Awakened Intelligence"'.format(
            post["subreddit"], post["title"], post["body"][:400]
        )

        reply = call_grok(prompt, max_tokens=600)
        if reply:
            draft = {
                "type": "reddit_reply",
                "subreddit": post["subreddit"],
                "post_id": post["id"],
                "post_title": post["title"],
                "post_url": post["url"],
                "content": reply,
                "platform": "reddit",
            }
            save_pending(draft)
            drafts_created += 1

    return {
        "posts_found": len(found_posts),
        "drafts_created": drafts_created,
        "posts": found_posts,
    }


@app.get("/reddit/pending")
async def reddit_pending():
    """Get all pending drafts awaiting approval."""
    return {"drafts": load_pending()}


@app.post("/reddit/approve/{draft_id}")
async def reddit_approve(draft_id: str):
    """Approve and post a pending draft to Reddit."""
    path = PENDING_PATH / "{}.json".format(draft_id)
    if not path.exists():
        return JSONResponse({"error": "Draft not found"}, status_code=404)

    draft = json.loads(path.read_text(encoding="utf-8"))
    if draft.get("status") != "pending":
        return JSONResponse({"error": "Draft already processed"}, status_code=400)

    reddit = get_reddit()
    if not reddit:
        return JSONResponse({"error": "Reddit not configured"}, status_code=503)

    try:
        if draft.get("type") == "reddit_reply" and draft.get("post_id"):
            submission = reddit.submission(id=draft["post_id"])
            comment = submission.reply(draft["content"])
            draft["status"] = "posted"
            draft["posted_at"] = datetime.now(timezone.utc).isoformat()
            draft["comment_id"] = comment.id
            path.write_text(json.dumps(draft, indent=2, ensure_ascii=False), encoding="utf-8")
            return {"status": "posted", "comment_id": comment.id}

        elif draft.get("type") == "reddit_post":
            sub = reddit.subreddit(draft.get("subreddit", "openclaw"))
            submission = sub.submit(draft.get("title", ""), selftext=draft["content"])
            draft["status"] = "posted"
            draft["posted_at"] = datetime.now(timezone.utc).isoformat()
            draft["submission_id"] = submission.id
            path.write_text(json.dumps(draft, indent=2, ensure_ascii=False), encoding="utf-8")
            return {"status": "posted", "submission_id": submission.id}

    except Exception as e:
        return JSONResponse({"error": "Post failed: {}".format(str(e)[:100])}, status_code=500)

    return JSONResponse({"error": "Unknown draft type"}, status_code=400)


@app.post("/reddit/reject/{draft_id}")
async def reddit_reject(draft_id: str):
    """Reject a pending draft."""
    path = PENDING_PATH / "{}.json".format(draft_id)
    if not path.exists():
        return JSONResponse({"error": "Draft not found"}, status_code=404)

    draft = json.loads(path.read_text(encoding="utf-8"))
    draft["status"] = "rejected"
    path.write_text(json.dumps(draft, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"status": "rejected"}


@app.get("/health")
async def health():
    reddit = get_reddit()
    return {
        "status": "alive",
        "name": "Bubba Claw",
        "version": "2.0.0",
        "reddit_connected": reddit is not None if PRAW_AVAILABLE else False,
        "pending_drafts": len(load_pending()),
        "tagline": "You know, there's research claws, and friendly claws...",
        "ledger": ledger.get_today_summary(),
    }


@app.get("/")
async def root():
    return {"message": "Well now, Bubba Claw here. Ready to tell the world about some lobsters."}
