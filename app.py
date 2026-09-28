from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import DateTime, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
DEFAULT_DATABASE_URL = (
    "sqlite:////tmp/fraud_desk.db"
    if os.getenv("VERCEL")
    else "sqlite:///./data/fraud_desk.db"
)

class Settings(BaseSettings):
    app_name: str = "FRAUD DESK"
    environment: str = "development"
    host: str = "0.0.0.0"
    port: int = 8000
    database_url: str = DEFAULT_DATABASE_URL

    hindsight_base_url: str = "https://api.hindsight.vectorize.io"
    hindsight_api_key: str = ""
    hindsight_bank_id: str = "fraud-desk"
    hindsight_timeout_seconds: float = 30.0

    llm_provider: str = "groq"
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"
    llm_fallback_model: str = "qwen/qwen3-32b"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    llm_timeout_seconds: float = 45.0

    dispatch_webhook_url: str = ""
    dispatch_bearer_token: str = ""
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

# SQLite needs a writable directory on Vercel.
if settings.database_url.startswith("sqlite:////tmp/"):
    Path("/tmp").mkdir(parents=True, exist_ok=True)
elif settings.database_url.startswith("sqlite:///./"):
    (ROOT / "data").mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    channel: Mapped[str] = mapped_column(String(40), index=True)
    sender_id: Mapped[str] = mapped_column(String(255), default="")
    raw_message: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="OPEN", index=True)
    baseline_score: Mapped[int] = mapped_column(Integer, default=0)
    memory_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence_delta: Mapped[int] = mapped_column(Integer, default=0)
    threat_level: Mapped[str] = mapped_column(String(20), default="LOW")
    campaign: Mapped[str] = mapped_column(String(120), default="UNKNOWN")
    rationale: Mapped[str] = mapped_column(Text, default="")
    memory_attribution: Mapped[str] = mapped_column(Text, default="")
    iocs_json: Mapped[str] = mapped_column(Text, default="{}")
    recall_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Verdict(Base):
    __tablename__ = "verdicts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    analyst: Mapped[str] = mapped_column(String(120), default="analyst")
    verdict: Mapped[str] = mapped_column(String(50))
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Dispatch(Base):
    __tablename__ = "dispatches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    artifact_type: Mapped[str] = mapped_column(String(80))
    destination: Mapped[str] = mapped_column(String(255), default="LOCAL_EXPORT")
    status: Mapped[str] = mapped_column(String(30), default="CREATED")
    response: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)


def serialize_case(c: Case) -> dict[str, Any]:
    return {
        "id": c.id,
        "channel": c.channel,
        "sender_id": c.sender_id,
        "raw_message": c.raw_message,
        "status": c.status,
        "baseline_score": c.baseline_score,
        "memory_score": c.memory_score,
        "confidence_delta": c.confidence_delta,
        "threat_level": c.threat_level,
        "campaign": c.campaign,
        "rationale": c.rationale,
        "memory_attribution": c.memory_attribution,
        "iocs": json.loads(c.iocs_json or "{}"),
        "recall": json.loads(c.recall_json or "[]"),
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }

# -----------------------------------------------------------------------------
# IOC extraction
# -----------------------------------------------------------------------------

PATTERNS = {
    "upi_ids": re.compile(r"(?<![\w.-])[A-Za-z0-9._-]{2,64}@[A-Za-z0-9._-]+\b", re.I),
    "phone_numbers": re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"),
    "whatsapp_handles": re.compile(r"(?<!\w)wa(?:\.me|atsapp)\s*[:/-]?\s*([+\d][\d\s-]{7,18})", re.I),
    "telegram_handles": re.compile(r"(?<!\w)@([A-Za-z][A-Za-z0-9_]{4,31})\b"),
    "shortcodes": re.compile(r"\b[A-Z]{2}-[A-Z0-9]{4,10}\b"),
    "urls": re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"),
}
SUSPICIOUS_TLDS = {".top", ".click", ".xyz", ".live", ".shop", ".vip", ".icu", ".tk", ".gq", ".cf"}
BRANDS = ("mseb", "mahadiscom", "sbi", "hdfc", "icici", "cbi", "customs", "income", "upi", "bank", "kyc", "youtube", "telegram")


def extract_iocs(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, pattern in PATTERNS.items():
        values = [v.strip(".,);]}") for v in pattern.findall(text)]
        if key == "telegram_handles":
            values = [f"@{v}" for v in values]
        out[key] = sorted(set(values))
    out["malicious_urls"] = []
    for url in out["urls"]:
        candidate = url if url.lower().startswith(("http://", "https://")) else "http://" + url
        try:
            host = urlparse(candidate).hostname or ""
        except ValueError:
            host = ""
        lower = host.lower()
        if any(lower.endswith(tld) for tld in SUSPICIOUS_TLDS) or any(b in lower for b in BRANDS):
            out["malicious_urls"].append(url)
    out["counts"] = {k: len(v) for k, v in out.items() if isinstance(v, list)}
    return out

# -----------------------------------------------------------------------------
# Hindsight
# -----------------------------------------------------------------------------

_hindsight_client: Any | None = None
_hindsight_available = False
_hindsight_error = ""


def hindsight_client() -> Any:
    global _hindsight_client
    if _hindsight_client is None:
        try:
            from hindsight_client import Hindsight
        except ImportError as exc:
            raise RuntimeError("hindsight-client is not installed. Run: pip install -r requirements.txt") from exc
        if not settings.hindsight_api_key:
            raise RuntimeError("HINDSIGHT_API_KEY is not configured")
        _hindsight_client = Hindsight(
            base_url=settings.hindsight_base_url,
            api_key=settings.hindsight_api_key,
            timeout=settings.hindsight_timeout_seconds,
        )
    return _hindsight_client


async def ensure_bank() -> bool:
    global _hindsight_available, _hindsight_error
    try:
        c = hindsight_client()
        # Current Hindsight SDK supports idempotent create/update with mission + disposition.
        await c.acreate_bank(
            bank_id=settings.hindsight_bank_id,
            name="Fraud Desk Intelligence",
            mission="Identify recurring fraud infrastructure, campaign evolution, analyst-confirmed patterns, and operational countermeasures across fraud cases. Be evidence-led and explicit about uncertainty.",
            disposition={"skepticism": 4, "literalism": 4, "empathy": 2},
        )
        _hindsight_available = True
        _hindsight_error = ""
        return True
    except Exception as exc:
        _hindsight_available = False
        _hindsight_error = str(exc)
        return False


def hindsight_available() -> bool:
    return _hindsight_available


async def recall_case(query: str) -> dict[str, Any]:
    if not _hindsight_available:
        return {"available": False, "items": [], "text": "Hindsight is unavailable.", "error": _hindsight_error}
    try:
        result = await hindsight_client().arecall(
            bank_id=settings.hindsight_bank_id,
            query=query,
            max_tokens=3500,
            budget="mid",
            include_chunks=False,
        )
        items = getattr(result, "results", None) or []
        serial = []
        for item in items:
            if hasattr(item, "model_dump"):
                serial.append(item.model_dump())
            elif hasattr(item, "__dict__"):
                serial.append(item.__dict__)
            else:
                serial.append(str(item))
        return {"available": True, "items": serial, "text": json.dumps(serial, ensure_ascii=False, default=str)[:14000]}
    except Exception as exc:
        return {"available": False, "items": [], "text": f"Hindsight recall failed: {exc}", "error": str(exc)}


async def retain_case(content: str, metadata: dict[str, str] | None = None, tags: list[str] | None = None) -> bool:
    if not _hindsight_available:
        return False
    try:
        await hindsight_client().aretain(
            bank_id=settings.hindsight_bank_id,
            content=content,
            metadata=metadata or {},
            tags=tags or ["fraud-desk"],
        )
        return True
    except Exception:
        return False


async def reflect_macro(query: str) -> dict[str, Any]:
    if not _hindsight_available:
        return {"available": False, "answer": "Hindsight is unavailable. Check /api/health for the connection error."}
    try:
        result = await hindsight_client().areflect(bank_id=settings.hindsight_bank_id, query=query, budget="mid")
        answer = getattr(result, "text", None) or getattr(result, "answer", None) or str(result)
        based_on = getattr(result, "based_on", None)
        return {"available": True, "answer": answer, "based_on": based_on}
    except Exception as exc:
        return {"available": False, "answer": f"Hindsight reflect failed: {exc}"}

# -----------------------------------------------------------------------------
# LLM
# -----------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a cyber-fraud triage analyst for a national fraud desk. Return strict JSON only. Never invent evidence. Separate facts observed in the message from historical memory. Score 0-100. threat_level must be CRITICAL, HIGH, MEDIUM, or LOW. campaign must be a concise taxonomy string such as STAGE_2_REMOTE_ACCESS_EXPLOIT, TASK_SCAM_UPI_FRAUD, DIGITAL_ARREST_EXTORTION, MERCHANT_REFUND_TRAP, or UNKNOWN. Provide rationale and recommended_actions as arrays. Confidence should reflect evidence quality, not certainty."""


def parse_json(text: str) -> dict[str, Any]:
    cleaned = text.strip().replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start >= 0 and end > start:
            return json.loads(cleaned[start:end + 1])
        raise


def fallback_score(message: str, iocs: dict[str, Any]) -> int:
    m = message.lower()
    score = 8
    score += min(35, len(iocs.get("malicious_urls", [])) * 20)
    score += min(24, len(iocs.get("upi_ids", [])) * 12)
    score += min(15, len(iocs.get("phone_numbers", [])) * 5)
    keywords = ("otp", "urgent", "arrest", "refund", "apk", "install", "screen share", "remote", "kyc", "verify", "payment", "qr", "telegram")
    score += min(45, sum(5 for x in keywords if x in m))
    return min(100, score)


def deterministic_campaign(message: str) -> str:
    m = message.lower()
    rules = [
        (("apk", "power", "electricity", "mseb", "mahadiscom", "remote"), "STAGE_2_REMOTE_ACCESS_EXPLOIT"),
        (("youtube", "rating", "task", "telegram", "review"), "TASK_SCAM_UPI_FRAUD"),
        (("cbi", "customs", "digital arrest", "police", "video call"), "DIGITAL_ARREST_EXTORTION"),
        (("refund", "qr", "merchant", "reverse", "upi"), "MERCHANT_REFUND_TRAP"),
    ]
    for terms, campaign in rules:
        if sum(1 for t in terms if t in m) >= 2:
            return campaign
    return "UNKNOWN"


async def groq_call(messages: list[dict[str, str]], model: str) -> str:
    if not settings.groq_api_key:
        raise RuntimeError("GROQ_API_KEY is not configured")
    headers = {"Authorization": f"Bearer {settings.groq_api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": messages, "temperature": 0.1, "response_format": {"type": "json_object"}}
    async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
        r = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


async def gemini_call(messages: list[dict[str, str]]) -> str:
    if not settings.gemini_api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured")
    prompt = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent"
    payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}}
    async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
        r = await client.post(url, params={"key": settings.gemini_api_key}, json=payload)
        r.raise_for_status()
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]


async def analyze_llm(channel: str, sender: str, message: str, iocs: dict[str, Any], memory_context: str = "") -> dict[str, Any]:
    user = f"""Channel: {channel}\nSender: {sender}\nInbound message:\n{message}\n\nExtracted IOCs:\n{json.dumps(iocs, ensure_ascii=False)}\n\nHistorical Hindsight context (treat as evidence to compare, not as unquestioned truth):\n{memory_context or 'NONE'}\n\nReturn JSON with keys: threat_score, threat_level, campaign, confidence, rationale, recommended_actions, evidence, memory_factors."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]
    try:
        provider = settings.llm_provider.lower()
        if provider == "gemini":
            raw = await gemini_call(messages)
        elif provider == "none":
            raise RuntimeError("LLM_PROVIDER=none")
        else:
            try:
                raw = await groq_call(messages, settings.groq_model)
            except Exception as first_exc:
                if settings.llm_fallback_model and settings.llm_fallback_model != settings.groq_model:
                    raw = await groq_call(messages, settings.llm_fallback_model)
                else:
                    raise first_exc
        data = parse_json(raw)
    except Exception as exc:
        # Never make the whole fraud desk unavailable because an LLM call failed.
        data = {
            "threat_score": fallback_score(message, iocs),
            "threat_level": "HIGH" if fallback_score(message, iocs) >= 70 else "MEDIUM" if fallback_score(message, iocs) >= 40 else "LOW",
            "campaign": deterministic_campaign(message),
            "confidence": 55,
            "rationale": f"LLM unavailable; deterministic fraud triage used. Provider error: {str(exc)[:300]}",
            "recommended_actions": ["Preserve the original message and identifiers", "Correlate extracted IOCs with prior cases", "Require analyst review before external action"],
            "evidence": ["IOC extraction", "rule-based fraud indicators"],
            "memory_factors": [],
            "llm_error": str(exc)[:500],
        }
    data["threat_score"] = max(0, min(100, int(data.get("threat_score", 0))))
    data["confidence"] = max(0, min(100, int(data.get("confidence", 0))))
    data["recommended_actions"] = list(data.get("recommended_actions") or [])
    data["evidence"] = list(data.get("evidence") or [])
    data["memory_factors"] = list(data.get("memory_factors") or [])
    return data

# -----------------------------------------------------------------------------
# Agent
# -----------------------------------------------------------------------------


def stable_case_id(channel: str, sender: str, message: str) -> str:
    return hashlib.sha256(f"{channel}|{sender}|{message}".encode()).hexdigest()[:16]


async def triage(channel: str, sender: str, message: str, memory_enabled: bool = True) -> dict[str, Any]:
    iocs = extract_iocs(message)
    baseline = await analyze_llm(channel, sender, message, iocs, "")
    base_rule_score = fallback_score(message, iocs)
    base_campaign = deterministic_campaign(message)
    if baseline.get("threat_score", 0) == 0:
        baseline["threat_score"] = base_rule_score
    if baseline.get("campaign") in (None, "", "UNKNOWN") and base_campaign != "UNKNOWN":
        baseline["campaign"] = base_campaign

    recalled = {"available": False, "items": [], "text": ""}
    augmented = dict(baseline)
    if memory_enabled:
        query = f"Fraud case channel={channel}; sender={sender}; IOCs={json.dumps(iocs)}; message={message}"
        recalled = await recall_case(query)
        augmented = await analyze_llm(channel, sender, message, iocs, recalled.get("text", ""))
        if augmented.get("threat_score", 0) == 0:
            augmented["threat_score"] = baseline.get("threat_score", base_rule_score)
        if augmented.get("campaign") in (None, "", "UNKNOWN"):
            augmented["campaign"] = baseline.get("campaign") or base_campaign

    before = int(baseline.get("threat_score", base_rule_score))
    after = int(augmented.get("threat_score", before))
    delta = after - before
    items = recalled.get("items") or []
    matched = len(items) if isinstance(items, list) else 0
    attribution = (
        f"Matched {matched} recalled Hindsight memory item(s). Historical infrastructure, campaign patterns and analyst decisions were supplied to the consolidated assessment."
        if memory_enabled and recalled.get("available")
        else "No historical Hindsight context was available for this assessment."
    )
    return {
        "case_id": stable_case_id(channel, sender, message),
        "channel": channel,
        "sender_id": sender,
        "raw_message": message,
        "iocs": iocs,
        "baseline": baseline,
        "consolidated": augmented,
        "confidence_delta": delta,
        "memory_attribution": attribution,
        "memory_available": bool(recalled.get("available")),
        "recall": recalled,
        "campaign": augmented.get("campaign") or base_campaign,
    }


async def learn_from_verdict(case: dict[str, Any], verdict: str, analyst: str, notes: str) -> bool:
    content = (
        f"Fraud Desk analyst verdict. Case {case['id']}. Channel={case['channel']}. Sender={case['sender_id']}. "
        f"Message={case['raw_message']}. Extracted IOCs={json.dumps(case['iocs'], ensure_ascii=False)}. "
        f"Agent campaign={case['campaign']}. Agent score={case['memory_score']}. "
        f"Analyst verdict={verdict}. Analyst={analyst}. Analyst notes={notes or 'none'}. "
        "Treat this as an analyst-confirmed/overridden episode for future fraud recall."
    )
    return await retain_case(
        content,
        metadata={"case_id": case["id"], "analyst": analyst, "verdict": verdict, "campaign": case["campaign"]},
        tags=["fraud-desk", "analyst-verdict", verdict.lower()],
    )

# -----------------------------------------------------------------------------
# Operational artifacts
# -----------------------------------------------------------------------------


def artifact_header(case: dict[str, Any]) -> str:
    return f"FRAUD DESK | CASE {case['id']} | Generated {datetime.now(timezone.utc).isoformat()}"


def render_artifact(case: dict[str, Any], artifact_type: str) -> str:
    if artifact_type == "official_brief":
        return f"""{artifact_header(case)}\n\nNATIONAL CYBER FRAUD INCIDENT BRIEF\n\nClassification: {case['threat_level']}\nCampaign taxonomy: {case['campaign']}\nChannel: {case['channel']}\nSender/identifier: {case['sender_id']}\nThreat score: {case['memory_score']}/100\nHindsight confidence delta: {case['confidence_delta']:+d} points\n\nEXECUTIVE SUMMARY\n{case['rationale']}\n\nOBSERVED INDICATORS\n{json.dumps(case['iocs'], ensure_ascii=False, indent=2)}\n\nMEMORY ATTRIBUTION\n{case['memory_attribution']}\n\nRECOMMENDED ACTIONS\n- Preserve original message and metadata.\n- Correlate extracted identifiers against internal fraud cases.\n- Contact affected financial/telecom partners through established channels.\n- Preserve evidence before blocking or takedown actions.\n- Record analyst disposition in the case ledger.\n\nSOURCE MESSAGE\n{case['raw_message']}\n\nThis is an operational draft. Human authorization is required before submission to an external authority.\n"""
    if artifact_type == "takedown_notice":
        return f"""Subject: Abuse/Takedown Request — Suspected Fraud Infrastructure — Case {case['id']}\n\nTo: Abuse / Registrar Operations\n\nWe are reporting suspected fraud infrastructure associated with case {case['id']}.\n\nCampaign: {case['campaign']}\nObserved channel: {case['channel']}\nIndicators: {json.dumps(case['iocs'], ensure_ascii=False)}\nThreat score: {case['memory_score']}/100\n\nObserved activity:\n{case['rationale']}\n\nRequested action:\n1. Preserve relevant logs under your abuse/legal process.\n2. Review the reported host/domain/account for policy violations.\n3. Restrict or suspend malicious infrastructure where policy and applicable law permit.\n4. Provide the incident/ticket reference to the reporting desk.\n\nOriginal message:\n{case['raw_message']}\n\nFraud Desk case reference: {case['id']}\n"""
    if artifact_type == "customer_warning":
        return f"""SECURITY ALERT\n\nWe detected a suspected fraud attempt matching a known fraud pattern.\n\nDo not:\n- install APKs sent through unsolicited messages\n- share OTPs, PINs, passwords, CVV or screen-sharing access\n- scan an unexpected QR code to receive money\n- transfer funds to unlock a refund, job, parcel or account\n- stay on a pressure call with someone claiming to be police, customs or bank staff\n\nIf you already transferred money, contact your bank immediately and use the official cyber-fraud reporting process.\n\nCase reference: {case['id']}\n"""
    raise HTTPException(400, "Unknown artifact type")

# -----------------------------------------------------------------------------
# API models and app
# -----------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    channel: str = Field(min_length=1, max_length=40)
    sender_id: str = Field(default="", max_length=255)
    message: str = Field(min_length=3, max_length=20000)
    memory_enabled: bool = True


class VerdictRequest(BaseModel):
    case_id: str
    verdict: str = Field(min_length=2, max_length=50)
    analyst: str = Field(default="analyst", max_length=120)
    notes: str = Field(default="", max_length=5000)


class DispatchRequest(BaseModel):
    case_id: str
    artifact_type: str
    destination: str = "LOCAL_EXPORT"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await ensure_bank()
    yield


app = FastAPI(title="FRAUD DESK — Active Fraud Intelligence", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_list or ["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return INDEX_HTML


@app.get("/api/health")
def health() -> dict[str, Any]:
    with SessionLocal() as db:
        cases = db.query(func.count(Case.id)).scalar() or 0
        dispatches = db.query(func.count(Dispatch.id)).scalar() or 0
        verdicts = db.query(func.count(Verdict.id)).scalar() or 0
    return {
        "status": "ok",
        "hindsight_available": hindsight_available(),
        "hindsight_error": _hindsight_error if not hindsight_available() else "",
        "bank_id": settings.hindsight_bank_id,
        "llm_provider": settings.llm_provider,
        "llm_model": settings.groq_model if settings.llm_provider == "groq" else settings.gemini_model,
        "cases": cases,
        "verdicts": verdicts,
        "dispatches": dispatches,
    }


@app.get("/api/cases")
def list_cases(limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    with SessionLocal() as db:
        rows = db.query(Case).order_by(Case.updated_at.desc()).limit(limit).all()
        return {"items": [serialize_case(x) for x in rows]}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    with SessionLocal() as db:
        c = db.get(Case, case_id)
        if not c:
            raise HTTPException(404, "Case not found")
        return serialize_case(c)


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest) -> dict[str, Any]:
    result = await triage(req.channel, req.sender_id, req.message, req.memory_enabled)
    consolidated = result["consolidated"]
    case = Case(
        id=result["case_id"], channel=req.channel, sender_id=req.sender_id, raw_message=req.message,
        baseline_score=int(result["baseline"].get("threat_score", 0)),
        memory_score=int(consolidated.get("threat_score", 0)),
        confidence_delta=int(result["confidence_delta"]),
        threat_level=str(consolidated.get("threat_level", "LOW")).upper(),
        campaign=str(result["campaign"]), rationale=str(consolidated.get("rationale", "")),
        memory_attribution=result["memory_attribution"],
        iocs_json=json.dumps(result["iocs"], ensure_ascii=False),
        recall_json=json.dumps(result.get("recall", {}).get("items", []), ensure_ascii=False, default=str),
    )
    with SessionLocal() as db:
        existing = db.get(Case, case.id)
        if existing:
            for attr in ("channel", "sender_id", "raw_message", "baseline_score", "memory_score", "confidence_delta", "threat_level", "campaign", "rationale", "memory_attribution", "iocs_json", "recall_json"):
                setattr(existing, attr, getattr(case, attr))
            existing.updated_at = utcnow()
            db.commit()
            db.refresh(existing)
            saved = existing
        else:
            db.add(case)
            db.commit()
            db.refresh(case)
            saved = case
    result["case"] = serialize_case(saved)
    return result


@app.post("/api/verdict")
async def verdict(req: VerdictRequest) -> dict[str, Any]:
    with SessionLocal() as db:
        c = db.get(Case, req.case_id)
        if not c:
            raise HTTPException(404, "Case not found")
        c.status = "CLOSED" if req.verdict.lower() in {"confirmed", "false_positive", "closed", "fraud"} else "REVIEW"
        db.add(Verdict(case_id=req.case_id, analyst=req.analyst, verdict=req.verdict, notes=req.notes))
        db.commit()
        db.refresh(c)
        case_data = serialize_case(c)
    stored = await learn_from_verdict(case_data, req.verdict, req.analyst, req.notes)
    return {"ok": True, "hindsight_retained": stored, "case": case_data}


@app.get("/api/reflect")
async def reflect(q: str = "What are the most active fraud campaigns and repeated identifiers across recent indexed episodes?") -> dict[str, Any]:
    return await reflect_macro(q)


@app.get("/api/benchmark")
async def benchmark() -> dict[str, Any]:
    with SessionLocal() as db:
        rows = db.query(Case).filter(Case.status == "CLOSED").all()
        verdict_rows = db.query(Verdict).all()
    latest: dict[str, str] = {}
    for v in verdict_rows:
        latest[v.case_id] = v.verdict
    labeled = [r for r in rows if r.id in latest]
    if not labeled:
        return {"sample_size": 0, "message": "No closed analyst-labeled cases yet. Confirm or reject cases to build a real benchmark.", "memory_on": {}, "memory_off": {}}
    def confirmed(v: str) -> bool:
        return v.lower() in {"confirmed", "true_positive", "fraud"}
    on_acc = sum(confirmed(latest[r.id]) == (r.memory_score >= 60) for r in labeled) / len(labeled)
    off_acc = sum(confirmed(latest[r.id]) == (r.baseline_score >= 60) for r in labeled) / len(labeled)
    return {
        "sample_size": len(labeled),
        "memory_on": {"accuracy": round(on_acc * 100, 1), "avg_score": round(sum(r.memory_score for r in labeled) / len(labeled), 1)},
        "memory_off": {"accuracy": round(off_acc * 100, 1), "avg_score": round(sum(r.baseline_score for r in labeled) / len(labeled), 1)},
    }


@app.get("/api/artifacts/{case_id}/{artifact_type}")
def artifact(case_id: str, artifact_type: str) -> PlainTextResponse:
    with SessionLocal() as db:
        c = db.get(Case, case_id)
        if not c:
            raise HTTPException(404, "Case not found")
        case = serialize_case(c)
    body = render_artifact(case, artifact_type)
    return PlainTextResponse(body, headers={"Content-Disposition": f'attachment; filename="{artifact_type}-{case_id}.txt"'})


@app.post("/api/dispatch")
async def dispatch(req: DispatchRequest) -> dict[str, Any]:
    with SessionLocal() as db:
        c = db.get(Case, req.case_id)
        if not c:
            raise HTTPException(404, "Case not found")
        case = serialize_case(c)
        body = render_artifact(case, req.artifact_type)
        record = Dispatch(case_id=req.case_id, artifact_type=req.artifact_type, destination=req.destination, status="CREATED")
        db.add(record)
        db.commit()
        db.refresh(record)
        dispatch_id = record.id

    if req.destination != "LOCAL_EXPORT" and settings.dispatch_webhook_url:
        headers = {"Content-Type": "application/json"}
        if settings.dispatch_bearer_token:
            headers["Authorization"] = f"Bearer {settings.dispatch_bearer_token}"
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(settings.dispatch_webhook_url, headers=headers, json={"case": case, "artifact_type": req.artifact_type, "artifact": body})
                response.raise_for_status()
                status, response_text = "SENT", response.text[:4000]
        except Exception as exc:
            status, response_text = "FAILED", str(exc)
        with SessionLocal() as db:
            record = db.get(Dispatch, dispatch_id)
            record.status, record.response = status, response_text
            db.commit()
        return {"ok": status == "SENT", "dispatch_id": dispatch_id, "status": status, "response": response_text}

    return {"ok": True, "dispatch_id": dispatch_id, "status": "READY_FOR_AUTHORIZED_SUBMISSION", "artifact": body}


# Embedded UI: there is deliberately NO frontend directory in this project.
INDEX_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8" />\n  <meta name="viewport" content="width=device-width, initial-scale=1" />\n  <title>FRAUD DESK — Active Fraud Intelligence</title>\n  <script src="https://cdn.tailwindcss.com"></script>\n  <script>tailwind.config={theme:{extend:{colors:{navy:\'#0B0F17\',crimson:\'#FF2E63\',mint:\'#00F2FE\'}}}}</script>\n  <script src="https://unpkg.com/lucide@latest"></script>\n  <style>\n    body{background:#0B0F17;color:#e7edf7;font-family:Inter,ui-sans-serif,system-ui,sans-serif}.panel{background:#111722;border:1px solid #202a3a}.muted{color:#8190a8}.glow{box-shadow:0 0 28px rgba(0,242,254,.08)}.danger{color:#FF2E63}.mint{color:#00F2FE}.chip{border:1px solid #29354a;background:#151e2d}.score{background:conic-gradient(#FF2E63 var(--score),#263143 0)}.tab.active{border-color:#00F2FE;color:#00F2FE;background:#10202a}.scroll{scrollbar-width:thin;scrollbar-color:#334155 #0b0f17}\n  </style>\n</head>\n<body class="min-h-screen">\n<header class="border-b border-slate-800 bg-[#0b0f17]/95 sticky top-0 z-30 backdrop-blur">\n  <div class="max-w-[1600px] mx-auto px-5 py-3 flex items-center gap-5">\n    <div class="flex items-center gap-3 min-w-[260px]"><div class="w-9 h-9 rounded-lg bg-[#FF2E63]/15 border border-[#FF2E63]/40 grid place-items-center"><i data-lucide="shield-alert" class="w-5 h-5 text-[#FF2E63]"></i></div><div><div class="font-black tracking-tight">FRAUD DESK</div><div class="text-[10px] uppercase tracking-[.22em] muted">Active Fraud Intelligence Center</div></div></div>\n    <div class="flex-1 grid grid-cols-4 gap-2 text-xs"><div class="panel rounded-lg px-3 py-2"><span class="muted">Bank</span><b class="ml-2">fraud-desk</b></div><div class="panel rounded-lg px-3 py-2"><span class="muted">Cases</span><b id="metricCases" class="ml-2 mint">—</b></div><div class="panel rounded-lg px-3 py-2"><span class="muted">Hindsight</span><b id="metricHindsight" class="ml-2">CHECKING</b></div><div class="panel rounded-lg px-3 py-2"><span class="muted">Dispatches</span><b id="metricDispatches" class="ml-2">—</b></div></div>\n    <button onclick="loadAll()" class="panel rounded-lg p-2 hover:border-slate-600" title="Refresh"><i data-lucide="refresh-cw" class="w-4 h-4"></i></button>\n  </div>\n</header>\n<main class="max-w-[1600px] mx-auto p-5 space-y-5">\n  <section class="grid lg:grid-cols-[1.35fr_.65fr] gap-5">\n    <div class="panel rounded-2xl p-5 glow">\n      <div class="flex items-start justify-between gap-4"><div><div class="text-xs uppercase tracking-widest mint font-bold">Live intake</div><h1 class="text-2xl font-black mt-1">Inbound Fraud Triage</h1><p class="muted text-sm mt-1">Create a real case, compare stateless analysis with Hindsight recall, then retain the analyst decision.</p></div><label class="flex items-center gap-2 text-xs muted"><input id="memoryEnabled" type="checkbox" checked class="accent-cyan-400 w-4 h-4"> Hindsight memory</label></div>\n      <div class="grid md:grid-cols-3 gap-3 mt-5"><div><label class="text-xs muted">Channel</label><select id="channel" class="mt-1 w-full bg-[#0c121d] border border-slate-700 rounded-lg px-3 py-2"><option>SMS</option><option>WhatsApp</option><option>Telegram</option><option>Banking Portal</option><option>Phone</option><option>Email</option></select></div><div class="md:col-span-2"><label class="text-xs muted">Sender / identifier</label><input id="sender" class="mt-1 w-full bg-[#0c121d] border border-slate-700 rounded-lg px-3 py-2" placeholder="VM-MSEBPW / +9198... / @handle" /></div></div>\n      <div class="mt-3"><label class="text-xs muted">Raw inbound message</label><textarea id="message" rows="7" class="mt-1 w-full bg-[#0c121d] border border-slate-700 rounded-lg px-3 py-3 outline-none focus:border-cyan-400" placeholder="Paste the complete message, including links, UPI IDs and instructions..."></textarea></div>\n      <div class="flex flex-wrap gap-2 mt-3"><button onclick="loadScenario(0)" class="chip rounded-full px-3 py-1 text-xs">MSEB APK</button><button onclick="loadScenario(1)" class="chip rounded-full px-3 py-1 text-xs">YouTube Task</button><button onclick="loadScenario(2)" class="chip rounded-full px-3 py-1 text-xs">Digital Arrest</button><button onclick="loadScenario(3)" class="chip rounded-full px-3 py-1 text-xs">Refund QR</button></div>\n      <button id="analyzeBtn" onclick="analyze()" class="mt-4 w-full bg-[#FF2E63] hover:bg-[#e52657] rounded-xl py-3 font-black tracking-wide flex items-center justify-center gap-2"><i data-lucide="scan-search" class="w-5 h-5"></i> RUN MULTI-AGENT TRIAGE</button>\n    </div>\n    <div class="panel rounded-2xl p-5"><div class="flex justify-between"><div><div class="text-xs uppercase tracking-widest mint font-bold">Operations</div><h2 class="font-bold mt-1">Memory & Campaign Pulse</h2></div><span id="pulse" class="text-xs muted">—</span></div><div class="mt-5 space-y-3"><button onclick="reflect()" class="w-full panel rounded-xl px-4 py-3 text-left hover:border-cyan-400 flex items-center gap-3"><i data-lucide="brain-circuit" class="mint"></i><div><b class="text-sm">Reflect across memory</b><div class="text-xs muted">Ask Hindsight for cross-case patterns.</div></div></button><button onclick="benchmark()" class="w-full panel rounded-xl px-4 py-3 text-left hover:border-cyan-400 flex items-center gap-3"><i data-lucide="scale" class="mint"></i><div><b class="text-sm">Build live benchmark</b><div class="text-xs muted">Uses closed, analyst-labeled cases only.</div></div></button></div><div id="opsOutput" class="mt-4 bg-[#0b1019] rounded-xl p-4 text-xs muted min-h-36 whitespace-pre-wrap overflow-auto scroll">Operational output appears here.</div></div>\n  </section>\n\n  <section class="grid xl:grid-cols-[1fr_1.2fr] gap-5">\n    <div class="panel rounded-2xl p-5"><div class="flex justify-between items-center"><div><div class="text-xs uppercase tracking-widest danger font-bold">Case ledger</div><h2 class="font-bold">Persistent investigations</h2></div><button onclick="loadCases()" class="text-xs muted hover:text-white">Refresh</button></div><div id="caseList" class="mt-4 space-y-2 max-h-[620px] overflow-auto scroll"></div></div>\n    <div class="panel rounded-2xl p-5"><div class="flex justify-between items-start"><div><div class="text-xs uppercase tracking-widest mint font-bold">Investigation workbench</div><h2 id="caseTitle" class="font-bold">No case selected</h2></div><div id="caseStatus" class="text-xs"></div></div><div id="result" class="mt-4 text-sm muted">Run triage or select an existing case from the ledger.</div></div>\n  </section>\n</main>\n<div id="toast" class="fixed bottom-5 right-5 hidden panel rounded-xl px-4 py-3 text-sm shadow-xl"></div>\n<script>\nconst scenarios=[\n [\'SMS\',\'VM-MSEBPW\',\'MSEDCL notice: electricity service will be disconnected today. Download the MSEB Quick Update APK to verify your account: https://mseb-verify.top/update.apk. Call +919876543210 immediately.\'],\n [\'Telegram\',\'@quicktaskjobs\',\'Congratulations! Your YouTube rating task is approved. Complete 5 reviews and deposit Rs 2,000 to unlock your withdrawal. Send to taskreward@oksbi. Contact our manager on Telegram @profitdesk.\'],\n [\'WhatsApp\',\'+919900112233\',\'CBI CUSTOMS NOTICE: your parcel contains illegal items. You are under digital arrest. Join this video call now and pay the verification fee through UPI to avoid arrest.\'],\n [\'WhatsApp\',\'+918888777666\',\'Your merchant refund is ready. Scan this QR to receive the refund and enter your UPI PIN. If QR fails, send Rs 1 to refunddesk@ybl for verification.\']\n];\nlet selected=null;\nfunction toast(s,ok=true){const t=document.getElementById(\'toast\');t.textContent=s;t.classList.remove(\'hidden\');t.classList.toggle(\'text-cyan-300\',ok);t.classList.toggle(\'text-red-300\',!ok);setTimeout(()=>t.classList.add(\'hidden\'),3500)}\nasync function api(url,opt={}){const r=await fetch(url,{headers:{\'Content-Type\':\'application/json\',...(opt.headers||{})},...opt});if(!r.ok)throw new Error((await r.text()).slice(0,500));return r.json()}\nfunction loadScenario(i){const s=scenarios[i];channel.value=s[0];sender.value=s[1];message.value=s[2];window.scrollTo({top:0,behavior:\'smooth\'})}\nasync function loadAll(){await Promise.all([loadCases(),loadHealth()]);lucide.createIcons()}\nasync function loadHealth(){try{const h=await api(\'/api/health\');metricCases.textContent=h.cases;metricDispatches.textContent=h.dispatches;metricHindsight.textContent=h.hindsight_available?\'ONLINE\':\'OFFLINE\';metricHindsight.className=\'ml-2 \'+(h.hindsight_available?\'mint\':\'text-red-400\');pulse.textContent=h.hindsight_available?\'MEMORY ONLINE\':\'MEMORY OFFLINE\'}catch(e){toast(\'Backend unavailable\',false)}}\nasync function loadCases(){try{const d=await api(\'/api/cases\');caseList.innerHTML=d.items.length?d.items.map(c=>`<button onclick="selectCase(\'${c.id}\')" class="w-full text-left panel rounded-xl p-3 hover:border-cyan-400 ${selected===c.id?\'border-cyan-400\':\'\'}"><div class="flex justify-between gap-3"><b class="text-sm">${escapeHtml(c.campaign)}</b><span class="text-[10px] ${c.threat_level===\'CRITICAL\'?\'text-red-400\':\'text-amber-300\'}">${c.threat_level}</span></div><div class="text-xs muted mt-1">${escapeHtml(c.channel)} · ${escapeHtml(c.sender_id||\'unknown\')}</div><div class="flex justify-between text-[10px] mt-2"><span>Score ${c.memory_score}</span><span>Δ ${c.confidence_delta>=0?\'+\':\'\'}${c.confidence_delta}</span><span>${new Date(c.updated_at).toLocaleString()}</span></div></button>`).join(\'\'):\'<div class="muted text-sm p-4">No cases yet.</div>\'}catch(e){toast(\'Could not load cases\',false)}}\nasync function analyze(){const btn=document.getElementById(\'analyzeBtn\');btn.disabled=true;btn.innerHTML=\'ANALYZING…\';try{const d=await api(\'/api/analyze\',{method:\'POST\',body:JSON.stringify({channel:channel.value,sender_id:sender.value,message:message.value,memory_enabled:memoryEnabled.checked})});selected=d.case_id;renderCase(d.case);await loadCases();await loadHealth();toast(\'Case persisted and triage completed\')}catch(e){toast(e.message,false)}finally{btn.disabled=false;btn.innerHTML=\'<i data-lucide="scan-search" class="w-5 h-5"></i> RUN MULTI-AGENT TRIAGE\';lucide.createIcons()}}\nasync function selectCase(id){try{selected=id;const c=await api(\'/api/cases/\'+id);renderCase(c);await loadCases()}catch(e){toast(e.message,false)}}\nfunction scoreRing(score){return `<div class="w-28 h-28 rounded-full score grid place-items-center" style="--score:${score}%"><div class="w-20 h-20 rounded-full bg-[#0b1019] grid place-items-center"><b class="text-3xl">${score}</b></div></div>`}\nfunction renderCase(c){caseTitle.textContent=`Case ${c.id} · ${c.campaign}`;caseStatus.innerHTML=`<span class="chip rounded-full px-2 py-1">${c.status}</span>`;result.innerHTML=`<div class="grid md:grid-cols-[130px_1fr] gap-5 items-center"><div>${scoreRing(c.memory_score)}<div class="text-center mt-2 text-xs muted">Threat score</div></div><div><div class="flex flex-wrap gap-2"><span class="chip rounded-full px-3 py-1 text-xs">${c.threat_level}</span><span class="chip rounded-full px-3 py-1 text-xs">${escapeHtml(c.campaign)}</span><span class="chip rounded-full px-3 py-1 text-xs mint">Hindsight Δ ${c.confidence_delta>=0?\'+\':\'\'}${c.confidence_delta}</span></div><p class="mt-3 text-sm">${escapeHtml(c.rationale||\'No rationale recorded.\')}</p><div class="mt-3 p-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 text-xs"><b class="mint">MEMORY ATTRIBUTION</b><div class="mt-1 muted">${escapeHtml(c.memory_attribution||\'None\')}</div></div></div></div>\n<div class="mt-5"><b class="text-sm">Extracted indicators</b><div class="flex flex-wrap gap-2 mt-2">${renderIocs(c.iocs)}</div></div>\n<div class="mt-5 grid md:grid-cols-2 gap-4"><div class="panel rounded-xl p-4"><div class="text-xs uppercase tracking-widest muted">Before vs After</div><div class="mt-3 grid grid-cols-2 gap-2"><div class="bg-[#0b1019] rounded-lg p-3"><div class="text-xs muted">Memory OFF</div><b class="text-2xl">${c.baseline_score}</b></div><div class="bg-[#0b1019] rounded-lg p-3"><div class="text-xs mint">Memory ON</div><b class="text-2xl">${c.memory_score}</b></div></div></div><div class="panel rounded-xl p-4"><div class="text-xs uppercase tracking-widest muted">Actions</div><div class="grid grid-cols-2 gap-2 mt-3"><button onclick="verdict(\'${c.id}\',\'confirmed\')" class="bg-emerald-500/15 border border-emerald-500/30 rounded-lg py-2 text-xs">Confirm fraud</button><button onclick="verdict(\'${c.id}\',\'false_positive\')" class="bg-slate-500/15 border border-slate-500/30 rounded-lg py-2 text-xs">False positive</button></div></div></div>\n<div class="mt-5"><div class="flex items-center justify-between"><b class="text-sm">Artifact & dispatch desk</b><span class="text-xs muted">Human authorization required</span></div><div class="grid md:grid-cols-3 gap-2 mt-3"><button onclick="artifact(\'${c.id}\',\'official_brief\')" class="chip rounded-lg p-3 text-xs text-left">Official incident brief</button><button onclick="artifact(\'${c.id}\',\'takedown_notice\')" class="chip rounded-lg p-3 text-xs text-left">Phishing takedown notice</button><button onclick="artifact(\'${c.id}\',\'customer_warning\')" class="chip rounded-lg p-3 text-xs text-left">Customer warning</button></div><button onclick="dispatch(\'${c.id}\')" class="mt-3 w-full border border-[#FF2E63]/50 text-[#FF7b9b] hover:bg-[#FF2E63]/10 rounded-lg py-2 text-xs font-bold">CREATE AUDITED DISPATCH PACKAGE</button></div>`}\nfunction renderIocs(i){const a=[];for(const [k,v] of Object.entries(i||{})){if(Array.isArray(v)&&v.length)a.push(...v.map(x=>`<span class="chip rounded-full px-2 py-1 text-[10px]">${escapeHtml(x)}</span>`))}return a.join(\'\')||\'<span class="muted text-xs">No high-value identifiers extracted.</span>\'}\nasync function verdict(id,v){const notes=prompt(\'Analyst notes (stored in Hindsight):\',\'\');if(notes===null)return;try{const d=await api(\'/api/verdict\',{method:\'POST\',body:JSON.stringify({case_id:id,verdict:v,analyst:\'analyst\',notes})});toast(d.hindsight_retained?\'Verdict retained in Hindsight\':\'Verdict saved; Hindsight unavailable\');await selectCase(id)}catch(e){toast(e.message,false)}}\nasync function artifact(id,type){window.open(`/api/artifacts/${id}/${type}`,\'_blank\');}\nasync function dispatch(id){const type=prompt(\'Artifact type: official_brief, takedown_notice, or customer_warning\',\'official_brief\');if(!type)return;try{const d=await api(\'/api/dispatch\',{method:\'POST\',body:JSON.stringify({case_id:id,artifact_type:type,destination:\'LOCAL_EXPORT\'})});toast(`Dispatch ${d.dispatch_id} created: ${d.status}`);await loadHealth()}catch(e){toast(e.message,false)}}\nasync function reflect(){opsOutput.textContent=\'Querying Hindsight reflect…\';try{const d=await api(\'/api/reflect\');opsOutput.textContent=d.answer||\'No response\';}catch(e){opsOutput.textContent=e.message}}\nasync function benchmark(){opsOutput.textContent=\'Building benchmark from analyst-labeled cases…\';try{const d=await api(\'/api/benchmark\');opsOutput.textContent=JSON.stringify(d,null,2)}catch(e){opsOutput.textContent=e.message}}\nfunction escapeHtml(s){return String(s??\'\').replace(/[&<>\'"]/g,c=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',"\'":\'&#39;\',\'"\':\'&quot;\'}[c]))}\nloadAll();lucide.createIcons();\n</script>\n</body></html>\n'


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=settings.host, port=settings.port, reload=False)
