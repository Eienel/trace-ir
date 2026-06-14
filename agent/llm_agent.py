"""Live LLM agent (provider-agnostic) that produces forensic findings from raw artifacts.

This is the real-evidence test of TRACE's thesis. Instead of scripting a
hallucination, we let an actual LLM read raw artifact lines and write findings,
each of which it must cite to a specific line. TRACE's verifier then checks every
citation against the real bytes. Whatever the model fabricates or mis-cites is
caught for real, not by a hardcoded rule.

No SDK dependency: every provider is called over its REST API with urllib (stdlib).

Supported providers (auto-detected from environment, first match wins):
  - Google Gemini        GEMINI_API_KEY      [GEMINI_MODEL, default gemini-2.0-flash]
  - OpenAI               OPENAI_API_KEY      [OPENAI_MODEL, default gpt-4o-mini]
  - Anthropic Claude     ANTHROPIC_API_KEY   [ANTHROPIC_MODEL, default claude-3-5-haiku-latest]
  - Any OpenAI-compatible endpoint (Groq, Together, Ollama, OpenRouter, vLLM, ...):
        LLM_API_KEY, LLM_API_BASE (e.g. https://api.groq.com/openai/v1), LLM_MODEL

Set whichever you have, then run with `--live`. Example:
    export GEMINI_API_KEY=...        # Linux/macOS/WSL
    setx GEMINI_API_KEY "..."        # Windows (open a new shell after)
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from server.citations import Citation, Finding

ARTIFACT_FILES = ["amcache.txt", "mft.txt", "prefetch.txt", "evtx_logons.txt"]

SYSTEM_PROMPT = """You are a senior DFIR (digital forensics and incident response) \
analyst triaging a Windows host. Below are raw forensic artifact lines, each \
prefixed with its line number inside its file. Identify malicious or suspicious \
findings, and give your overall incident assessment.

Return ONLY a JSON array. Each element is an object with these fields:
- summary: string, the finding
- severity: one of info|low|medium|high|critical
- confidence: one of confirmed|inferred
- source_file: the exact FILE name the supporting line came from, or null
- line_number: the integer line number of the supporting line, or null
- raw_line: the EXACT verbatim text of that supporting line (omit the "N: " \
prefix), or null

Quote raw_line character-for-character as shown. If a statement is your own \
interpretation, assessment, or attribution that is not tied to one specific \
quotable line, set source_file, line_number, and raw_line to null."""

_HTTP_TIMEOUT = 90


# --------------------------------------------------------------------------- #
# Provider selection
# --------------------------------------------------------------------------- #
def _select_provider() -> Optional[Tuple[str, str]]:
    """Return (provider_id, model) for the first configured provider, else None."""
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini", os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    if os.environ.get("OPENAI_API_KEY"):
        return "openai", os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")
    if os.environ.get("LLM_API_KEY") and os.environ.get("LLM_API_BASE"):
        return "openai_compatible", os.environ.get("LLM_MODEL", "")
    return None


def llm_available() -> bool:
    return _select_provider() is not None


def provider_name() -> str:
    sel = _select_provider()
    if not sel:
        return "none"
    pid, model = sel
    label = {"gemini": "Google Gemini", "openai": "OpenAI",
             "anthropic": "Anthropic Claude",
             "openai_compatible": "OpenAI-compatible endpoint"}[pid]
    return f"{label} ({model})" if model else label


# --------------------------------------------------------------------------- #
# REST callers (stdlib only)
# --------------------------------------------------------------------------- #
_MAX_RETRIES = 5


def _post(url: str, payload: dict, headers: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    last_err = None
    for attempt in range(_MAX_RETRIES):
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = e
            # 429 = rate limited, 503 = overloaded: back off and retry.
            if e.code in (429, 503) and attempt < _MAX_RETRIES - 1:
                retry_after = e.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() \
                    else 2 ** attempt * 5  # 5, 10, 20, 40s
                print(f"  rate limited ({e.code}); waiting {int(wait)}s "
                      f"(attempt {attempt + 1}/{_MAX_RETRIES})...")
                time.sleep(wait)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _call_gemini(model: str, prompt: str, temperature: float) -> str:
    key = os.environ["GEMINI_API_KEY"]
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={key}")
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature,
                             "responseMimeType": "application/json"},
    }
    data = _post(url, payload, {})
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _call_openai_chat(base: str, key: str, model: str, prompt: str,
                      temperature: float) -> str:
    url = base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
    }
    data = _post(url, payload, {"Authorization": f"Bearer {key}"})
    return data["choices"][0]["message"]["content"]


def _call_anthropic(model: str, prompt: str, temperature: float) -> str:
    key = os.environ["ANTHROPIC_API_KEY"]
    url = "https://api.anthropic.com/v1/messages"
    payload = {
        "model": model,
        "max_tokens": 2048,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    data = _post(url, payload,
                 {"x-api-key": key, "anthropic-version": "2023-06-01"})
    return "".join(b.get("text", "") for b in data.get("content", []))


def _generate(prompt: str, temperature: float) -> str:
    sel = _select_provider()
    if not sel:
        raise RuntimeError("No LLM provider configured")
    pid, model = sel
    if pid == "gemini":
        return _call_gemini(model, prompt, temperature)
    if pid == "openai":
        return _call_openai_chat("https://api.openai.com/v1",
                                 os.environ["OPENAI_API_KEY"], model, prompt, temperature)
    if pid == "anthropic":
        return _call_anthropic(model, prompt, temperature)
    if pid == "openai_compatible":
        return _call_openai_chat(os.environ["LLM_API_BASE"],
                                 os.environ["LLM_API_KEY"], model, prompt, temperature)
    raise RuntimeError(f"Unknown provider {pid}")


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _load_case_text(case_dir: str) -> str:
    blocks = []
    for name in ARTIFACT_FILES:
        path = os.path.join(case_dir, name)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh]
        numbered = "\n".join(f"{i}: {ln}" for i, ln in enumerate(lines, 1))
        blocks.append(f"### FILE: {name}\n{numbered}")
    return "\n\n".join(blocks)


def _parse_findings_json(raw: str) -> list:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fall back to slicing out the first balanced JSON value.
        for open_c, close_c in (("[", "]"), ("{", "}")):
            start, end = raw.find(open_c), raw.rfind(close_c)
            if start != -1 and end != -1:
                try:
                    data = json.loads(raw[start:end + 1])
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return []
    return _coerce_findings(data)


def _coerce_findings(data) -> list:
    """Normalize whatever JSON shape the model returned into a flat list of
    finding dicts. Small models often ignore "return a JSON array" and emit an
    object whose values are the lists (e.g. malicious_findings / suspicious_...),
    or a single finding object. Pull findings out of any of those shapes."""
    if isinstance(data, list):
        return [it for it in data if isinstance(it, dict)]
    if isinstance(data, dict):
        # A bare finding object (has the expected keys) is one finding.
        if "summary" in data or "raw_line" in data:
            return [data]
        # Otherwise treat each list-valued field as a bucket of findings, and
        # each finding-shaped object value as a single finding.
        out: list = []
        for v in data.values():
            if isinstance(v, list):
                out.extend(it for it in v if isinstance(it, dict))
            elif isinstance(v, dict) and ("summary" in v or "raw_line" in v):
                out.append(v)
        return out
    return []


def get_llm_findings(case_dir: str, iteration: int,
                     rejected: Optional[List[str]] = None,
                     temperature: float = 0.0) -> List[Finding]:
    """Call the configured LLM to analyze the case; return findings with the
    model's own claimed citations. Citations are NOT trusted here - they are
    exactly what the verifier checks. A fabricated or mis-quoted citation fails
    verification downstream.
    """
    if not llm_available():
        raise RuntimeError("No LLM provider configured")

    prompt = SYSTEM_PROMPT
    if rejected:
        prompt += ("\n\nIMPORTANT: On the previous pass these claims were REJECTED "
                   "because they were not backed by a verbatim evidence line. Do "
                   "NOT repeat them. Only report findings you can quote exactly:\n")
        prompt += "\n".join(f"- {r}" for r in rejected)
    prompt += "\n\n=== ARTIFACTS ===\n" + _load_case_text(case_dir)

    raw = _generate(prompt, temperature)
    items = _parse_findings_json(raw)

    findings: List[Finding] = []
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            continue
        sf, ln, rl = it.get("source_file"), it.get("line_number"), it.get("raw_line")
        citation = None
        if sf and ln and rl:
            path = os.path.join(case_dir, os.path.basename(str(sf)))
            try:
                citation = Citation("llm_agent", path, int(ln), str(rl))
            except (ValueError, TypeError):
                citation = None
        findings.append(Finding(
            id=f"llm:{iteration}:{idx}",
            summary=str(it.get("summary", "")).strip() or "(empty)",
            severity=str(it.get("severity", "info")).lower(),
            confidence=str(it.get("confidence", "inferred")).lower(),
            citation=citation,
        ))
    return findings
