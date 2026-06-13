# TRACE - 5-Minute Demo Video Script

Format required by the brief: screencast of live terminal execution with audio
narration, showing the agent working against case data including **at least one
self-correction sequence**. Keep it under 5:00. Record terminal full-screen,
font size large enough to read.

Tools to record with (free): **OBS Studio** (screen + mic) or Windows **Game Bar**
(Win+G). Speak slowly; it's better to finish at 4:30 than rush.

---

## 0:00-0:30 - The problem (talking head or title card)

> "AI attackers now go from access to domain control in under 8 minutes.
> Defenders can't keep up. SANS built Protocol SIFT to put an AI agent on the
> SIFT Workstation - but in their own words, it *hallucinates more than they'd
> like*. A forensic finding you can't trust is worse than no finding. This is
> TRACE: an architecture that makes the agent unable to fabricate findings or
> damage evidence - and proves it."

## 0:30-1:15 - The idea (show docs/architecture_diagram.svg on screen)

> "Two architectural guardrails. One: the agent only gets typed, read-only tools
> through a custom MCP server - there is no shell, no write, no delete, so it
> physically cannot damage evidence. Two: every finding must cite the exact line
> of raw tool output that produced it. A verifier checks that citation against the
> real bytes. If a claim isn't backed by evidence, it's dropped - and the agent
> re-runs to correct itself."

## 1:15-1:35 - Generate the case (terminal)

```
python -m benchmark.make_sample_data
```
> "Here's a synthetic Windows intrusion - AmCache, MFT, prefetch, and event logs -
> with known ground truth so we can score accuracy."

## 1:35-3:00 - Run the agent, show self-correction (terminal)

```
python -m agent.loop --case sample_data/case01 --max-iterations 3
```
> "The agent enumerates artifacts, then calls each typed tool. Watch the summary:
> it ran **2 iterations** and **dropped 2 claims as UNVERIFIED**. On the first
> pass the model volunteered two findings with no evidence - exfiltration to a C2,
> and attribution to a named ransomware group. The verifier caught both because
> no tool produced them. The agent self-corrected and re-ran. That's the
> self-correction sequence."

Then show the log:
```
type logs\execution_log.jsonl   (Windows)   # or: cat on Linux
```
> "Every tool call is logged with a timestamp and token usage. Each surviving
> finding cites a tool, a file, and a line number - full audit trail. A judge can
> trace any finding back to the execution that produced it."

## 3:00-4:00 - Prove it with the benchmark (terminal)

```
python -m benchmark.run_benchmark --case sample_data/case01
```
> "Same agent, two modes. The unverified baseline - Protocol SIFT-like - reports
> 7 true findings but also 2 hallucinations. TRACE reports the same 7 true
> findings and **zero** hallucinations. We didn't lose a single real detection.
> We just removed the lies. That result is written straight into our accuracy
> report."

## 4:00-4:40 - The guardrail is real, not a prompt (terminal)

> "And the evidence guardrail isn't a polite instruction the model can ignore.
> The agent has no shell tool to call - ask for one and the dispatch refuses,
> because it doesn't exist."

Optional one-liner to show the refusal:
```
python -c "from server.trace_server import call_tool; call_tool('execute_shell', cmd='rm -rf /')"
```
> "It raises. Evidence spoliation is prevented by architecture."

## 4:40-5:00 - Close

> "TRACE: typed read-only tools, evidence-cited findings, a verifier that catches
> hallucinations, and a benchmark that proves it - a defender a practitioner can
> actually stand behind at 3 a.m. The same architecture drops straight onto the
> real SIFT Workstation by swapping in regipy and python-evtx. Thanks for
> watching."

---

## Recording checklist
- [ ] Terminal font large, dark theme, window maximized
- [ ] Mic tested, no background noise
- [ ] Run the three commands once before recording so output is warm
- [ ] Keep total under 5:00
- [ ] Upload unlisted to YouTube, paste link in Devpost submission
