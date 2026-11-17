"""Rule-based detection of suspicious instructions and hidden content in text.

Patterns target prompt-injection phrasing, hidden Unicode, encoded blobs,
embedded code/command execution and exfiltration-style links. Matching text
is reported, never executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.detectors.base import DetectionContext, FindingDraft, snippet


@dataclass(frozen=True)
class PatternRule:
    key: str
    description: str
    severity: str
    pattern: re.Pattern[str]


RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "prompt_injection",
        "Instruction-override / prompt-injection phrasing",
        "high",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system)\b[^.\n]{0,20}"
            r"\b(instructions?|prompts?|rules|guidelines)\b|\byou are now\b|\bdeveloper mode\b|\bjailbreak\b|\bdo anything now\b",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "system_prompt_leak",
        "Requests to reveal or impersonate system prompts",
        "medium",
        re.compile(
            r"\b(reveal|print|show|repeat)\b[^.\n]{0,30}\b(system prompt|hidden instructions|your instructions)\b|<\|?(system|im_start)\|?>",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "hidden_unicode",
        "Zero-width or bidirectional control characters",
        "high",
        re.compile("[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]"),
    ),
    PatternRule(
        "encoded_payload",
        "Long base64/hex-like encoded blob",
        "medium",
        re.compile(r"(?:[A-Za-z0-9+/]{80,}={0,2})|(?:\b(?:0x)?[0-9a-fA-F]{96,}\b)"),
    ),
    PatternRule(
        "code_execution",
        "Shell or code-execution primitives",
        "high",
        re.compile(
            r"\b(os\.system|subprocess\.(run|popen|call)|eval\s*\(|exec\s*\(|__import__|rm\s+-rf|powershell\s+-e(nc)?|"
            r"curl\s+[^|\n]*\|\s*(ba)?sh|wget\s+[^|\n]*\|\s*(ba)?sh)",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "markup_injection",
        "Script or active markup",
        "medium",
        re.compile(r"<\s*script\b|javascript:|onerror\s*=|<\s*iframe\b", re.IGNORECASE),
    ),
    PatternRule(
        "exfiltration_link",
        "URL carrying query parameters that could exfiltrate data",
        "low",
        re.compile(r"https?://[^\s\"'<>]+\?[^\s\"'<>]*=(\{|\$|%7B)?[^\s\"'<>]*", re.IGNORECASE),
    ),
)


class SuspiciousInstructionDetector:
    name = "suspicious_instruction_pattern"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        return (ctx.text_series() is not None, "no text column")

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        text = ctx.text_series()
        if text is None:
            return []
        values = text.tolist()
        disabled = set(ctx.config.get("disabled_pattern_rules", []))
        findings: list[FindingDraft] = []
        for rule in RULES:
            if rule.key in disabled:
                continue
            hits: list[int] = []
            matches: list[dict[str, object]] = []
            for i, value in enumerate(values):
                m = rule.pattern.search(value)
                if m:
                    hits.append(i)
                    if len(matches) < 5:
                        matched = m.group(0).encode("unicode_escape").decode() if rule.key == "hidden_unicode" else m.group(0)
                        matches.append({"row": i, "match": snippet(matched, 80), "text": snippet(value)})
            if not hits:
                continue
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity=rule.severity,
                    title=f"{rule.description}: {len(hits)} rows",
                    confidence=0.8 if rule.severity == "high" else 0.6,
                    explanation=(
                        f"Rule '{rule.key}' matched {len(hits)} of {len(values)} rows. Such content in training data can teach a model "
                        "to follow injected instructions or emit unsafe output."
                    ),
                    evidence={"rule": rule.key, "row_indices": hits, "matches": matches},
                    investigation_steps=[
                        "Read the matched rows in full.",
                        "Decide whether the content is legitimate for the task (e.g. a security-education corpus).",
                        "Remove or relabel rows that should not be learned.",
                    ],
                    limitations="Pattern rules are easy to evade with paraphrasing and can match benign security discussions.",
                )
            )
        return findings
