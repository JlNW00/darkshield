"""
DarkShield Dark Pattern Classifier - Amazon Nova 2 Lite via Bedrock.
Classifies detected UI patterns into a 10-category taxonomy with
severity ratings, OECD guideline references, and remediation advice.
"""
import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import boto3

logger = logging.getLogger("darkshield.classifier")

# ── 10-Category Dark Pattern Taxonomy ──────────────────────────────

TAXONOMY = {
    "asymmetric_choice": {
        "name": "Asymmetric Choice",
        "description": "One option is visually or functionally emphasized over others",
        "oecd_ref": "OECD Guidelines Section 4.1 - Misleading interface design",
    },
    "confirmshaming": {
        "name": "Confirmshaming",
        "description": "Using guilt or shame to steer user decisions",
        "oecd_ref": "OECD Guidelines Section 3.2 - Emotional manipulation",
    },
    "forced_consent": {
        "name": "Forced Consent",
        "description": "Pre-selecting options or bundling consent without explicit choice",
        "oecd_ref": "OECD Guidelines Section 5.1 - Consent mechanisms",
    },
    "hidden_costs": {
        "name": "Hidden Costs",
        "description": "Fees or charges not disclosed until late in the process",
        "oecd_ref": "OECD Guidelines Section 2.3 - Price transparency",
    },
    "interface_interference": {
        "name": "Interface Interference",
        "description": "UI elements that confuse, distract, or mislead users",
        "oecd_ref": "OECD Guidelines Section 4.2 - Interface clarity",
    },
    "misdirection": {
        "name": "Misdirection",
        "description": "Drawing attention away from important information",
        "oecd_ref": "OECD Guidelines Section 4.3 - Attention manipulation",
    },
    "nagging": {
        "name": "Nagging",
        "description": "Repeated prompts to take an action the user has declined",
        "oecd_ref": "OECD Guidelines Section 3.3 - Persistent pressure",
    },
    "obstruction": {
        "name": "Obstruction",
        "description": "Making certain actions unnecessarily difficult",
        "oecd_ref": "OECD Guidelines Section 6.1 - Ease of withdrawal",
    },
    "sneaking": {
        "name": "Sneaking",
        "description": "Adding items or charges without explicit user consent",
        "oecd_ref": "OECD Guidelines Section 2.1 - Transparent transactions",
    },
    "urgency": {
        "name": "Urgency",
        "description": "Artificial time pressure or scarcity to rush decisions",
        "oecd_ref": "OECD Guidelines Section 3.1 - Pressure tactics",
    },
}

REMEDIATION = {
    "asymmetric_choice": "Ensure all options (accept/reject) have equal visual weight, size, and prominence.",
    "confirmshaming": "Use neutral language for all options. Avoid guilt-tripping or emotional manipulation.",
    "forced_consent": "Default all non-essential options to OFF. Require explicit opt-in for each category.",
    "hidden_costs": "Display total cost including all fees from the product page. No surprise charges at checkout.",
    "interface_interference": "Use clear, consistent UI patterns. Ensure interactive elements are unambiguous.",
    "misdirection": "Keep important information (pricing, terms) visually prominent and easy to find.",
    "nagging": "Respect user choices. If declined, don't prompt again for the same action in the session.",
    "obstruction": "Make cancellation/deletion as easy as signup. Maximum 2-3 clicks for any destructive action.",
    "sneaking": "Never pre-add items to cart. All additions must be explicit user actions.",
    "urgency": "Only show real scarcity data. Remove fake countdown timers and fabricated viewer counts.",
}


@dataclass
class ClassificationResult:
    """Result from classifying a single finding."""
    pattern_type: str
    category_name: str
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 - 1.0
    description: str
    oecd_reference: str
    remediation: str
    raw_response: Optional[str] = None


class DarkPatternClassifier:
    """
    Classifies dark pattern findings using Amazon Nova 2 Lite via Bedrock.
    Sends multimodal prompts (screenshot + context) for classification.
    """

    def __init__(
        self,
        region: Optional[str] = None,
        model_id: Optional[str] = None,
    ):
        from app.config import settings
        self.region = region or settings.aws_region
        self.model_id = model_id or settings.bedrock_model_id
        self.client = boto3.client(
            "bedrock-runtime",
            region_name=self.region,
            aws_access_key_id=settings.aws_access_key_id or None,
            aws_secret_access_key=settings.aws_secret_access_key or None,
        )

    def _build_classification_prompt(self, context: str) -> str:
        """Build the classification prompt with taxonomy context."""
        categories = "\n".join(
            f"- {key}: {val['name']} -- {val['description']}"
            for key, val in TAXONOMY.items()
        )
        return f"""You are an expert in dark pattern analysis and consumer protection.

Analyze the following UI finding and classify it into one of these dark pattern categories:

{categories}

Finding context:
{context}

Respond in valid JSON with these exact fields:
{{
  "pattern_type": "<category_key from list above>",
  "severity": "<critical|high|medium|low>",
  "confidence": <0.0 to 1.0>,
  "description": "<brief explanation of the dark pattern detected>"
}}

Severity guide:
- critical: Actively deceptive, causes financial harm or data loss
- high: Significantly manipulative, hard to avoid
- medium: Misleading but user can work around it
- low: Minor dark pattern, slight nudge

Return ONLY the JSON object, no other text."""

    def _classify_sync(
        self, context: str, screenshot_b64: Optional[str] = None,
    ) -> ClassificationResult:
        """Synchronous classification call to Bedrock."""
        prompt = self._build_classification_prompt(context)

        # Build message content
        content = []
        if screenshot_b64:
            try:
                content.append({
                    "image": {
                        "format": "png",
                        "source": {
                            "bytes": base64.b64decode(screenshot_b64),
                        },
                    },
                })
            except Exception as e:
                logger.warning(f"Failed to decode screenshot: {e}")

        content.append({"text": prompt})

        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=[{"role": "user", "content": content}],
                inferenceConfig={
                    "maxTokens": 500,
                    "temperature": 0.1,
                },
            )

            # Extract text from response
            raw_text = ""
            output_message = response.get("output", {}).get("message", {})
            for block in output_message.get("content", []):
                if "text" in block:
                    raw_text += block["text"]

            # Parse JSON from response
            result = json.loads(raw_text.strip())
            pattern_type = result.get("pattern_type", "interface_interference")
            taxonomy_entry = TAXONOMY.get(pattern_type, TAXONOMY["interface_interference"])

            return ClassificationResult(
                pattern_type=pattern_type,
                category_name=taxonomy_entry["name"],
                severity=result.get("severity", "medium"),
                confidence=float(result.get("confidence", 0.5)),
                description=result.get("description", context[:200]),
                oecd_reference=taxonomy_entry["oecd_ref"],
                remediation=REMEDIATION.get(pattern_type, "Review and fix the identified pattern."),
                raw_response=raw_text,
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse classifier JSON: {e}, raw: {raw_text[:500]}")
            return self._fallback_classification(context)
        except Exception as e:
            logger.error(f"Bedrock classification failed: {e}")
            return self._fallback_classification(context)

    def _fallback_classification(self, context: str) -> ClassificationResult:
        """Keyword-based fallback when Bedrock is unavailable."""
        context_lower = context.lower()
        matched = "interface_interference"
        for key in TAXONOMY:
            if key.replace("_", " ") in context_lower or key in context_lower:
                matched = key
                break

        taxonomy_entry = TAXONOMY[matched]
        return ClassificationResult(
            pattern_type=matched,
            category_name=taxonomy_entry["name"],
            severity="medium",
            confidence=0.3,
            description=f"Fallback classification: {context[:200]}",
            oecd_reference=taxonomy_entry["oecd_ref"],
            remediation=REMEDIATION.get(matched, "Review and fix the identified pattern."),
            raw_response=None,
        )

    async def classify(
        self, context: str, screenshot_b64: Optional[str] = None,
    ) -> ClassificationResult:
        """Async wrapper -- runs blocking Bedrock call in a thread."""
        return await asyncio.to_thread(self._classify_sync, context, screenshot_b64)

    async def classify_batch(
        self, findings: list[dict], concurrency: int = 3,
    ) -> list[ClassificationResult]:
        """
        Classify multiple findings with bounded concurrency.
        Each finding dict should have 'context' (str) and optionally 'screenshot_b64' (str).
        """
        semaphore = asyncio.Semaphore(concurrency)
        results: list[ClassificationResult] = []

        async def _classify_one(finding: dict) -> ClassificationResult:
            async with semaphore:
                return await self.classify(
                    context=finding.get("context", ""),
                    screenshot_b64=finding.get("screenshot_b64"),
                )

        tasks = [_classify_one(f) for f in findings]
        settled = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(settled):
            if isinstance(result, Exception):
                logger.error(f"Batch classification [{i}] failed: {result}")
                context = findings[i].get("context", "unknown finding")
                results.append(self._fallback_classification(context))
            else:
                results.append(result)

        return results
