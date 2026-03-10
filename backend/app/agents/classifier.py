"""
DarkShield Classifier - Nova 2 Lite via Amazon Bedrock
Classifies detected UI elements into dark pattern categories using
multimodal AI (screenshot + DOM context).
"""
import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone

import boto3
from botocore.config import Config as BotoConfig

logger = logging.getLogger("darkshield.classifier")


# ---------------------------------------------------------------------------
# OECD Dark Pattern Guidelines Reference
# ---------------------------------------------------------------------------
OECD_REFERENCES = {
    "confirmshaming": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.2",
        "principle": "Interface Interference - Emotional Steering",
        "description": "Using shame, guilt, or emotional manipulation to steer user decisions",
        "regulation": "EU Digital Services Act Art. 25; FTC Section 5 Unfair Practices",
    },
    "misdirection": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.1",
        "principle": "Interface Interference - Visual Manipulation",
        "description": "Using visual hierarchy, color, or sizing to steer users toward a preferred choice",
        "regulation": "EU GDPR Art. 7 (consent must be freely given); ePrivacy Directive",
    },
    "roach_motel": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.4",
        "principle": "Asymmetric Action - Easy In, Hard Out",
        "description": "Making it easy to subscribe/sign up but disproportionately difficult to cancel/leave",
        "regulation": "FTC Click-to-Cancel Rule (2024); EU Consumer Rights Directive Art. 11",
    },
    "forced_continuity": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.5",
        "principle": "Forced Action - Continued Service",
        "description": "Continuing charges after a free trial without adequate notice or easy cancellation",
        "regulation": "FTC Restore Online Shoppers' Confidence Act; EU Consumer Rights Directive",
    },
    "hidden_costs": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.3",
        "principle": "Information Manipulation - Drip Pricing",
        "description": "Revealing additional costs only at the end of the purchase process",
        "regulation": "FTC Section 5; EU Consumer Rights Directive Art. 6 (price transparency)",
    },
    "trick_questions": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.1",
        "principle": "Interface Interference - Confusing Language",
        "description": "Using double negatives or confusing wording to trick users into unintended choices",
        "regulation": "EU GDPR Art. 4(11) (clear and plain language for consent); CCPA",
    },
    "disguised_ads": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.6",
        "principle": "Content Manipulation - Disguised Advertising",
        "description": "Ads designed to look like content, navigation, or system notifications",
        "regulation": "FTC Endorsement Guides; EU Unfair Commercial Practices Directive",
    },
    "friend_spam": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.7",
        "principle": "Social Engineering - Contact Harvesting",
        "description": "Tricking users into sharing contacts for marketing purposes",
        "regulation": "EU GDPR Art. 6 (lawful basis); CAN-SPAM Act",
    },
    "privacy_zuckering": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.8",
        "principle": "Information Manipulation - Privacy Erosion",
        "description": "Tricking users into sharing more personal data than intended",
        "regulation": "EU GDPR Art. 5 (data minimization); CCPA Right to Know",
    },
    "bait_and_switch": {
        "guideline": "OECD Guidelines on Dark Commercial Patterns (2024), Section 3.3",
        "principle": "Information Manipulation - Deceptive Presentation",
        "description": "Advertising one thing but delivering or charging for another",
        "regulation": "FTC Section 5; EU Unfair Commercial Practices Directive Art. 6",
    },
}

REMEDIATION_TEMPLATES = {
    "confirmshaming": [
        "Replace emotionally manipulative text with neutral language (e.g., 'No thanks' instead of 'No, I don't want to save money')",
        "Ensure both options use equivalent, non-judgmental tone",
        "Remove imagery or icons designed to induce guilt",
    ],
    "misdirection": [
        "Make accept and reject/decline buttons equal in size, color, and prominence",
        "Use the same visual styling (button vs link) for all user choices",
        "Ensure the privacy-friendly option is equally accessible",
    ],
    "roach_motel": [
        "Match the number of steps to cancel with the number of steps to subscribe",
        "Provide a clearly visible cancel/delete option in account settings",
        "Implement one-click cancellation as required by FTC Click-to-Cancel Rule",
    ],
    "forced_continuity": [
        "Send clear notification before trial-to-paid conversion",
        "Provide easy cancellation before billing begins",
        "Display upcoming charge date and amount prominently in account settings",
    ],
    "hidden_costs": [
        "Display the total price including all fees on the product page",
        "Itemize all costs (shipping, tax, service fees) before checkout",
        "Do not add items to cart that the user did not explicitly select",
    ],
    "trick_questions": [
        "Use clear, affirmative language for consent checkboxes",
        "Avoid double negatives in any user-facing text",
        "Leave non-essential checkboxes unchecked by default",
    ],
    "disguised_ads": [
        "Clearly label all advertisements with 'Ad' or 'Sponsored'",
        "Visually distinguish ads from organic content and navigation",
        "Do not mimic system notifications or error messages for promotional content",
    ],
    "friend_spam": [
        "Do not pre-select 'share with contacts' or 'invite friends' options",
        "Clearly explain what will happen with imported contacts before access is granted",
        "Provide genuine opt-in (not opt-out) for any contact sharing",
    ],
    "privacy_zuckering": [
        "Default all privacy settings to the most protective option",
        "Use clear, plain language to explain data collection scope",
        "Provide granular privacy controls without burying them in settings",
    ],
    "bait_and_switch": [
        "Ensure advertised prices match checkout prices",
        "Do not pre-select premium options, add-ons, or upgrades",
        "Clearly distinguish between different product tiers at point of selection",
    ],
}


@dataclass
class ClassificationResult:
    """Result from classifying a single detected pattern."""
    pattern_id: str
    original_category: str
    ai_category: str
    ai_confidence: float
    severity: str
    description: str
    evidence_summary: str
    oecd_reference: dict = field(default_factory=dict)
    remediation: list[str] = field(default_factory=list)
    ai_reasoning: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


class DarkPatternClassifier:
    """
    Classifies dark pattern findings using Amazon Nova 2 Lite via Bedrock.
    
    Takes screenshots and DOM context from the browser agent and uses
    multimodal AI to confirm, reclassify, or dismiss potential findings.
    """

    MODEL_ID = "amazon.nova-lite-v1:0"

    def __init__(
        self,
        aws_region: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
    ):
        region = aws_region or os.getenv("AWS_REGION", "us-east-1")
        access_key = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

        session_kwargs = {"region_name": region}
        if access_key and secret_key:
            session_kwargs["aws_access_key_id"] = access_key
            session_kwargs["aws_secret_access_key"] = secret_key

        session = boto3.Session(**session_kwargs)
        self.bedrock = session.client(
            "bedrock-runtime",
            config=BotoConfig(
                retries={"max_attempts": 3, "mode": "adaptive"},
                read_timeout=60,
            ),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def classify_pattern(
        self,
        pattern_id: str,
        category: str,
        description: str,
        evidence: str,
        screenshot_b64: Optional[str] = None,
        dom_context: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a single detected pattern using Nova 2 Lite.
        
        Sends the screenshot + context to the model for confirmation,
        reclassification, or dismissal.
        """
        prompt = self._build_classification_prompt(
            category=category,
            description=description,
            evidence=evidence,
            dom_context=dom_context,
        )

        messages = [{"role": "user", "content": []}]

        # Add screenshot if available (multimodal)
        if screenshot_b64:
            try:
                image_bytes = base64.b64decode(screenshot_b64)
                messages[0]["content"].append({
                    "image": {
                        "format": "png",
                        "source": {"bytes": image_bytes},
                    }
                })
            except Exception:
                logger.warning("Failed to decode screenshot for pattern %s", pattern_id)

        messages[0]["content"].append({"text": prompt})

        # Call Bedrock
        try:
            response = await asyncio.to_thread(
                self.bedrock.converse,
                modelId=self.MODEL_ID,
                messages=messages,
                inferenceConfig={
                    "maxTokens": 1024,
                    "temperature": 0.1,
                    "topP": 0.9,
                },
                system=[{
                    "text": (
                        "You are a dark pattern classification expert. Analyze UI elements "
                        "and classify them according to established dark pattern taxonomies. "
                        "Be precise, cite evidence, and output valid JSON only."
                    )
                }],
            )

            result_text = response["output"]["message"]["content"][0]["text"]
            ai_result = self._parse_classification_response(result_text)

        except Exception as exc:
            logger.exception("Bedrock classification failed for %s", pattern_id)
            # Fall back to the browser agent's original classification
            ai_result = {
                "category": category,
                "confidence": 0.5,
                "severity": "medium",
                "reasoning": f"AI classification failed ({exc}); using browser agent's assessment",
                "description": description,
            }

        ai_category = ai_result.get("category", category)
        oecd_ref = OECD_REFERENCES.get(ai_category, {})
        remediation = REMEDIATION_TEMPLATES.get(ai_category, [])

        return ClassificationResult(
            pattern_id=pattern_id,
            original_category=category,
            ai_category=ai_category,
            ai_confidence=float(ai_result.get("confidence", 0.5)),
            severity=ai_result.get("severity", "medium"),
            description=ai_result.get("description", description),
            evidence_summary=ai_result.get("evidence_summary", evidence),
            oecd_reference=oecd_ref,
            remediation=remediation,
            ai_reasoning=ai_result.get("reasoning", ""),
        )

    async def classify_batch(
        self,
        patterns: list[dict],
    ) -> list[ClassificationResult]:
        """
        Classify multiple patterns concurrently.
        
        Each dict in patterns should have:
        - pattern_id, category, description, evidence
        - Optional: screenshot_b64, dom_context
        """
        tasks = [
            self.classify_pattern(
                pattern_id=p["pattern_id"],
                category=p["category"],
                description=p["description"],
                evidence=p["evidence"],
                screenshot_b64=p.get("screenshot_b64"),
                dom_context=p.get("dom_context"),
            )
            for p in patterns
        ]

        # Run up to 5 concurrently to avoid throttling
        results = []
        batch_size = 5
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i : i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            for j, r in enumerate(batch_results):
                if isinstance(r, Exception):
                    logger.error("Classification failed for pattern: %s", r)
                    p = patterns[i + j]
                    results.append(ClassificationResult(
                        pattern_id=p["pattern_id"],
                        original_category=p["category"],
                        ai_category=p["category"],
                        ai_confidence=0.5,
                        severity="medium",
                        description=p["description"],
                        evidence_summary=p["evidence"],
                        oecd_reference=OECD_REFERENCES.get(p["category"], {}),
                        remediation=REMEDIATION_TEMPLATES.get(p["category"], []),
                        ai_reasoning=f"Classification failed: {r}",
                    ))
                else:
                    results.append(r)

        return results

    def get_oecd_reference(self, category: str) -> dict:
        """Get OECD guideline reference for a dark pattern category."""
        return OECD_REFERENCES.get(category, {})

    def get_remediation(self, category: str) -> list[str]:
        """Get remediation suggestions for a dark pattern category."""
        return REMEDIATION_TEMPLATES.get(category, [])

    # ------------------------------------------------------------------
    # Prompt Construction
    # ------------------------------------------------------------------
    @staticmethod
    def _build_classification_prompt(
        category: str,
        description: str,
        evidence: str,
        dom_context: Optional[str] = None,
    ) -> str:
        categories_list = ", ".join([
            "confirmshaming", "misdirection", "roach_motel", "forced_continuity",
            "hidden_costs", "trick_questions", "disguised_ads", "friend_spam",
            "privacy_zuckering", "bait_and_switch",
        ])

        prompt = f"""Analyze this potential dark pattern finding and classify it.

## Browser Agent's Initial Finding
- **Detected Category:** {category}
- **Description:** {description}
- **Evidence:** {evidence}

## Your Task
1. Examine the screenshot (if provided) and the evidence description.
2. Confirm or reclassify into the correct dark pattern category.
3. Assess severity (low / medium / high / critical).
4. Rate your confidence (0.0 to 1.0).
5. Explain your reasoning.

## Valid Categories
{categories_list}

## Severity Guidelines
- **low**: Minor UX issue, borderline dark pattern, minimal user harm
- **medium**: Clear dark pattern, some user manipulation, moderate impact
- **high**: Significant manipulation, clear user detriment, violates guidelines
- **critical**: Extreme manipulation, blocks user rights, likely illegal

"""
        if dom_context:
            prompt += f"""## DOM Context
```html
{dom_context[:2000]}
```

"""

        prompt += """## Response Format (JSON only)
```json
{
    "category": "one_of_the_valid_categories",
    "confidence": 0.85,
    "severity": "high",
    "description": "Concise description of the dark pattern",
    "evidence_summary": "Key evidence supporting this classification",
    "reasoning": "Step-by-step reasoning for this classification"
}
```

Respond with ONLY the JSON object, no other text."""

        return prompt

    # ------------------------------------------------------------------
    # Response Parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_classification_response(response_text: str) -> dict:
        """Parse the AI classification response."""
        if not response_text:
            return {}

        # Try direct JSON parse
        try:
            return json.loads(response_text)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try extracting from code block
        if "```" in response_text:
            try:
                json_str = response_text.split("```json")[-1].split("```")[0].strip()
                return json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                pass
            try:
                json_str = response_text.split("```")[-2].strip()
                return json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                pass

        # Try finding JSON in text
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(response_text[start:end])
            except json.JSONDecodeError:
                pass

        logger.warning("Failed to parse classifier response: %s", response_text[:300])
        return {}


# ---------------------------------------------------------------------------
# Standalone utility for quick classification without full pipeline
# ---------------------------------------------------------------------------
async def quick_classify(
    screenshot_path: Optional[str] = None,
    description: str = "",
    evidence: str = "",
    category: str = "misdirection",
) -> ClassificationResult:
    """Quick standalone classification for testing."""
    classifier = DarkPatternClassifier()

    screenshot_b64 = None
    if screenshot_path and os.path.exists(screenshot_path):
        with open(screenshot_path, "rb") as f:
            screenshot_b64 = base64.b64encode(f.read()).decode("utf-8")

    return await classifier.classify_pattern(
        pattern_id="quick-test-001",
        category=category,
        description=description,
        evidence=evidence,
        screenshot_b64=screenshot_b64,
    )
