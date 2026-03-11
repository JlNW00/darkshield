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

# -- 10-Category Dark Pattern Taxonomy --------------------------------------

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
    "confirmshaming": "Use neutral language for all options. Avoid guilt-tripping or emotional manipulation in button text.",
    "forced_consent": "Default all optional consent to unchecked. Require explicit affirmative action for each consent.",
    "hidden_costs": "Display all fees and charges upfront before checkout begins. No surprise costs at final step.",
    "interface_interference": "Simplify UI. Ensure key actions and information are clearly visible and unobstructed.",
    "misdirection": "Give equal visual prominence to all relevant information. Don't use visual hierarchy to hide important disclosures.",
    "nagging": "Respect user's first refusal. Don't re-prompt for the same action in the same session.",
    "obstruction": "Make account deletion, unsubscribe, and opt-out actions as easy as sign-up. Maximum 3 steps.",
    "sneaking": "Never add items to cart or charges to invoices without explicit user confirmation.",
    "urgency": "Remove artificial timers and false scarcity claims. Only show genuine time-limited information.",
}


@dataclass
class ClassifiedPattern:
    """A dark pattern finding after classification."""
    pattern_type: str
    category: str
    category_name: str
    description: str
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 - 1.0
    oecd_reference: str
    remediation: str
    screenshot_b64: Optional[str] = None
    raw_response: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON storage and API responses."""
        return {
            "pattern_type": self.pattern_type,
            "category": self.category,
            "category_name": self.category_name,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "oecd_reference": self.oecd_reference,
            "remediation": self.remediation,
            "screenshot_b64": self.screenshot_b64,
        }


class DarkPatternClassifier:
    """
    Classifies dark patterns using Amazon Nova 2 Lite via AWS Bedrock.
    """

    def __init__(
        self,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        region_name: str = "us-east-1",
        model_id: str = "amazon.nova-lite-v1:0",
    ):
        self.model_id = model_id
        self.client = boto3.client(
            "bedrock-runtime",
            aws_access_key_id=aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=region_name,
        )

    async def classify(
        self,
        pattern_type: str,
        description: str,
        screenshot_b64: Optional[str] = None,
    ) -> dict:
        """Classify a single dark pattern finding. Returns a plain dict."""
        return await asyncio.to_thread(
            self._classify_sync, pattern_type, description, screenshot_b64
        )

    async def classify_batch(self, findings: list) -> list[dict]:
        """
        Classify multiple findings concurrently.
        Accepts either Finding dataclass instances (with .pattern_type,
        .description, .screenshot_b64 attributes) or plain dicts.
        """
        tasks = []
        for f in findings:
            # Support both Finding dataclass instances and plain dicts
            if hasattr(f, "pattern_type"):
                pattern_type = f.pattern_type
                description = f.description
                screenshot_b64 = getattr(f, "screenshot_b64", None)
            else:
                pattern_type = f["pattern_type"]
                description = f["description"]
                screenshot_b64 = f.get("screenshot_b64")
            tasks.append(
                self.classify(
                    pattern_type=pattern_type,
                    description=description,
                    screenshot_b64=screenshot_b64,
                )
            )
        return await asyncio.gather(*tasks)

    def _classify_sync(
        self,
        pattern_type: str,
        description: str,
        screenshot_b64: Optional[str] = None,
    ) -> dict:
        """Synchronous Bedrock call. Returns a plain dict."""
        taxonomy_info = TAXONOMY.get(pattern_type, {})

        prompt = f"""You are a dark pattern classification expert. Analyze this UI finding and classify it.

Pattern Type (detected): {pattern_type}
Description: {description}
Known Taxonomy: {json.dumps(taxonomy_info, indent=2)}

Classify this finding with:
1. The most accurate category from: {list(TAXONOMY.keys())}
2. Severity: critical, high, medium, or low
3. Confidence score (0.0-1.0)
4. Brief explanation

Respond in JSON:
{{
  "category": "<category_key>",
  "severity": "<critical|high|medium|low>",
  "confidence": <0.0-1.0>,
  "explanation": "<brief explanation>"
}}"""

        messages = [{"role": "user", "content": [{"text": prompt}]}]

        # Add screenshot if provided
        if screenshot_b64:
            try:
                messages[0]["content"].insert(0, {
                    "image": {
                        "format": "png",
                        "source": {"bytes": base64.b64decode(screenshot_b64)},
                    }
                })
            except Exception:
                logger.warning("Failed to attach screenshot to classification request")

        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=messages,
                inferenceConfig={"maxTokens": 512, "temperature": 0.1},
            )

            text = response["output"]["message"]["content"][0]["text"]
            # Extract JSON from response
            start = text.find("{")
            end = text.rfind("}") + 1
            parsed = json.loads(text[start:end]) if start >= 0 else {}

            category = parsed.get("category", pattern_type)
            if category not in TAXONOMY:
                category = pattern_type

            tax = TAXONOMY.get(category, TAXONOMY.get(pattern_type, {}))

            return {
                "pattern_type": pattern_type,
                "category": category,
                "category_name": tax.get("name", category),
                "description": description,
                "severity": parsed.get("severity", "medium"),
                "confidence": float(parsed.get("confidence", 0.7)),
                "oecd_reference": tax.get("oecd_ref", ""),
                "remediation": REMEDIATION.get(category, ""),
                "explanation": parsed.get("explanation", ""),
                "screenshot_b64": screenshot_b64,
            }

        except Exception as e:
            logger.exception("Classification failed for pattern: %s", pattern_type)
            tax = TAXONOMY.get(pattern_type, {})
            return {
                "pattern_type": pattern_type,
                "category": pattern_type,
                "category_name": tax.get("name", pattern_type),
                "description": description,
                "severity": "medium",
                "confidence": 0.5,
                "oecd_reference": tax.get("oecd_ref", ""),
                "remediation": REMEDIATION.get(pattern_type, ""),
                "explanation": f"Classification error: {e}",
                "screenshot_b64": screenshot_b64,
            }
