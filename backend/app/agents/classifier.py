"""Dark pattern classifier using Nova 2 Lite."""
from dataclasses import dataclass
from typing import Optional
from .browser_agent import PatternCategory, Severity, DetectedPattern

# OECD Dark Pattern Guidelines mapping
OECD_GUIDELINES = {
    PatternCategory.CONFIRMSHAMING: "OECD 3.2.1 - Emotional manipulation in opt-out flows",
    PatternCategory.MISDIRECTION: "OECD 3.1.2 - Visual hierarchy manipulation",
    PatternCategory.ROACH_MOTEL: "OECD 3.3.1 - Asymmetric ease of action",
    PatternCategory.FORCED_CONTINUITY: "OECD 3.3.2 - Automatic renewal without clear consent",
    PatternCategory.HIDDEN_COSTS: "OECD 3.2.3 - Drip pricing and hidden charges",
    PatternCategory.TRICK_QUESTIONS: "OECD 3.1.3 - Confusing language in consent flows",
    PatternCategory.DISGUISED_ADS: "OECD 3.1.1 - Deceptive content presentation",
    PatternCategory.FRIEND_SPAM: "OECD 3.4.1 - Unauthorized social sharing",
    PatternCategory.PRIVACY_ZUCKERING: "OECD 3.4.2 - Misleading privacy controls",
    PatternCategory.BAIT_AND_SWITCH: "OECD 3.2.2 - Misleading offer presentation",
}

REMEDIATION_TEMPLATES = {
    PatternCategory.CONFIRMSHAMING: "Replace guilt-trip language with neutral opt-out text. E.g., change 'No thanks, I don't want to save money' to 'No thanks'.",
    PatternCategory.MISDIRECTION: "Ensure all options have equal visual weight. Primary and secondary actions should be equally accessible.",
    PatternCategory.ROACH_MOTEL: "Make cancellation/deletion as easy as signup. Maximum 2 clicks to reach cancellation from account settings.",
    PatternCategory.FORCED_CONTINUITY: "Show clear renewal dates and prices. Provide easy one-click cancellation before renewal.",
    PatternCategory.HIDDEN_COSTS: "Display total price including all fees from the first price shown. No surprise charges at checkout.",
    PatternCategory.TRICK_QUESTIONS: "Use clear, unambiguous language. Avoid double negatives. Make the consequence of each choice obvious.",
    PatternCategory.DISGUISED_ADS: "Clearly label all sponsored/promoted content. Ads must be visually distinct from organic content.",
    PatternCategory.FRIEND_SPAM: "Never access contacts without explicit, informed consent. Default to no sharing.",
    PatternCategory.PRIVACY_ZUCKERING: "Default to maximum privacy. Make privacy settings easy to find and understand.",
    PatternCategory.BAIT_AND_SWITCH: "Ensure advertised offers match actual terms. No auto-substitution without clear consent.",
}

@dataclass
class ClassificationResult:
    is_dark_pattern: bool
    category: Optional[PatternCategory] = None
    severity: Optional[Severity] = None
    confidence: float = 0.0
    explanation: str = ""

class DarkPatternClassifier:
    """Classifies UI elements as dark patterns using Nova 2 Lite."""

    def __init__(self, nova_api_key: Optional[str] = None):
        self.nova_api_key = nova_api_key

    async def classify(self, screenshot_b64: str, dom_context: str, scenario_step: str) -> ClassificationResult:
        """
        Classify a UI element/state as a potential dark pattern.
        
        TODO: Integrate Nova 2 Lite API
        - Send screenshot + DOM context to Nova 2 Lite
        - Ask it to identify dark pattern type and severity
        - Return structured classification
        """
        # TODO: Replace with actual Nova 2 Lite API call
        # response = await nova_lite.analyze(
        #     image=screenshot_b64,
        #     prompt=f"Analyze this UI for dark patterns. Context: {scenario_step}. "
        #            f"DOM: {dom_context[:500]}. "
        #            f"Classify as one of: {[p.value for p in PatternCategory]}. "
        #            f"Rate severity: low/medium/high/critical. "
        #            f"Explain your reasoning.",
        # )
        return ClassificationResult(is_dark_pattern=False)

    def get_remediation(self, pattern: DetectedPattern) -> str:
        return REMEDIATION_TEMPLATES.get(pattern.category, "Review this element for potential dark patterns.")

    def get_oecd_reference(self, category: PatternCategory) -> str:
        return OECD_GUIDELINES.get(category, "No specific OECD guideline mapped.")
