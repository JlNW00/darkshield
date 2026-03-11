"""'
DarkShield Browser Agent - Nova Act powered dark pattern scanner.
Runs browser automation scenarios to detect deceptive UI patterns.
All blocking Nova Act calls are wrapped in asyncio.to_thread() to
avoid blocking the FastAPI event loop.
"""
import asyncio
import base64
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("darkshield.agent")


@dataclass
class Finding:
    """A single dark pattern finding from a scenario."""
    pattern_type: str
    description: str
    severity: str  # critical, high, medium, low
    screenshot_b64: Optional[str] = None
    element_text: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ScenarioResult:
    """Result from running a single audit scenario."""
    scenario: str
    status: str  # completed, failed, timeout
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    steps_completed: int = 0


class DarkPatternAgent:
    """
    Nova Act-powered browser agent for dark pattern detection.
    Each scenario navigates a site and tests for specific deceptive patterns.
    """

    def __init__(self, api_key: Optional[str] = None, headless: bool = True):
        self.api_key = api_key or os.getenv("NOVA_ACT_API_KEY", "")
        self.headless = headless
        if not self.api_key:
            raise ValueError("NOVA_ACT_API_KEY is required")

    async def run_all_scenarios(
        self,
        url: str,
        scenarios: Optional[list[str]] = None,
        on_event: Optional[Callable] = None,
    ) -> list[ScenarioResult]:
        """Run all (or selected) audit scenarios against a URL."""
        available = {
            "cookie_consent": self._scenario_cookie_consent,
            "subscription_cancel": self._scenario_subscription_cancel,
            "checkout_flow": self._scenario_checkout_flow,
            "account_deletion": self._scenario_account_deletion,
        }
        to_run = scenarios or list(available.keys())
        results = []

        for name in to_run:
            if name not in available:
                logger.warning(f"Unknown scenario: {name}")
                continue

            if on_event:
                on_event({
                    "type": "scenario_started",
                    "scenario": name,
                    "message": f"Starting scenario: {name}",
                })

            start = time.time()
            try:
                result = await available[name](url, on_event)
                result.duration_seconds = time.time() - start
                results.append(result)
            except Exception as e:
                logger.error(f"Scenario {name} failed: {e}")
                results.append(ScenarioResult(
                    scenario=name,
                    status="failed",
                    error=str(e),
                    duration_seconds=time.time() - start,
                ))

            if on_event:
                on_event({
                    "type": "scenario_completed",
                    "scenario": name,
                    "status": results[-1].status,
                    "patterns_found": len(results[-1].findings),
                })

        return results

    # -----------------------------------------------------------------------
    # Scenario: Cookie Consent
    # -----------------------------------------------------------------------
    async def _scenario_cookie_consent(
        self, url: str, on_event: Optional[Callable] = None
    ) -> ScenarioResult:
        """Detect dark patterns in cookie consent flows."""
        from nova_act import NovaAct

        findings = []
        steps = 0

        def _run():
            nonlocal steps
            with NovaAct(starting_url=url, api_key=self.api_key, headless=self.headless) as nova:
                # Step 1: Look for cookie consent banner
                result = nova.act(
                    "Look for a cookie consent banner or privacy notice. "
                    "If found, describe what options are available (accept/reject/customize). "
                    "Note if the reject or customize option is harder to find than accept.",
                    schema={
                        "type": "object",
                        "properties": {
                            "banner_found": {"type": "boolean"},
                            "accept_prominent": {"type": "boolean"},
                            "reject_difficult": {"type": "boolean"},
                            "pre_checked": {"type": "boolean"},
                            "description": {"type": "string"},
                        }
                    }
                )
                steps += 1

                parsed = result.parsed_response or {}
                if parsed.get("banner_found"):
                    if parsed.get("reject_difficult") or parsed.get("accept_prominent"):
                        screenshot = nova.take_screenshot()
                        findings.append(Finding(
                            pattern_type="asymmetric_choice",
                            description=parsed.get("description", "Cookie consent uses asymmetric choice design"),
                            severity="high",
                            screenshot_b64=_encode_screenshot(screenshot),
                        ))

                    if parsed.get("pre_checked"):
                        screenshot = nova.take_screenshot()
                        findings.append(Finding(
                            pattern_type="forced_consent",
                            description="Cookie options are pre-selected without explicit user choice",
                            severity="high",
                            screenshot_b64=_encode_screenshot(screenshot),
                        ))

                # Step 2: Check for nagging if rejected
                result2 = nova.act(
                    "Try to find and click the 'reject all' or 'decline' option for cookies. "
                    "After declining, does a new popup or prompt appear asking to reconsider?",
                    schema={
                        "type": "object",
                        "properties": {
                            "reject_found": {"type": "boolean"},
                            "re_prompt_appeared": {"type": "boolean"},
                            "description": {"type": "string"},
                        }
                    }
                )
                steps += 1

                parsed2 = result2.parsed_response or {}
                if parsed2.get("re_prompt_appeared"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="nagging",
                        description=parsed2.get("description", "Site re-prompts after cookie rejection"),
                        severity="medium",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

        try:
            await asyncio.to_thread(_run)
            return ScenarioResult(scenario="cookie_consent", status="completed", findings=findings, steps_completed=steps)
        except Exception as e:
            logger.exception("cookie_consent scenario failed")
            return ScenarioResult(scenario="cookie_consent", status="failed", error=str(e), steps_completed=steps)

    # -----------------------------------------------------------------------
    # Scenario: Subscription Cancellation
    # -----------------------------------------------------------------------
    async def _scenario_subscription_cancel(
        self, url: str, on_event: Optional[Callable] = None
    ) -> ScenarioResult:
        """Detect dark patterns in subscription cancellation flows."""
        from nova_act import NovaAct

        findings = []
        steps = 0

        def _run():
            nonlocal steps
            with NovaAct(starting_url=url, api_key=self.api_key, headless=self.headless) as nova:
                result = nova.act(
                    "Navigate to account settings or subscription management. "
                    "Look for cancel subscription or unsubscribe options. "
                    "Describe how easy or difficult it is to find the cancellation option.",
                    schema={
                        "type": "object",
                        "properties": {
                            "cancel_found": {"type": "boolean"},
                            "steps_to_cancel": {"type": "integer"},
                            "obstruction_found": {"type": "boolean"},
                            "confirmshaming_found": {"type": "boolean"},
                            "description": {"type": "string"},
                        }
                    }
                )
                steps += 1

                parsed = result.parsed_response or {}
                if parsed.get("obstruction_found"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description=parsed.get("description", "Subscription cancellation is unnecessarily difficult"),
                        severity="high",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

                if parsed.get("confirmshaming_found"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="confirmshaming",
                        description="Cancellation flow uses guilt-inducing language",
                        severity="medium",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

                # Check for win-back offers / nagging
                result2 = nova.act(
                    "Continue the cancellation process. "
                    "Are there multiple screens asking you to reconsider, offers to stay, "
                    "or emotional appeals before you can complete cancellation?",
                    schema={
                        "type": "object",
                        "properties": {
                            "multiple_screens": {"type": "boolean"},
                            "emotional_appeal": {"type": "boolean"},
                            "description": {"type": "string"},
                        }
                    }
                )
                steps += 1

                parsed2 = result2.parsed_response or {}
                if parsed2.get("multiple_screens") or parsed2.get("emotional_appeal"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="nagging",
                        description=parsed2.get("description", "Multiple re-engagement screens during cancellation"),
                        severity="medium",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

        try:
            await asyncio.to_thread(_run)
            return ScenarioResult(scenario="subscription_cancel", status="completed", findings=findings, steps_completed=steps)
        except Exception as e:
            logger.exception("subscription_cancel scenario failed")
            return ScenarioResult(scenario="subscription_cancel", status="failed", error=str(e), steps_completed=steps)

    # -----------------------------------------------------------------------
    # Scenario: Checkout Flow
    # -----------------------------------------------------------------------
    async def _scenario_checkout_flow(
        self, url: str, on_event: Optional[Callable] = None
    ) -> ScenarioResult:
        """Detect dark patterns in checkout flows."""
        from nova_act import NovaAct

        findings = []
        steps = 0

        def _run():
            nonlocal steps
            with NovaAct(starting_url=url, api_key=self.api_key, headless=self.headless) as nova:
                result = nova.act(
                    "Navigate to a product page and begin the checkout process. "
                    "Look for: hidden fees appearing late, pre-checked add-ons, "
                    "urgency timers, or items added to cart without consent.",
                    schema={
                        "type": "object",
                        "properties": {
                            "hidden_fees_found": {"type": "boolean"},
                            "pre_checked_addons": {"type": "boolean"},
                            "urgency_timer": {"type": "boolean"},
                            "sneak_items": {"type": "boolean"},
                            "description": {"type": "string"},
                        }
                    }
                )
                steps += 1

                parsed = result.parsed_response or {}
                if parsed.get("hidden_fees_found"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="hidden_costs",
                        description=parsed.get("description", "Fees not disclosed until late in checkout"),
                        severity="critical",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

                if parsed.get("pre_checked_addons"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="forced_consent",
                        description="Add-ons or extras are pre-selected in checkout",
                        severity="high",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

                if parsed.get("urgency_timer"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="urgency",
                        description="Artificial countdown timer present in checkout",
                        severity="medium",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

                if parsed.get("sneak_items"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="sneaking",
                        description="Items added to cart without explicit user consent",
                        severity="critical",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

        try:
            await asyncio.to_thread(_run)
            return ScenarioResult(scenario="checkout_flow", status="completed", findings=findings, steps_completed=steps)
        except Exception as e:
            logger.exception("checkout_flow scenario failed")
            return ScenarioResult(scenario="checkout_flow", status="failed", error=str(e), steps_completed=steps)

    # -----------------------------------------------------------------------
    # Scenario: Account Deletion
    # -----------------------------------------------------------------------
    async def _scenario_account_deletion(
        self, url: str, on_event: Optional[Callable] = None
    ) -> ScenarioResult:
        """Detect dark patterns in account deletion flows."""
        from nova_act import NovaAct

        findings = []
        steps = 0

        def _run():
            nonlocal steps
            with NovaAct(starting_url=url, api_key=self.api_key, headless=self.headless) as nova:
                result = nova.act(
                    "Navigate to account settings and look for the option to delete or deactivate "
                    "the account. Describe how easy it is to find and complete account deletion. "
                    "Note any dark patterns like hidden options, required contact with support, "
                    "or emotional manipulation.",
                    schema={
                        "type": "object",
                        "properties": {
                            "delete_option_found": {"type": "boolean"},
                            "requires_support_contact": {"type": "boolean"},
                            "obstruction_found": {"type": "boolean"},
                            "misdirection_found": {"type": "boolean"},
                            "description": {"type": "string"},
                        }
                    }
                )
                steps += 1

                parsed = result.parsed_response or {}
                if parsed.get("obstruction_found") or parsed.get("requires_support_contact"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description=parsed.get("description", "Account deletion is unnecessarily obstructed"),
                        severity="critical",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

                if parsed.get("misdirection_found"):
                    screenshot = nova.take_screenshot()
                    findings.append(Finding(
                        pattern_type="misdirection",
                        description="Account settings use misdirection to hide deletion option",
                        severity="high",
                        screenshot_b64=_encode_screenshot(screenshot),
                    ))

        try:
            await asyncio.to_thread(_run)
            return ScenarioResult(scenario="account_deletion", status="completed", findings=findings, steps_completed=steps)
        except Exception as e:
            logger.exception("account_deletion scenario failed")
            return ScenarioResult(scenario="account_deletion", status="failed", error=str(e), steps_completed=steps)


# ---------------------------------------------------------------------------
# AuditResult dataclass (used by routes)
# ---------------------------------------------------------------------------
@dataclass
class AuditResult:
    """Top-level result object tracked per audit."""
    audit_id: str
    target_url: str
    status: str  # running, completed, failed
    findings: list = field(default_factory=list)
    risk_score: float = 0.0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _encode_screenshot(screenshot: Any) -> Optional[str]:
    """Encode a Nova Act screenshot to base64."""
    if screenshot is None:
        return None
    try:
        if isinstance(screenshot, bytes):
            return base64.b64encode(screenshot).decode()
        if isinstance(screenshot, str):
            return screenshot
        # Nova Act may return an object with .data or .bytes
        if hasattr(screenshot, 'data'):
            return base64.b64encode(screenshot.data).decode()
        if hasattr(screenshot, 'bytes'):
            return base64.b64encode(screenshot.bytes).decode()
    except Exception:
        logger.exception("Failed to encode screenshot")
    return None
