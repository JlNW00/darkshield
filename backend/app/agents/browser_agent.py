"""
DarkShield Browser Agent - Nova Act SDK Integration
Automated dark pattern detection through behavioral testing.
"""
import asyncio
import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Callable, Awaitable
from datetime import datetime, timezone

logger = logging.getLogger("darkshield.agent")


class PatternCategory(str, Enum):
    CONFIRMSHAMING = "confirmshaming"
    MISDIRECTION = "misdirection"
    ROACH_MOTEL = "roach_motel"
    FORCED_CONTINUITY = "forced_continuity"
    HIDDEN_COSTS = "hidden_costs"
    TRICK_QUESTIONS = "trick_questions"
    DISGUISED_ADS = "disguised_ads"
    FRIEND_SPAM = "friend_spam"
    PRIVACY_ZUCKERING = "privacy_zuckering"
    BAIT_AND_SWITCH = "bait_and_switch"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectedPattern:
    """A single dark pattern finding from the browser agent."""
    pattern_id: str
    category: PatternCategory
    severity: Severity
    scenario: str
    description: str
    evidence: str
    screenshot_b64: Optional[str] = None
    screenshot_path: Optional[str] = None
    dom_snapshot: Optional[str] = None
    url: str = ""
    element_selector: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ScenarioResult:
    """Result from running a single audit scenario."""
    scenario_name: str
    url: str
    success: bool
    patterns_found: list[DetectedPattern] = field(default_factory=list)
    steps_taken: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None
    screenshots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scenario_name": self.scenario_name,
            "url": self.url,
            "success": self.success,
            "patterns_found": [p.to_dict() for p in self.patterns_found],
            "steps_taken": self.steps_taken,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "screenshots": self.screenshots,
        }


@dataclass
class AuditResult:
    """Complete audit result across all scenarios."""
    audit_id: str
    target_url: str
    started_at: str
    completed_at: Optional[str] = None
    scenarios: list[ScenarioResult] = field(default_factory=list)
    total_patterns: int = 0
    risk_score: float = 0.0
    status: str = "running"

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "target_url": self.target_url,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "scenarios": [s.to_dict() for s in self.scenarios],
            "total_patterns": self.total_patterns,
            "risk_score": self.risk_score,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Event callback type for streaming progress to WebSocket
# ---------------------------------------------------------------------------
EventCallback = Optional[Callable[[dict], Awaitable[None]]]


class DarkPatternAgent:
    """
    Browser automation agent using Amazon Nova Act SDK.
    
    Navigates target websites and runs behavioral tests to detect
    dark patterns across cookie consent, subscription cancellation,
    checkout flows, and account deletion scenarios.
    """

    def __init__(self, nova_act_api_key: Optional[str] = None):
        self.api_key = nova_act_api_key or os.getenv("NOVA_ACT_API_KEY", "")
        if not self.api_key:
            raise ValueError("NOVA_ACT_API_KEY is required")
        self._pattern_counter = 0

    def _next_pattern_id(self, audit_id: str) -> str:
        self._pattern_counter += 1
        return f"{audit_id}-P{self._pattern_counter:03d}"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    async def run_audit(
        self,
        url: str,
        audit_id: str,
        scenarios: Optional[list[str]] = None,
        on_event: EventCallback = None,
    ) -> AuditResult:
        """
        Run a full dark-pattern audit on *url*.

        Parameters
        ----------
        url : str
            Target website URL.
        audit_id : str
            Unique identifier for this audit run.
        scenarios : list[str] | None
            Subset of scenarios to run. None = all four.
        on_event : EventCallback
            Async callback for streaming progress events.
        """
        from nova_act import NovaAct  # imported here so tests can mock

        all_scenarios = {
            "cookie_consent": self._scenario_cookie_consent,
            "subscription_cancel": self._scenario_subscription_cancel,
            "checkout_flow": self._scenario_checkout_flow,
            "account_deletion": self._scenario_account_deletion,
        }

        chosen = scenarios or list(all_scenarios.keys())
        result = AuditResult(
            audit_id=audit_id,
            target_url=url,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        await self._emit(on_event, {
            "type": "audit_started",
            "audit_id": audit_id,
            "url": url,
            "scenarios": chosen,
        })

        for name in chosen:
            fn = all_scenarios.get(name)
            if fn is None:
                logger.warning("Unknown scenario: %s", name)
                continue

            await self._emit(on_event, {
                "type": "scenario_started",
                "audit_id": audit_id,
                "scenario": name,
            })

            t0 = time.monotonic()
            try:
                scenario_result = await fn(url, audit_id, NovaAct, on_event)
                scenario_result.duration_seconds = round(time.monotonic() - t0, 2)
                result.scenarios.append(scenario_result)
            except Exception as exc:
                logger.exception("Scenario %s failed", name)
                result.scenarios.append(ScenarioResult(
                    scenario_name=name,
                    url=url,
                    success=False,
                    error=str(exc),
                    duration_seconds=round(time.monotonic() - t0, 2),
                ))

            await self._emit(on_event, {
                "type": "scenario_completed",
                "audit_id": audit_id,
                "scenario": name,
                "patterns_found": len(result.scenarios[-1].patterns_found),
            })

        # Aggregate
        all_patterns = [p for s in result.scenarios for p in s.patterns_found]
        result.total_patterns = len(all_patterns)
        result.risk_score = self._calculate_risk_score(all_patterns)
        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.status = "completed"

        await self._emit(on_event, {
            "type": "audit_completed",
            "audit_id": audit_id,
            "total_patterns": result.total_patterns,
            "risk_score": result.risk_score,
        })

        return result

    # ------------------------------------------------------------------
    # Scenario 1: Cookie Consent
    # ------------------------------------------------------------------
    async def _scenario_cookie_consent(
        self, url: str, audit_id: str, NovaAct, on_event: EventCallback
    ) -> ScenarioResult:
        """
        Tests cookie consent banners for dark patterns:
        - Asymmetric button sizing (accept huge, reject tiny)
        - Pre-checked consent boxes
        - Difficulty dismissing / rejecting
        - Confusing language on reject option
        """
        result = ScenarioResult(scenario_name="cookie_consent", url=url, success=True)
        steps = 0

        with NovaAct(starting_page=url, api_key=self.api_key) as nova:
            # Step 1: Detect cookie banner presence
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "cookie_consent",
                "step": steps,
                "action": "Scanning page for cookie consent banner",
            })

            banner_check = nova.act(
                "Look at the current page. Is there a cookie consent banner, popup, or overlay visible? "
                "Respond with a JSON object: {\"banner_found\": true/false, \"banner_text\": \"...\", "
                "\"accept_button_text\": \"...\", \"reject_button_text\": \"...\", "
                "\"has_reject_option\": true/false, \"reject_visibility\": \"prominent/subtle/hidden/none\"}"
            )

            screenshot_b64 = self._capture_screenshot(nova)
            result.screenshots.append(f"cookie_banner_{steps}")

            banner_data = self._parse_act_response(banner_check.response)

            if not banner_data.get("banner_found", False):
                await self._emit(on_event, {
                    "type": "agent_observation",
                    "audit_id": audit_id,
                    "scenario": "cookie_consent",
                    "observation": "No cookie consent banner detected",
                })
                result.steps_taken = steps
                return result

            # Check 1: Missing or hidden reject option
            if not banner_data.get("has_reject_option", True):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.HIGH,
                    scenario="cookie_consent",
                    description="No visible option to reject cookies",
                    evidence=f"Cookie banner has accept button ('{banner_data.get('accept_button_text', 'Accept')}') but no reject/decline option",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.95,
                ))

            if banner_data.get("reject_visibility") in ("subtle", "hidden"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="cookie_consent",
                    description="Reject option is visually de-emphasized compared to accept",
                    evidence=f"Reject visibility: {banner_data.get('reject_visibility')}. Accept button: '{banner_data.get('accept_button_text')}', Reject: '{banner_data.get('reject_button_text')}'",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.85,
                ))

            # Step 2: Check button asymmetry
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "cookie_consent",
                "step": steps,
                "action": "Analyzing button sizes and visual hierarchy",
            })

            asymmetry_check = nova.act(
                "Compare the accept and reject buttons on the cookie banner. "
                "Respond with JSON: {\"accept_button_size\": \"large/medium/small\", "
                "\"reject_button_size\": \"large/medium/small\", "
                "\"accept_is_colored\": true/false, \"reject_is_colored\": true/false, "
                "\"accept_is_button\": true/false, \"reject_is_button\": true/false, "
                "\"reject_is_link_only\": true/false, "
                "\"size_difference\": \"none/slight/significant/extreme\"}"
            )

            asymmetry_data = self._parse_act_response(asymmetry_check.response)

            if asymmetry_data.get("size_difference") in ("significant", "extreme"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM if asymmetry_data["size_difference"] == "significant" else Severity.HIGH,
                    scenario="cookie_consent",
                    description="Asymmetric button design biases users toward accepting cookies",
                    evidence=f"Accept: {asymmetry_data.get('accept_button_size')} {'colored' if asymmetry_data.get('accept_is_colored') else 'plain'} button. Reject: {asymmetry_data.get('reject_button_size')} {'colored' if asymmetry_data.get('reject_is_colored') else 'plain'} {'button' if asymmetry_data.get('reject_is_button') else 'link'}",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.9,
                ))

            if asymmetry_data.get("reject_is_link_only"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="cookie_consent",
                    description="Reject option styled as plain text link instead of button",
                    evidence="Accept is a styled button while reject is only a text link, reducing visual prominence",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.88,
                ))

            # Step 3: Check for pre-checked boxes
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "cookie_consent",
                "step": steps,
                "action": "Checking for pre-selected consent categories",
            })

            precheck_result = nova.act(
                "Look for a 'manage preferences', 'cookie settings', or 'customize' button/link on the cookie banner and click it if found. "
                "Then check: are there consent category checkboxes? Are any pre-checked (besides 'necessary'/'essential')? "
                "Respond with JSON: {\"settings_found\": true/false, \"categories\": [{\"name\": \"...\", \"pre_checked\": true/false, \"is_essential\": true/false}], "
                "\"non_essential_pre_checked\": true/false}"
            )

            screenshot_b64_settings = self._capture_screenshot(nova)

            precheck_data = self._parse_act_response(precheck_result.response)

            if precheck_data.get("non_essential_pre_checked"):
                pre_checked_cats = [
                    c["name"] for c in precheck_data.get("categories", [])
                    if c.get("pre_checked") and not c.get("is_essential")
                ]
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.TRICK_QUESTIONS,
                    severity=Severity.HIGH,
                    scenario="cookie_consent",
                    description="Non-essential cookie categories are pre-checked by default",
                    evidence=f"Pre-checked non-essential categories: {', '.join(pre_checked_cats)}",
                    screenshot_b64=screenshot_b64_settings,
                    url=url,
                    confidence=0.92,
                ))

            # Step 4: Try to dismiss / reject and verify
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "cookie_consent",
                "step": steps,
                "action": "Attempting to reject cookies and verifying dismissal",
            })

            dismiss_result = nova.act(
                "Try to reject all non-essential cookies. Click 'Reject All', 'Decline', or uncheck all non-essential boxes and save. "
                "Then check: did the cookie banner actually dismiss? Is the page usable? "
                "Respond with JSON: {\"rejected_successfully\": true/false, \"banner_dismissed\": true/false, "
                "\"page_blocked\": true/false, \"required_extra_steps\": 0}"
            )

            dismiss_data = self._parse_act_response(dismiss_result.response)

            if dismiss_data.get("page_blocked"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.FORCED_CONTINUITY,
                    severity=Severity.CRITICAL,
                    scenario="cookie_consent",
                    description="Page blocks access after rejecting cookies (cookie wall)",
                    evidence="Attempting to reject cookies resulted in page content being blocked or inaccessible",
                    screenshot_b64=self._capture_screenshot(nova),
                    url=url,
                    confidence=0.95,
                ))

            extra_steps = dismiss_data.get("required_extra_steps", 0)
            if extra_steps and extra_steps > 2:
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.MEDIUM,
                    scenario="cookie_consent",
                    description="Rejecting cookies requires significantly more steps than accepting",
                    evidence=f"Accepting: 1 click. Rejecting: {extra_steps} steps required",
                    screenshot_b64=self._capture_screenshot(nova),
                    url=url,
                    confidence=0.88,
                ))

        result.steps_taken = steps
        return result

    # ------------------------------------------------------------------
    # Scenario 2: Subscription Cancellation
    # ------------------------------------------------------------------
    async def _scenario_subscription_cancel(
        self, url: str, audit_id: str, NovaAct, on_event: EventCallback
    ) -> ScenarioResult:
        """
        Tests subscription cancellation flow for:
        - Excessive steps to cancel
        - Confirmshaming language
        - Hidden cancel options
        - Dark pattern retention offers
        """
        result = ScenarioResult(scenario_name="subscription_cancel", url=url, success=True)
        steps = 0

        with NovaAct(starting_page=url, api_key=self.api_key) as nova:
            # Step 1: Navigate to account/settings
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "subscription_cancel",
                "step": steps,
                "action": "Navigating to account settings or subscription management",
            })

            nav_result = nova.act(
                "Find and navigate to the account settings, subscription management, or membership page. "
                "Look in the header menu, profile dropdown, footer links, or settings page. "
                "Respond with JSON: {\"found_settings\": true/false, \"navigation_path\": \"description of how you got there\", "
                "\"clicks_required\": 0}"
            )

            nav_data = self._parse_act_response(nav_result.response)
            screenshot_b64 = self._capture_screenshot(nova)

            if not nav_data.get("found_settings"):
                await self._emit(on_event, {
                    "type": "agent_observation",
                    "audit_id": audit_id,
                    "scenario": "subscription_cancel",
                    "observation": "Could not locate account/subscription settings (may require login)",
                })
                result.steps_taken = steps
                return result

            # Step 2: Find the cancel option
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "subscription_cancel",
                "step": steps,
                "action": "Searching for cancellation option",
            })

            cancel_search = nova.act(
                "Look for a 'Cancel subscription', 'Cancel membership', 'Cancel plan', or 'End subscription' option on this page. "
                "Do NOT click it yet. Report: {\"cancel_option_found\": true/false, "
                "\"cancel_text\": \"...\", \"cancel_prominence\": \"prominent/subtle/hidden\", "
                "\"cancel_location\": \"description of where it is\", "
                "\"is_buried_in_submenu\": true/false}"
            )

            cancel_data = self._parse_act_response(cancel_search.response)
            screenshot_b64_cancel = self._capture_screenshot(nova)

            if not cancel_data.get("cancel_option_found"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.CRITICAL,
                    scenario="subscription_cancel",
                    description="No visible cancellation option found in account settings",
                    evidence="Searched account/subscription settings but could not locate any cancel option",
                    screenshot_b64=screenshot_b64_cancel,
                    url=url,
                    confidence=0.9,
                ))
                result.steps_taken = steps
                return result

            if cancel_data.get("cancel_prominence") in ("subtle", "hidden"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="subscription_cancel",
                    description="Cancel option is visually hidden or de-emphasized",
                    evidence=f"Cancel prominence: {cancel_data.get('cancel_prominence')}. Location: {cancel_data.get('cancel_location', 'unknown')}",
                    screenshot_b64=screenshot_b64_cancel,
                    url=url,
                    confidence=0.85,
                ))

            if cancel_data.get("is_buried_in_submenu"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.MEDIUM,
                    scenario="subscription_cancel",
                    description="Cancel option is buried in a submenu or requires navigation through multiple pages",
                    evidence=f"Cancel located at: {cancel_data.get('cancel_location', 'deep submenu')}",
                    screenshot_b64=screenshot_b64_cancel,
                    url=url,
                    confidence=0.82,
                ))

            # Step 3: Click cancel and analyze the flow
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "subscription_cancel",
                "step": steps,
                "action": "Initiating cancellation to analyze the flow",
            })

            cancel_flow = nova.act(
                "Click the cancel subscription/membership option. Go through each step of the cancellation process, "
                "but STOP before the final confirmation. At each step, note: "
                "1) Any guilt-trip or confirmshaming language (e.g., 'Are you sure? You'll lose...'). "
                "2) Any retention offers or discounts shown. "
                "3) How many total steps/pages are in the cancellation flow. "
                "4) Whether the 'keep subscription' button is more prominent than 'continue canceling'. "
                "Respond with JSON: {\"total_steps\": 0, \"confirmshaming_texts\": [\"...\"], "
                "\"retention_offers\": [{\"type\": \"discount/pause/downgrade\", \"text\": \"...\"}], "
                "\"keep_button_more_prominent\": true/false, "
                "\"cancel_button_text\": \"...\", \"keep_button_text\": \"...\", "
                "\"emotional_language_used\": true/false, \"emotional_examples\": [\"...\"]}"
            )

            flow_data = self._parse_act_response(cancel_flow.response)
            screenshot_b64_flow = self._capture_screenshot(nova)

            # Check confirmshaming
            confirmshaming = flow_data.get("confirmshaming_texts", [])
            emotional = flow_data.get("emotional_examples", [])

            if confirmshaming or flow_data.get("emotional_language_used"):
                all_shame = confirmshaming + emotional
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.CONFIRMSHAMING,
                    severity=Severity.HIGH,
                    scenario="subscription_cancel",
                    description="Cancellation flow uses guilt-trip or emotionally manipulative language",
                    evidence=f"Confirmshaming examples: {'; '.join(all_shame[:5])}",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.9,
                ))

            # Check excessive steps
            total_steps = flow_data.get("total_steps", 0)
            if total_steps and total_steps > 3:
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.HIGH if total_steps > 5 else Severity.MEDIUM,
                    scenario="subscription_cancel",
                    description="Cancellation requires excessive number of steps",
                    evidence=f"Subscription signup: ~2 steps. Cancellation: {total_steps} steps",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.88,
                ))

            # Check asymmetric button prominence
            if flow_data.get("keep_button_more_prominent"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="subscription_cancel",
                    description="'Keep subscription' button is more visually prominent than 'Cancel'",
                    evidence=f"Keep button: '{flow_data.get('keep_button_text', 'Keep')}' (prominent). Cancel button: '{flow_data.get('cancel_button_text', 'Cancel')}' (de-emphasized)",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.87,
                ))

        result.steps_taken = steps
        return result

    # ------------------------------------------------------------------
    # Scenario 3: Checkout Flow
    # ------------------------------------------------------------------
    async def _scenario_checkout_flow(
        self, url: str, audit_id: str, NovaAct, on_event: EventCallback
    ) -> ScenarioResult:
        """
        Tests checkout/purchase flow for:
        - Hidden costs added during checkout
        - Pre-selected add-ons or insurance
        - Urgency/scarcity indicators (fake timers, low stock)
        - Bait-and-switch pricing
        """
        result = ScenarioResult(scenario_name="checkout_flow", url=url, success=True)
        steps = 0

        with NovaAct(starting_page=url, api_key=self.api_key) as nova:
            # Step 1: Navigate to a product and capture initial price
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "checkout_flow",
                "step": steps,
                "action": "Finding a product and capturing listed price",
            })

            product_check = nova.act(
                "Find any purchasable product, service, or plan on this website. Note the displayed price. "
                "Also look for urgency indicators: countdown timers, 'limited time', 'X left in stock', 'Y people viewing'. "
                "Respond with JSON: {\"product_found\": true/false, \"product_name\": \"...\", "
                "\"displayed_price\": \"...\", \"has_countdown_timer\": true/false, "
                "\"has_scarcity_indicator\": true/false, \"scarcity_text\": \"...\", "
                "\"has_social_proof_pressure\": true/false, \"social_proof_text\": \"...\"}"
            )

            product_data = self._parse_act_response(product_check.response)
            screenshot_b64 = self._capture_screenshot(nova)

            if not product_data.get("product_found"):
                await self._emit(on_event, {
                    "type": "agent_observation",
                    "audit_id": audit_id,
                    "scenario": "checkout_flow",
                    "observation": "No purchasable product found on the page",
                })
                result.steps_taken = steps
                return result

            initial_price = product_data.get("displayed_price", "unknown")

            # Check urgency/scarcity dark patterns
            if product_data.get("has_countdown_timer"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="checkout_flow",
                    description="Countdown timer creates artificial urgency",
                    evidence="Page displays a countdown timer near the product/price",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.75,
                    metadata={"note": "Timer may be legitimate for actual sales; requires context"},
                ))

            if product_data.get("has_scarcity_indicator"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="checkout_flow",
                    description="Scarcity indicator may create false urgency",
                    evidence=f"Scarcity text: '{product_data.get('scarcity_text', 'N/A')}'",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.7,
                    metadata={"note": "May reflect actual inventory; flagged for review"},
                ))

            # Step 2: Add to cart and proceed to checkout
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "checkout_flow",
                "step": steps,
                "action": "Adding product to cart and proceeding to checkout",
            })

            cart_result = nova.act(
                "Add the product to cart and proceed to the checkout page. "
                "Look carefully for: pre-selected add-ons, insurance, warranties, donations, "
                "or any item that was NOT explicitly chosen but appears in the cart. "
                "Compare the checkout total with the original displayed price. "
                "Respond with JSON: {\"reached_checkout\": true/false, "
                "\"original_price\": \"" + initial_price + "\", \"checkout_total\": \"...\", "
                "\"price_increased\": true/false, \"price_difference\": \"...\", "
                "\"pre_selected_addons\": [{\"name\": \"...\", \"price\": \"...\", \"was_opt_in\": false}], "
                "\"hidden_fees\": [{\"name\": \"...\", \"amount\": \"...\"}], "
                "\"has_donation_preselected\": true/false}"
            )

            cart_data = self._parse_act_response(cart_result.response)
            screenshot_b64_cart = self._capture_screenshot(nova)

            if cart_data.get("price_increased"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.HIDDEN_COSTS,
                    severity=Severity.HIGH,
                    scenario="checkout_flow",
                    description="Price increased between product page and checkout",
                    evidence=f"Product page: {cart_data.get('original_price', initial_price)}. Checkout: {cart_data.get('checkout_total', 'unknown')}. Difference: {cart_data.get('price_difference', 'unknown')}",
                    screenshot_b64=screenshot_b64_cart,
                    url=url,
                    confidence=0.9,
                ))

            for addon in cart_data.get("pre_selected_addons", []):
                if not addon.get("was_opt_in", True):
                    result.patterns_found.append(DetectedPattern(
                        pattern_id=self._next_pattern_id(audit_id),
                        category=PatternCategory.BAIT_AND_SWITCH,
                        severity=Severity.HIGH,
                        scenario="checkout_flow",
                        description=f"Pre-selected add-on: {addon.get('name', 'Unknown')}",
                        evidence=f"'{addon.get('name')}' ({addon.get('price', '?')}) was automatically added to cart without explicit opt-in",
                        screenshot_b64=screenshot_b64_cart,
                        url=url,
                        confidence=0.92,
                    ))

            for fee in cart_data.get("hidden_fees", []):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.HIDDEN_COSTS,
                    severity=Severity.HIGH,
                    scenario="checkout_flow",
                    description=f"Hidden fee: {fee.get('name', 'Unknown')}",
                    evidence=f"Fee '{fee.get('name')}' ({fee.get('amount', '?')}) appeared at checkout, not shown on product page",
                    screenshot_b64=screenshot_b64_cart,
                    url=url,
                    confidence=0.88,
                ))

            if cart_data.get("has_donation_preselected"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.TRICK_QUESTIONS,
                    severity=Severity.MEDIUM,
                    scenario="checkout_flow",
                    description="Charitable donation pre-selected at checkout",
                    evidence="A donation was automatically included in the cart total",
                    screenshot_b64=screenshot_b64_cart,
                    url=url,
                    confidence=0.85,
                ))

            # Step 3: Check for trick questions in the form
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "checkout_flow",
                "step": steps,
                "action": "Scanning checkout form for confusing opt-in/opt-out patterns",
            })

            form_check = nova.act(
                "Examine the checkout form carefully. Look for: "
                "1) Double-negative checkboxes (e.g., 'Uncheck to not receive emails'). "
                "2) Pre-checked newsletter/marketing sign-ups. "
                "3) Confusing language about data sharing. "
                "4) Any checkbox that's intentionally hard to understand. "
                "Respond with JSON: {\"trick_questions_found\": [{\"text\": \"...\", "
                "\"is_pre_checked\": true/false, \"is_double_negative\": true/false, \"confusion_type\": \"...\"}], "
                "\"pre_checked_marketing\": true/false}"
            )

            form_data = self._parse_act_response(form_check.response)

            for trick in form_data.get("trick_questions_found", []):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.TRICK_QUESTIONS,
                    severity=Severity.MEDIUM,
                    scenario="checkout_flow",
                    description=f"Confusing checkbox: {trick.get('confusion_type', 'misleading language')}",
                    evidence=f"Text: '{trick.get('text', 'N/A')}'. Pre-checked: {trick.get('is_pre_checked')}. Double-negative: {trick.get('is_double_negative')}",
                    screenshot_b64=self._capture_screenshot(nova),
                    url=url,
                    confidence=0.83,
                ))

        result.steps_taken = steps
        return result

    # ------------------------------------------------------------------
    # Scenario 4: Account Deletion
    # ------------------------------------------------------------------
    async def _scenario_account_deletion(
        self, url: str, audit_id: str, NovaAct, on_event: EventCallback
    ) -> ScenarioResult:
        """
        Tests account deletion flow for:
        - Excessive confirmation steps
        - Emotional manipulation / guilt-trip language
        - Hidden delete option
        - Forced waiting periods
        """
        result = ScenarioResult(scenario_name="account_deletion", url=url, success=True)
        steps = 0

        with NovaAct(starting_page=url, api_key=self.api_key) as nova:
            # Step 1: Find account deletion option
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "account_deletion",
                "step": steps,
                "action": "Searching for account deletion option",
            })

            delete_search = nova.act(
                "Navigate to account settings and look for an option to delete the account, "
                "close the account, or deactivate the account. Check the settings page, "
                "privacy settings, security settings, and any 'danger zone' section. "
                "Do NOT click it yet. "
                "Respond with JSON: {\"delete_option_found\": true/false, "
                "\"delete_text\": \"...\", \"location\": \"...\", "
                "\"pages_navigated\": 0, \"prominence\": \"prominent/subtle/hidden\", "
                "\"requires_contact_support\": true/false}"
            )

            delete_data = self._parse_act_response(delete_search.response)
            screenshot_b64 = self._capture_screenshot(nova)

            if not delete_data.get("delete_option_found"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.CRITICAL,
                    scenario="account_deletion",
                    description="No self-service account deletion option found",
                    evidence="Searched all settings pages; no delete/close account option available to users",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.9,
                ))
                result.steps_taken = steps
                return result

            if delete_data.get("requires_contact_support"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.HIGH,
                    scenario="account_deletion",
                    description="Account deletion requires contacting customer support",
                    evidence="Users cannot delete their own account -- must email or call support",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.92,
                ))

            if delete_data.get("prominence") in ("subtle", "hidden"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.MISDIRECTION,
                    severity=Severity.MEDIUM,
                    scenario="account_deletion",
                    description="Account deletion option is hidden or hard to find",
                    evidence=f"Delete option found at: {delete_data.get('location', 'unknown')}. Required navigating {delete_data.get('pages_navigated', '?')} pages",
                    screenshot_b64=screenshot_b64,
                    url=url,
                    confidence=0.85,
                ))

            # Step 2: Click delete and analyze the flow
            steps += 1
            await self._emit(on_event, {
                "type": "agent_action",
                "audit_id": audit_id,
                "scenario": "account_deletion",
                "step": steps,
                "action": "Initiating account deletion flow to analyze barriers",
            })

            deletion_flow = nova.act(
                "Click the delete/close account option. Go through the deletion process "
                "but STOP before the final irreversible confirmation. At each step, note: "
                "1) Any guilt-trip language ('We'll miss you', 'Your friends will lose access'). "
                "2) Any scary warnings about data loss. "
                "3) Total number of confirmation steps/pages. "
                "4) Any forced waiting period mentioned. "
                "5) Any 'reactivation' pitch or 'maybe just deactivate instead?' suggestions. "
                "Respond with JSON: {\"total_confirmation_steps\": 0, "
                "\"guilt_trip_texts\": [\"...\"], \"scary_warnings\": [\"...\"], "
                "\"forced_waiting_period\": \"none/days/weeks\", \"waiting_period_text\": \"...\", "
                "\"offered_deactivation_instead\": true/false, "
                "\"required_type_confirmation\": true/false, "
                "\"required_survey\": true/false, \"survey_mandatory\": true/false}"
            )

            flow_data = self._parse_act_response(deletion_flow.response)
            screenshot_b64_flow = self._capture_screenshot(nova)

            # Check guilt-trip language
            guilt_texts = flow_data.get("guilt_trip_texts", [])
            if guilt_texts:
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.CONFIRMSHAMING,
                    severity=Severity.HIGH,
                    scenario="account_deletion",
                    description="Account deletion flow uses guilt-trip language",
                    evidence=f"Guilt-trip examples: {'; '.join(guilt_texts[:5])}",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.9,
                ))

            # Check excessive confirmations
            confirm_steps = flow_data.get("total_confirmation_steps", 0)
            if confirm_steps and confirm_steps > 3:
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.HIGH if confirm_steps > 5 else Severity.MEDIUM,
                    scenario="account_deletion",
                    description="Account deletion requires excessive confirmation steps",
                    evidence=f"Account creation: ~2 steps. Deletion: {confirm_steps} confirmation steps",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.88,
                ))

            # Check forced waiting period
            if flow_data.get("forced_waiting_period") != "none" and flow_data.get("forced_waiting_period"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.FORCED_CONTINUITY,
                    severity=Severity.MEDIUM,
                    scenario="account_deletion",
                    description="Account deletion has a forced waiting/cooling-off period",
                    evidence=f"Waiting period: {flow_data.get('waiting_period_text', flow_data.get('forced_waiting_period'))}",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.8,
                    metadata={"note": "Some jurisdictions require cooling-off periods; may be legitimate"},
                ))

            # Check mandatory survey
            if flow_data.get("required_survey") and flow_data.get("survey_mandatory"):
                result.patterns_found.append(DetectedPattern(
                    pattern_id=self._next_pattern_id(audit_id),
                    category=PatternCategory.ROACH_MOTEL,
                    severity=Severity.LOW,
                    scenario="account_deletion",
                    description="Mandatory survey required before account deletion",
                    evidence="Users must complete a survey to proceed with deletion",
                    screenshot_b64=screenshot_b64_flow,
                    url=url,
                    confidence=0.8,
                ))

        result.steps_taken = steps
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    async def _emit(callback: EventCallback, event: dict):
        """Send an event through the callback if provided."""
        if callback:
            try:
                await callback(event)
            except Exception:
                logger.warning("Event callback failed", exc_info=True)

    @staticmethod
    def _capture_screenshot(nova) -> Optional[str]:
        """Capture a screenshot from the Nova browser session."""
        try:
            screenshot = nova.get_screenshot()
            if isinstance(screenshot, bytes):
                return base64.b64encode(screenshot).decode("utf-8")
            elif isinstance(screenshot, str):
                return screenshot
        except Exception:
            logger.warning("Screenshot capture failed", exc_info=True)
        return None

    @staticmethod
    def _parse_act_response(response: str) -> dict:
        """Extract JSON from a Nova Act response string."""
        if not response:
            return {}
        # Try direct parse
        try:
            return json.loads(response)
        except (json.JSONDecodeError, TypeError):
            pass
        # Try extracting JSON from markdown code block
        if "```" in str(response):
            try:
                json_str = str(response).split("```json")[-1].split("```")[0].strip()
                return json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                pass
            try:
                json_str = str(response).split("```")[-2].strip()
                return json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                pass
        # Try finding JSON object in the string
        text = str(response)
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass
        logger.warning("Could not parse JSON from response: %s", response[:200])
        return {}

    @staticmethod
    def _calculate_risk_score(patterns: list[DetectedPattern]) -> float:
        """Calculate overall risk score 0-10 based on findings."""
        if not patterns:
            return 0.0

        severity_weights = {
            Severity.LOW: 1.0,
            Severity.MEDIUM: 2.5,
            Severity.HIGH: 5.0,
            Severity.CRITICAL: 8.0,
        }

        total_weight = sum(
            severity_weights.get(p.severity, 1.0) * p.confidence
            for p in patterns
        )

        # Normalize: 0-10 scale, with diminishing returns after ~5 major findings
        raw = total_weight / 3.0
        score = min(10.0, raw * (1 - 0.3 * (raw / 20.0)))  # soft cap
        return round(score, 2)
