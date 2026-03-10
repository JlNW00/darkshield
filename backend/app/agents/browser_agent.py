""" 
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
                await on_event({
                    "type": "scenario_start",
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
                    duration_seconds=time.time() - start,
                    error=str(e),
                ))

            if on_event:
                await on_event({
                    "type": "scenario_end",
                    "scenario": name,
                    "status": results[-1].status,
                    "findings_count": len(results[-1].findings),
                })

        return results

    # -- Blocking helpers (run inside thread) ---------------------------

    def _run_nova_session(self, url: str, actions: list[dict]) -> list[dict]:
        """
        Synchronous helper that opens a Nova Act session and executes a
        sequence of actions. Each action dict has:
          - "instruction": str passed to nova.act()
          - "name": human label for logging
        Returns a list of result dicts with keys: name, success, result, screenshot_b64.
        """
        from nova_act import NovaAct  # imported here to avoid top-level dep issues

        step_results = []
        with NovaAct(
            starting_page=url,
            api_key=self.api_key,
            headless=self.headless,
        ) as nova:
            for action in actions:
                name = action.get("name", "step")
                instruction = action["instruction"]
                logger.debug(f"Nova Act step '{name}': {instruction}")
                try:
                    result = nova.act(instruction)
                    # Capture screenshot after each step
                    screenshot_b64 = None
                    try:
                        png_bytes = nova.page.screenshot()
                        screenshot_b64 = base64.b64encode(png_bytes).decode()
                    except Exception:
                        pass

                    step_results.append({
                        "name": name,
                        "success": getattr(result, "success", True),
                        "result": str(getattr(result, "response", result)),
                        "screenshot_b64": screenshot_b64,
                    })
                except Exception as e:
                    step_results.append({
                        "name": name,
                        "success": False,
                        "result": str(e),
                        "screenshot_b64": None,
                    })
        return step_results

    # -- Scenarios ------------------------------------------------------

    async def _scenario_cookie_consent(
        self, url: str, on_event: Optional[Callable] = None,
    ) -> ScenarioResult:
        """Test cookie consent banners for dark patterns."""
        findings = []

        actions = [
            {
                "name": "detect_banner",
                "instruction": (
                    "Look for a cookie consent banner or popup on this page. "
                    "Describe what you see: is there an accept button, a reject/decline button, "
                    "and a settings/customize button? Note the relative sizes and colors of the buttons."
                ),
            },
            {
                "name": "check_reject",
                "instruction": (
                    "Try to reject all cookies or decline. Is there a visible 'Reject All' or "
                    "'Decline' button? If so, click it. If not, describe what options are available "
                    "to dismiss cookies without accepting."
                ),
            },
            {
                "name": "check_preselected",
                "instruction": (
                    "If there is a cookie settings/preferences panel, open it. "
                    "Check if any non-essential cookie categories are pre-selected/pre-checked. "
                    "List which categories are toggled on by default."
                ),
            },
            {
                "name": "check_dismiss",
                "instruction": (
                    "Try to close or dismiss the cookie banner without making a choice. "
                    "Is there an X button or can you click outside the banner? "
                    "Does the banner block interaction with the page underneath?"
                ),
            },
        ]

        if on_event:
            await on_event({"type": "step", "scenario": "cookie_consent", "message": "Launching browser for cookie consent audit..."})

        # Run all blocking Nova Act steps in a thread
        step_results = await asyncio.to_thread(self._run_nova_session, url, actions)

        steps_completed = sum(1 for s in step_results if s["success"])

        # Analyze results for dark patterns
        for step in step_results:
            result_text = step["result"].lower()

            if step["name"] == "detect_banner":
                if "no" in result_text and ("reject" in result_text or "decline" in result_text):
                    findings.append(Finding(
                        pattern_type="asymmetric_choice",
                        description="Cookie banner has Accept button but no visible Reject option",
                        severity="high",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))
                if "larger" in result_text or "prominent" in result_text or "bigger" in result_text:
                    findings.append(Finding(
                        pattern_type="interface_interference",
                        description="Accept button is visually more prominent than alternatives",
                        severity="medium",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "check_preselected":
                if "pre-selected" in result_text or "pre-checked" in result_text or "toggled on" in result_text:
                    findings.append(Finding(
                        pattern_type="forced_consent",
                        description="Non-essential cookies are pre-selected by default",
                        severity="high",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "check_dismiss":
                if "block" in result_text or "cannot" in result_text or "no x" in result_text:
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description="Cookie banner blocks page interaction and cannot be easily dismissed",
                        severity="medium",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

        return ScenarioResult(
            scenario="cookie_consent",
            status="completed",
            findings=findings,
            steps_completed=steps_completed,
        )

    async def _scenario_subscription_cancel(
        self, url: str, on_event: Optional[Callable] = None,
    ) -> ScenarioResult:
        """Test subscription cancellation flow for dark patterns."""
        findings = []

        actions = [
            {
                "name": "find_cancel",
                "instruction": (
                    "Navigate to account settings, subscription, or billing page. "
                    "Look for a cancel subscription or cancel membership option. "
                    "Describe where you found it and how many clicks it took to reach."
                ),
            },
            {
                "name": "start_cancel",
                "instruction": (
                    "Click the cancel button or link. What happens? Is there a confirmation page, "
                    "a survey, discount offers, guilt-tripping language, or multiple steps? "
                    "Describe each screen you encounter."
                ),
            },
            {
                "name": "count_steps",
                "instruction": (
                    "Continue through the entire cancellation flow until you reach the final "
                    "confirmation. Count every page, popup, and confirmation step. "
                    "Note any emotional language, special offers, or confusing button labels."
                ),
            },
            {
                "name": "verify_cancel",
                "instruction": (
                    "After completing the cancellation flow, verify the subscription status. "
                    "Is it actually cancelled? Or is it scheduled for end of billing period? "
                    "Was there a final 'are you sure?' confirmation?"
                ),
            },
        ]

        if on_event:
            await on_event({"type": "step", "scenario": "subscription_cancel", "message": "Testing subscription cancellation flow..."})

        step_results = await asyncio.to_thread(self._run_nova_session, url, actions)
        steps_completed = sum(1 for s in step_results if s["success"])

        for step in step_results:
            result_text = step["result"].lower()

            if step["name"] == "find_cancel":
                if any(w in result_text for w in ["couldn't find", "unable to locate", "no cancel", "not found"]):
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description="Cancel option is hidden or extremely difficult to find",
                        severity="critical",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "start_cancel":
                if any(w in result_text for w in ["guilt", "miss out", "lose", "sad", "sorry to see"]):
                    findings.append(Finding(
                        pattern_type="confirmshaming",
                        description="Cancellation flow uses guilt-tripping or emotional language",
                        severity="high",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))
                if any(w in result_text for w in ["discount", "offer", "deal", "special price"]):
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description="Retention offers interrupt the cancellation flow",
                        severity="medium",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "count_steps":
                if any(w in result_text for w in ["multiple", "several", "many steps", "5", "6", "7"]):
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description="Cancellation requires an excessive number of steps",
                        severity="high",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

        return ScenarioResult(
            scenario="subscription_cancel",
            status="completed",
            findings=findings,
            steps_completed=steps_completed,
        )

    async def _scenario_checkout_flow(
        self, url: str, on_event: Optional[Callable] = None,
    ) -> ScenarioResult:
        """Test checkout flow for sneaky additions and hidden costs."""
        findings = []

        actions = [
            {
                "name": "add_item",
                "instruction": (
                    "Find a product on this site and add it to the cart. "
                    "Then navigate to the cart/checkout page. "
                    "Describe what you see in the cart."
                ),
            },
            {
                "name": "check_extras",
                "instruction": (
                    "Look at all items in the cart. Are there any items you didn't add? "
                    "Check for pre-selected add-ons, insurance, warranties, donations, "
                    "or any extras that were automatically included."
                ),
            },
            {
                "name": "check_pricing",
                "instruction": (
                    "Examine the price breakdown. Are there any hidden fees, service charges, "
                    "or costs that weren't shown on the product page? Compare the displayed "
                    "product price with the checkout total before shipping."
                ),
            },
            {
                "name": "check_urgency",
                "instruction": (
                    "Look for urgency or scarcity cues: countdown timers, 'only X left', "
                    "'Y people viewing this', limited time offers, or pressure to complete "
                    "checkout quickly. Describe any you find."
                ),
            },
        ]

        if on_event:
            await on_event({"type": "step", "scenario": "checkout_flow", "message": "Testing checkout for hidden costs and sneaky additions..."})

        step_results = await asyncio.to_thread(self._run_nova_session, url, actions)
        steps_completed = sum(1 for s in step_results if s["success"])

        for step in step_results:
            result_text = step["result"].lower()

            if step["name"] == "check_extras":
                if any(w in result_text for w in ["pre-selected", "automatically added", "didn't add", "included by default"]):
                    findings.append(Finding(
                        pattern_type="sneaking",
                        description="Items or services were pre-added to cart without explicit user action",
                        severity="critical",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "check_pricing":
                if any(w in result_text for w in ["hidden fee", "service charge", "not shown", "additional cost", "higher"]):
                    findings.append(Finding(
                        pattern_type="hidden_costs",
                        description="Fees or charges not disclosed until checkout",
                        severity="critical",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "check_urgency":
                if any(w in result_text for w in ["countdown", "timer", "only", "left", "viewing", "hurry", "limited"]):
                    findings.append(Finding(
                        pattern_type="urgency",
                        description="Artificial urgency or scarcity cues used to pressure purchase",
                        severity="medium",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

        return ScenarioResult(
            scenario="checkout_flow",
            status="completed",
            findings=findings,
            steps_completed=steps_completed,
        )

    async def _scenario_account_deletion(
        self, url: str, on_event: Optional[Callable] = None,
    ) -> ScenarioResult:
        """Test account deletion flow for obstruction patterns."""
        findings = []

        actions = [
            {
                "name": "find_delete",
                "instruction": (
                    "Navigate to account settings and look for an option to delete the account, "
                    "close the account, or deactivate. Describe where you found it "
                    "(or if you couldn't find it)."
                ),
            },
            {
                "name": "start_delete",
                "instruction": (
                    "Click the delete/close account option. Describe the process: "
                    "how many confirmations, what warnings are shown, is there emotional "
                    "language, do they require contacting support instead?"
                ),
            },
            {
                "name": "check_barriers",
                "instruction": (
                    "Check for barriers: do you need to call a phone number, send an email, "
                    "chat with support, or wait a cooling period? Note any alternative actions "
                    "being pushed (like 'deactivate instead' or 'take a break')."
                ),
            },
        ]

        if on_event:
            await on_event({"type": "step", "scenario": "account_deletion", "message": "Testing account deletion accessibility..."})

        step_results = await asyncio.to_thread(self._run_nova_session, url, actions)
        steps_completed = sum(1 for s in step_results if s["success"])

        for step in step_results:
            result_text = step["result"].lower()

            if step["name"] == "find_delete":
                if any(w in result_text for w in ["couldn't find", "unable", "no option", "not available"]):
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description="No visible account deletion option in settings",
                        severity="critical",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

            elif step["name"] == "check_barriers":
                if any(w in result_text for w in ["call", "phone", "contact support", "email support", "chat with"]):
                    findings.append(Finding(
                        pattern_type="obstruction",
                        description="Account deletion requires contacting support instead of self-service",
                        severity="high",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))
                if any(w in result_text for w in ["deactivate instead", "take a break", "pause"]):
                    findings.append(Finding(
                        pattern_type="misdirection",
                        description="Deletion flow pushes alternative actions like deactivation",
                        severity="medium",
                        screenshot_b64=step["screenshot_b64"],
                        element_text=step["result"],
                    ))

        return ScenarioResult(
            scenario="account_deletion",
            status="completed",
            findings=findings,
            steps_completed=steps_completed,
        )
