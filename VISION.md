# DarkShield - AI-Powered Dark Pattern Detection

> Nova Hackathon Submission | March 2026

## What It Does

DarkShield is an AI-powered auditing tool that automatically detects dark patterns in web interfaces. Give it a URL, and a Nova Act browser agent navigates the site like a real user -- attempting to cancel subscriptions, reject cookies, delete accounts, and complete checkouts. Every manipulative design pattern it finds gets classified, scored by severity, mapped to OECD guidelines, and paired with a specific remediation.

## The Problem

Dark patterns cost consumers an estimated $12B/year in unwanted purchases, subscriptions they can't cancel, and privacy they didn't mean to give away. The FTC and EU regulators are cracking down, but auditing is still manual -- compliance teams click through flows one by one. That doesn't scale.

## How It Works

```
User submits URL
    |
    v
Nova Act agent launches browser
    |
    v
Runs audit scenarios:
  - Cookie consent test
  - Subscription cancel test
  - Checkout flow test
  - Account deletion test
    |
    v
Each interaction captured:
  - Screenshots at decision points
  - DOM state snapshots
  - User journey recording
    |
    v
Nova 2 Lite classifies findings:
  - Pattern type (10 categories)
  - Severity (low/medium/high/critical)
  - OECD guideline reference
  - Specific remediation steps
    |
    v
Dashboard displays:
  - Severity heatmap
  - Pattern breakdown
  - Before/after remediation
  - Compliance score
```

## Dark Pattern Taxonomy (10 Categories)

| Pattern | Description | Severity Range |
|---------|-------------|---------------|
| Confirmshaming | Guilt-trip language on opt-out buttons | Medium - High |
| Misdirection | Visual tricks to draw attention away from preferred action | Medium - High |
| Roach Motel | Easy to get in, hard to get out | High - Critical |
| Forced Continuity | Auto-renewal without clear consent | High - Critical |
| Hidden Costs | Surprise fees revealed late in flow | Critical |
| Trick Questions | Confusing language/double negatives in consent | Medium - High |
| Disguised Ads | Ads that look like content or navigation | Low - Medium |
| Friend Spam | Unauthorized access to contacts | High |
| Privacy Zuckering | Misleading privacy controls | Medium - High |
| Bait and Switch | Advertised offer doesn't match reality | High - Critical |

## Tech Stack

- **Frontend**: React + Tailwind CSS + Vite
- **Backend**: Python FastAPI on AWS Lambda
- **Browser Agent**: Nova Act SDK
- **Classifier**: Nova 2 Lite (multimodal)
- **Storage**: S3 (screenshots/reports) + DynamoDB (audit history)
- **Deployment**: AWS CDK, CloudFront CDN

## Build Timeline

| Day | Focus | Deliverable |
|-----|-------|-------------|
| 1 | Nova Act SDK setup, basic browser automation | Agent can navigate and screenshot |
| 2 | Dark pattern detection pipeline, classification | Agent identifies patterns |
| 3 | React dashboard, report generation, end-to-end | Full audit flow works |
| 4 | Polish, demo recording, edge cases | Submission-ready |

## Demo Script

1. Open DarkShield dashboard
2. Paste a URL known for dark patterns
3. Watch the agent navigate in real-time (screen recording)
4. Show audit report: 3 critical, 5 high, 2 medium findings
5. Click into a finding: see screenshot, classification, OECD reference, and fix suggestion
6. Compare: before screenshot vs. remediation mockup

## Key Differentiators

- **Behavioral, not static**: Actually tries to cancel/checkout/delete, not just scanning HTML
- **OECD-mapped**: Every finding references specific regulatory guidelines
- **Actionable**: Each pattern comes with a specific remediation, not just a flag
- **Visual proof**: Screenshots at every decision point for compliance evidence
