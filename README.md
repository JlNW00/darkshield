# DarkShield

**AI-powered dark pattern detection and auditing tool.**

DarkShield uses Amazon Nova Act to autonomously navigate websites and Amazon Nova 2 Lite to classify manipulative UI patterns. Feed it any URL and it returns a detailed report of every dark pattern found, categorized by severity, with OECD regulatory references and remediation suggestions.

> Nova Hackathon 2026 Submission

## Quick Start

```bash
# 1. Clone
git clone https://github.com/JlNW00/darkshield.git
cd darkshield

# 2. Backend
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys (see below)
uvicorn app.main:app --reload

# 3. Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** -- enter a URL and hit Scan.

## API Keys You Need

| Key | Where to get it | What it does |
|-----|----------------|--------------|
| `NOVA_ACT_API_KEY` | [Amazon Nova Act](https://nova.amazon.com/) | Browser automation agent |
| `AWS_ACCESS_KEY_ID` | AWS IAM Console | Bedrock access for classifier |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM Console | Bedrock access for classifier |

Put them in `backend/.env`:

```
NOVA_ACT_API_KEY=your_key_here
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_key_here
AWS_REGION=us-east-1
```

## Architecture

```
User -> React Dashboard -> FastAPI Backend -> Nova Act Agent -> Target Website
                                           -> Nova 2 Lite Classifier (Bedrock)
                                           -> PDF Report Generator (WeasyPrint)
                              WebSocket <----- Real-time progress streaming
```

### Backend (`backend/`)
- **FastAPI** app with REST + WebSocket endpoints
- **Nova Act Agent** (`agents/browser_agent.py`) - Autonomous browser that runs 4 audit scenarios
- **Nova 2 Lite Classifier** (`agents/classifier.py`) - Multimodal AI classification via Bedrock
- **Storage** (`services/storage.py`) - Local file storage for screenshots, audits, reports
- **Report Generator** (`services/report_generator.py`) - PDF/HTML export with WeasyPrint

### Frontend (`frontend/`)
- **React + Vite + Tailwind** dashboard
- Real-time WebSocket feed showing agent actions live
- Severity heatmap, pattern detail cards, OECD references
- PDF report download

## Detection Scenarios

| Scenario | What it tests |
|----------|--------------|
| **Cookie Consent** | Asymmetric buttons, pre-checked boxes, hidden reject, cookie walls |
| **Subscription Cancel** | Hidden cancel, excessive steps, confirmshaming, retention dark patterns |
| **Checkout Flow** | Hidden costs, pre-selected add-ons, fake urgency/scarcity, trick questions |
| **Account Deletion** | Missing delete option, guilt-trip language, forced waiting, mandatory surveys |

## Dark Pattern Taxonomy (10 categories)

1. **Confirmshaming** - Guilt-trip language to shame users into compliance
2. **Misdirection** - Visual tricks to steer attention away from preferred choices
3. **Roach Motel** - Easy to get in, hard to get out
4. **Forced Continuity** - Charging after free trial without clear notice
5. **Hidden Costs** - Fees revealed only at checkout
6. **Trick Questions** - Confusing double-negatives and misleading checkboxes
7. **Disguised Ads** - Ads that look like content or navigation
8. **Friend Spam** - Harvesting contacts under false pretenses
9. **Privacy Zuckering** - Tricking users into sharing more data than intended
10. **Bait and Switch** - Advertising one thing, delivering another

Each finding includes OECD guideline references and applicable regulations (GDPR, FTC, DSA).

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/audit` | Start a new audit |
| `GET` | `/api/v1/audit/{id}` | Get audit results |
| `GET` | `/api/v1/audit/{id}/patterns` | Get detected patterns |
| `GET` | `/api/v1/audit/{id}/report` | Download PDF report |
| `GET` | `/api/v1/audits` | List all audits |
| `DELETE` | `/api/v1/audit/{id}` | Delete an audit |
| `GET` | `/api/v1/health` | Health check |
| `WS` | `/api/v1/ws/audit/{id}` | Real-time audit stream |

## Tech Stack

- **Browser Agent**: Amazon Nova Act SDK
- **Classifier**: Amazon Nova 2 Lite via Bedrock
- **Backend**: Python, FastAPI, WebSockets
- **Frontend**: React, Vite
- **PDF Export**: WeasyPrint
- **Storage**: Local filesystem (hackathon) / S3 + DynamoDB (production)

## License

MIT