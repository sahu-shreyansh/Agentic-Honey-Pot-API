# Agentic Honey-Pot API

A secure, intelligent, and production-ready honeypot API designed to engage scammers, extract intelligence, and simulate human behavior to waste their time.

---

## 🚀 Deployment (Render)

This API is ready for immediate deployment on **Render**.

### Option 1: Zero-Config Deployment (Recommended)
1.  Push this code to a GitHub/GitLab repository.
2.  Log in to [Render.com](https://render.com).
3.  Click **New +** -> **Web Service**.
4.  Connect your repository.
5.  Render will automatically detect the configuration.
    *   **Runtime**: Python 3
    *   **Build Command**: `pip install -r requirements.txt`
    *   **Start Command**: `python main.py`
6.  Add your Environment Variables in the "Environment" tab:
    *   `HONEYPOT_API_KEY`: (Generate a secure key)
    *   `GEMINI_API_KEY`: (Your Google Gemini API Key)

### Option 2: Docker Deployment
If you prefer using Docker:
1.  Select **Docker** as the runtime when creating the Web Service.
2.  Render will automatically build using the `Dockerfile`.
3.  Add the same environment variables as above.

### Verification
Once deployed, your API will be available at `https://your-service-name.onrender.com`.
*   Swagger Docs: `https://your-service-name.onrender.com/docs`
*   Health Check: `https://your-service-name.onrender.com/health`

---

## 🛠 Local Development

### 1. Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
echo "HONEYPOT_API_KEY=demo-key" > .env
echo "GEMINI_API_KEY=your-gemini-key" >> .env
```

### 2. Run
```bash
python main.py
```
Server will start at `http://0.0.0.0:8080`.


---

## 🐳 Docker Support

Build and run locally with Docker:

```bash
# Build
docker build -t agentic-honeypot .

# Run
docker run -p 8080:8080 -e HONEYPOT_API_KEY=demo-key agentic-honeypot
```

---

## 🧩 Features

### 1. Intelligent Scam Detection
*   **Pattern Matching**: Detects UPIs, bank accounts, and phishing links.
*   **Behavioral Analysis**: Identifies urgency, authority impersonation, and fear induction.
*   **Multi-Factor Scoring**: Calculates a confidence score (0-1) for every message.

### 2. Adaptive Phase Logic
The bot transitions through phases to maximize engagement time:
1.  **TRUST**: Feigns compliance to lower scammer defenses.
2.  **CONFUSION**: Misunderstands instructions (e.g., confusing Apps with SMS).
3.  **EXTRACTION**: "Accidentally" offers wrong info, prompting the scammer to reveal their details.
4.  **EXIT**: Simulates technical failures (Battery low, Network error) to stall indefinitely.

### 3. Generative AI Responses
Uses **Google Gemini 1.5 Flash** to generate human-like, context-aware replies that are distinct every time. Falls back to a robust rule-based system if the AI is unavailable.

---

## 📄 API Reference

### POST `/agentic-honeypot`
Analyzes a message and returns a honeypot response.

**Headers**
- `x-api-key`: Your security key.

**Request Body**
```json
{
  "message": {
    "text": "Your account is blocked, verify now",
    "sender": "unknown"
  },
  "conversationHistory": [
    { "text": "Hello?", "sender": "scammer" }
  ],
  "metadata": {
    "channel": "whatsapp"
  }
}
```

**Response**
```json
{
  "scamDetected": true,
  "confidence": 0.95,
  "phase": "EXTRACTION",
  "agentReply": "Sir I am trying to open the link but it says 404 error.",
  "extractedIntelligence": {
    "phishingLinks": ["http://fake-bank.com"]
  }
}
```
