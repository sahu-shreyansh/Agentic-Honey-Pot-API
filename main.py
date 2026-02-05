"""
Agentic Honey-Pot API - Production-Ready Scam Detection & Engagement System

This API implements an intelligent honeypot system that:
- Detects scam patterns and behavioral signals
- Extracts sensitive information mentions
- Generates contextual human-like responses to sustain engagement
- Tracks metrics for scam analysis
- Provides comprehensive intelligence extraction
"""
import os
import re
import time
import random
import logging
from contextlib import asynccontextmanager
from typing import List, Optional, Dict
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator


# --- CONFIGURATION ---
load_dotenv()

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- GEMINI SETUP ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = None

if GEMINI_API_KEY:
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("Gemini AI successfully configured")
    except ImportError:
        logger.error("google-genai library not found. Install it with: pip install google-genai")
else:
    logger.warning("GEMINI_API_KEY not found. Falling back to rule-based responses.")

# --- CONFIGURATION ---
# load_dotenv() called above to ensure env vars available for assignments below

API_KEY = os.getenv("HONEYPOT_API_KEY")
if not API_KEY:
    logger.warning("No HONEYPOT_API_KEY configured. Using demo-key - NOT for production!")
    API_KEY = "demo-key"

APP_NAME = "Agentic Honey-Pot API"
API_VERSION = "2.0.0"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8080))
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
MAX_HISTORY_LENGTH = 50
MIN_CONFIDENCE_THRESHOLD = 0.3

# --- MODELS ---
class Message(BaseModel):
    sender: str = "unknown"
    text: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class Metadata(BaseModel):
    channel: str = "unknown"
    language: str = "en"
    locale: str = "unknown"
    riskLevel: str = "medium"

class RequestBody(BaseModel):
    message: Message = Field(default_factory=Message)
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=Metadata)

class EngagementMetrics(BaseModel):
    """Metrics tracking scammer engagement."""
    engagementDurationSeconds: int = Field(default=0, ge=0)
    totalMessagesExchanged: int = Field(default=0, ge=0)
    averageResponseTime: float = Field(default=0.0, ge=0.0)
    sessionId: Optional[str] = None

class ExtractedIntelligence(BaseModel):
    """Extracted sensitive information from messages."""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    otherPatterns: Dict[str, List[str]] = Field(default_factory=dict)

class HoneypotResponse(BaseModel):
    """API response with comprehensive scam analysis."""
    status: str = Field(default="success")
    scamDetected: bool
    phase: str = Field(description="Current conversation phase (TRUST, CONFUSION, EXTRACTION, EXIT)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score of scam detection")
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    behavioralSignals: Dict[str, bool] = Field(default_factory=dict)
    instructionPattern: Optional[str] = Field(default=None)
    agentReply: str = Field(description="Generated response to continue engagement")
    agentNotes: str = Field(description="Internal analysis notes")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

# --- EXTRACTION PATTERNS ---
# Enhanced regex patterns with better accuracy
UPI_REGEX = r"\b[a-zA-Z0-9][a-zA-Z0-9.\-_]*@[a-zA-Z]{2,}\b"
BANK_REGEX = r"\b\d{9,18}\b"
URL_REGEX = r"https?://[^\s]+"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
PHONE_REGEX = r"\b(?:\+91|91|0)?[6-9]\d{9}\b"

BEHAVIORAL_KEYWORDS = {
    "urgency": [
        "immediately", "urgent", "now", "blocked", "fast", "quick", 
        "do it now", "asap", "right now", "straight away"
    ],
    "authorityImpersonation": [
        "bank", "support", "customer care", "police", "cbi", "rbi", "officer",
        "government", "official", "representative", "executive", "manager"
    ],
    "fearInduction": [
        "blocked", "suspended", "legal", "penalty", "arrest", "fine",
        "account closure", "action", "complaint", "notice", "violation"
    ],
    "socialEngineering": [
        "help", "support", "guide", "please", "need your", "can you",
        "do me a favor", "trusted", "secure"
    ],
    "technicalPretext": [
        "update", "software", "system", "security", "bug", "issue",
        "maintenance", "verification", "confirm"
    ]
}

INSTRUCTION_PATTERNS = {
    "ask_for_upi_id": ["upi id", "@", "vpa", "upi address", "send upi"],
    "ask_for_otp": ["otp", "one time password", "verification code"],
    "ask_for_link_click": ["click", "link", "url", "open", "visit", "download"],
    "ask_for_app_install": ["install", "download", "apk", "anydesk", "teamviewer", "app"],
    "ask_for_bank_details": ["account number", "ifsc", "bank details", "account info"],
    "ask_for_credentials": ["username", "email", "password", "login details"],
    "ask_for_cvv": ["cvv", "cvc", "security code", "card number"]
}

# --- COMPREHENSIVE SCAM TERMS ---
SCAM_TERMS = [
    "blocked", "suspended", "verify", "urgent", "immediate",
    "upi", "account", "refund", "claim", "winner",
    "click", "link", "update", "confirm", "password", "otp",
    "do it now", "why are you not responding", "fast", "asap",
    "bank", "verify identity", "pending", "pending approval",
    "transaction failed", "network issue", "settlement",
    "kyc", "aadhar", "pan", "secure", "official"
]

def extract_intelligence(text: str) -> dict:
    """
    Extract all sensitive information from text using multiple pattern matching.
    Returns a comprehensive dictionary of extracted data.
    """
    if not text or len(text.strip()) == 0:
        return {
            "upiIds": [], "bankAccounts": [], "phishingLinks": [],
            "emailAddresses": [], "phoneNumbers": [], "otherPatterns": {}
        }
    
    result = {
        "upiIds": list(set(re.findall(UPI_REGEX, text, re.IGNORECASE))),
        "bankAccounts": list(set(re.findall(BANK_REGEX, text))),
        "phishingLinks": list(set(re.findall(URL_REGEX, text))),
        "emailAddresses": list(set(re.findall(EMAIL_REGEX, text))),
        "phoneNumbers": list(set(re.findall(PHONE_REGEX, text))),
        "otherPatterns": {}
    }
    
    # Log extraction for analysis
    if any(result[k] for k in ["upiIds", "bankAccounts", "phishingLinks", "emailAddresses", "phoneNumbers"]):
        logger.info(f"Intelligence extracted: {result}")
    
    return result

def extract_behavioral_signals(text: str) -> dict:
    """
    Detect behavioral signals indicating scam attempt.
    Returns a dictionary of detected behavioral patterns.
    """
    if not text:
        return {}
    
    text_lower = text.lower()
    signals = {}
    
    for signal, keywords in BEHAVIORAL_KEYWORDS.items():
        signals[signal] = any(k in text_lower for k in keywords)
    
    return signals

def detect_instruction_pattern(text: str) -> Optional[str]:
    """
    Identify what the scammer is trying to extract.
    Returns the detected instruction pattern or None.
    """
    if not text:
        return None
    
    text_lower = text.lower()
    
    # Check for multiple matches and return the first (priority-ordered)
    for pattern, keywords in INSTRUCTION_PATTERNS.items():
        if any(k in text_lower for k in keywords) and len(text_lower.split()) > 3:
            return pattern
    
    return "general_instruction"

def merge_extracted(history_data: dict, current_data: dict) -> dict:
    """
    Merge extracted intelligence from conversation history with current message.
    Deduplicates entries while preserving order. Handles mixed list/dict types robustly.
    """
    merged = {}
    
    for k in set(history_data.keys()) | set(current_data.keys()):
        val1 = history_data.get(k)
        val2 = current_data.get(k)
        
        # Check if either value is a dict (implies dict merging strategy)
        if isinstance(val1, dict) or isinstance(val2, dict):
            d1 = val1 if isinstance(val1, dict) else {}
            d2 = val2 if isinstance(val2, dict) else {}
            merged[k] = {**d1, **d2}
            continue
            
        # Default/List merging strategy
        l1 = val1 if isinstance(val1, list) else []
        l2 = val2 if isinstance(val2, list) else []
        
        seen = set()
        result = []
        for item in (l1 + l2):
            if item not in seen:
                result.append(item)
                seen.add(item)
        merged[k] = result

    return merged

# --- AGENT RESPONSE LIBRARY ---
SAFE_FALLBACKS = {
    "TRUST": [
        "Sir I got this message now, please guide me what to do.",
        "Yes sir, I am listening, please tell me next step.",
        "Sir I understand, what should I do?"
    ],
    "CONFUSION": [
        "Sir this word you mentioned, where exactly should I type it?",
        "Sir I am confused, can you explain in simple words?",
        "Sir which application should I open for this?"
    ],
    "EXTRACTION": [
        "Sir can you share an example so I do not make mistake?",
        "Sir please guide slowly, I am new to this.",
        "Sir should I share now or later?"
    ],
    "EXIT": [
        "Sir network is little slow, I will try again shortly, thank you.",
        "Sir my battery is low, will contact you later.",
        "Sir someone is calling, will get back to you soon."
    ]
}

TRUST_PHASE_REPLIES = [
    "Yes sir, I am ready.",
    "Sir I trust you completely, please continue.",
    "I will help you sir, tell me what to do.",
    "Okay sir, I am listening carefully.",
    "Yes sir, I want to fix this issue."
]

CONFUSION_REPLIES = [
    "Sir I am getting confused, is this inside app or message?",
    "Sir you said fast, but I don't see where to do this.",
    "Sir please guide slowly, I don't want to make mistake.",
    "Which application sir? PhonePe or Google Pay?",
    "Can you show me step by step sir?"
]

EXTRACTION_REPLIES = [
    "Sir can you tell exact steps one by one?",
    "Sir should I open PhonePe first or messages?",
    "Sir is this UPI typed or scanned?",
    "Will it be secure sir?",
    "Should I do this right now?"
]

# Context-aware extraction replies
CONTEXT_EXTRACTION = {
    "ask_for_upi_id": [
        "Sir should I enter my UPI or your UPI ID?",
        "Should I send you my UPI sir?",
        "Where do I find my UPI ID?"
    ],
    "ask_for_otp": [
        "Sir I will not share OTP with anyone, is it safe?",
        "Should I really send you the code?",
        "Will bank officers ask me later about this?"
    ],
    "ask_for_link_click": [
        "Sir is this link safe? My phone gives warning.",
        "Can you send me official link from bank website?",
        "What will happen after I click?"
    ],
    "ask_for_bank_details": [
        "Why do you need my account details sir?",
        "Should I tell you my account number?",
        "Is bank asking for this?"
    ]
}

HUMAN_VARIANTS = [
    "where should I type this",
    "where do I put this",
    "how to enter this",
    "what do you mean by that",
    "can you repeat that",
    "my phone is slow"
]

DELAY_REPLIES = [
    "Sir I am outside now, will do in some time please wait",
    "Network is very slow sir, loading...",
    "One minute sir, finding my glasses",
    "Sir my phone battery is very low",
    "Someone just came home, will contact you soon"
]

# --- SCAM DETECTION & ANALYSIS ---
def is_scam(text: str) -> bool:
    """
    Detect if message contains common scam indicators.
    Uses multi-factor detection for higher accuracy.
    """
    if not text or len(text.strip()) < 3:
        return False
    
    text = text.lower()
    
    # Count matching terms (threshold-based)
    matches = sum(1 for term in SCAM_TERMS if term in text)
    
    return matches >= 1  # At least one scam indicator

def detect_repetition(history: List[Message], text: str, threshold: int = 3) -> bool:
    """
    Detect if the same instruction is being repeated.
    Indicates scammer frustration or victim hesitation.
    """
    if not text or len(history) == 0:
        return False
    
    text_lower = text.lower().strip()
    
    # Check for exact or near-exact repetition
    repetition_count = sum(
        1 for msg in history[-threshold:]
        if text_lower in (msg.text or "").lower()
    )
    
    return repetition_count >= 2

def decide_phase(history_len: int, extracted: dict, behavioral: dict, instruction: Optional[str]) -> str:
    """
    Determine conversation phase based on escalation logic.
    """

    # 1️⃣ EXIT conditions (highest priority)
    if behavioral.get("repetition") and history_len >= 4:
        return "EXIT"

    if behavioral.get("urgency") and history_len >= 4:
        return "EXIT"

    if history_len >= 10:
        return "EXIT"

    # 2️⃣ EXTRACTION phase (instruction or sensitive ask detected)
    if instruction and instruction != "general_instruction":
        return "EXTRACTION"

    extraction_targets = (
        extracted.get("upiIds", []) +
        extracted.get("bankAccounts", []) +
        extracted.get("emailAddresses", [])
    )
    if extraction_targets:
        return "EXTRACTION"

    if behavioral.get("urgency") or behavioral.get("fearInduction"):
        return "EXTRACTION" if history_len >= 2 else "CONFUSION"

    # 3️⃣ TRUST phase (ONLY very first interaction)
    if history_len == 0:
        return "TRUST"

    # 4️⃣ Default
    return "CONFUSION"

def calculate_confidence(extracted: dict, behavioral: dict, history_len: int, instruction: Optional[str]) -> float:
    """
    Calculate confidence score (0.0-1.0) that message is a scam attempt.
    Uses multi-factor scoring.
    """
    score = 0.5
    
    # Factor 1: Extracted sensitive info
    extracted_count = sum(len(v) for v in extracted.values())
    if extracted_count > 0:
        score += min(0.15 * extracted_count, 0.2)
    
    # Factor 2: Behavioral signals
    if behavioral.get("urgency"):
        score += 0.15
    if behavioral.get("fearInduction"):
        score += 0.1
    if behavioral.get("authorityImpersonation"):
        score += 0.1
    if behavioral.get("technicalPretext"):
        score += 0.05
    
    # Factor 3: Instruction pattern
    if instruction and instruction != "general_instruction":
        score += 0.1
    
    # Factor 4: Conversation depth
    if history_len >= 5:
        score += 0.05
    
    # Ensure score is valid probability
    return max(MIN_CONFIDENCE_THRESHOLD, min(score, 0.99))

def generate_agent_reply(phase: str, extracted: dict, instruction: Optional[str], history_len: int, history_text: List[str] = []) -> str:
    """
    Generate contextually appropriate response using Gemini AI or fallback rules.
    """
    # 1. Try Gemini AI Generation
    if client:
        try:
            prompt = f"""
            You are playing the role of a naive, non-technical, slightly older potential victim in a scam conversation.
            Your goal is to waste the scammer's time without exposing that you are a bot.
            NEVER admit you are an AI. NEVER refuse to help directly, but always have a problem doing it.

            Context:
            - Current Phase: {phase} (TRUST=Agreement, CONFUSION=Don't understand technical terms, EXTRACTION=Asked for info, EXIT=Stalling)
            - Scammer Instruction: {instruction or "General conversation"}
            - What we know about them: {extracted}
            - Recent Conversation: {history_text[-5:] if history_text else "No history"}

            Guidelines:
            - If Phase is TRUST: Be agreeable, polite, eagerness to resolve the issue.
            - If Phase is CONFUSION: Misunderstand technical terms (e.g., confuse 'browser' with 'gallery', 'UPI' with 'message').
            - If Phase is EXTRACTION: Act willing but incompetent. Fumble the details. Ask if you should do X or Y (both wrong).
            - If Phase is EXIT: Stall. Battery low, network slow, someone at door.

            Respond with a single short message (under 20 words). Act natural, use slightly broken grammar or older person mannerisms.
            """
            
            response = client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompt
            )
            
            if response.text:
                text = response.text.replace('"', '').strip()
                return text[:80]
        except Exception as e:
            logger.error(f"Gemini generation failed: {e}")

    # 2. Fallback to Rule-Based System
    # Try context-aware response first
    if phase == "EXTRACTION" and instruction in CONTEXT_EXTRACTION:
        candidates = CONTEXT_EXTRACTION[instruction]
        reply = random.choice(candidates)
    elif phase == "CONFUSION":
        reply = random.choice(CONFUSION_REPLIES)
    elif phase == "EXTRACTION":
        reply = random.choice(EXTRACTION_REPLIES)
    elif phase == "TRUST":
        reply = random.choice(TRUST_PHASE_REPLIES)
    else:
        reply = random.choice(SAFE_FALLBACKS.get(phase, SAFE_FALLBACKS["CONFUSION"]))
    
    # Add entropy - occasionally ask for clarification
    if random.random() < 0.15 and history_len >= 2:
        reply = random.choice(HUMAN_VARIANTS)
    
    # Add delay response occasionally
    if random.random() < 0.1 and phase == "EXIT":
        reply = random.choice(DELAY_REPLIES)
    
    return reply.strip()

# --- API APPLICATION ---
# --- STARTUP/SHUTDOWN EVENTS ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application on startup and cleanup on shutdown."""
    logger.info(f"Starting {APP_NAME} v{API_VERSION}")
    if not API_KEY or API_KEY == "demo-key":
        logger.warning("⚠️  Running with demo API key - NOT FOR PRODUCTION")
    yield
    logger.info(f"Shutting down {APP_NAME}")

# --- API APPLICATION ---
app = FastAPI(
    title=APP_NAME,
    version=API_VERSION,
    description="Production-ready Agentic Honey-Pot API for scam detection and engagement",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# --- ROUTE HANDLERS ---
@app.get("/", tags=["Health"])
@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": API_VERSION,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/status", tags=["Health"])
def status():
    """Detailed status endpoint."""
    return {
        "service": APP_NAME,
        "version": API_VERSION,
        "status": "operational",
        "debug_mode": DEBUG,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/dashboard", tags=["Visualization"])
def dashboard():
    """Simple HTML dashboard to visualize honeypot metrics (Bonus Feature)."""
    from fastapi.responses import HTMLResponse
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{APP_NAME} Dashboard</title>
        <style>
            body {{ font-family: sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f0f2f5; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            h1 {{ color: #1a73e8; }}
            .status {{ font-weight: bold; color: green; }}
        </style>
    </head>
    <body>
        <h1>🛡️ {APP_NAME} Live Monitor</h1>
        <div class="card">
            <h2>System Status</h2>
            <p>Version: <strong>{API_VERSION}</strong></p>
            <p>Status: <span class="status">OPERATIONAL</span></p>
            <p>Host: {HOST}:{PORT}</p>
        </div>
        <div class="card">
            <h2>Active Defenses</h2>
            <ul>
                <li>✅ Scam Pattern Recognition</li>
                <li>✅ Behavioral Analysis Engine</li>
                <li>✅ Generative AI Response System</li>
                <li>✅ Automatic Intelligence Extraction</li>
            </ul>
        </div>
        <p><em>Use /docs to interact with the API directly.</em></p>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/agentic-honeypot", response_model=HoneypotResponse, tags=["Honeypot"])
async def agentic_honeypot(body: RequestBody, x_api_key: str = Header(None)):
    """
    Main honeypot endpoint.
    
    Analyzes incoming message, detects scam indicators, and generates contextual response.
    
    Authentication: Requires X-API-Key header
    """
    start_time = time.time()
    
    try:
        # --- 1. AUTHENTICATION ---
        if not API_KEY or x_api_key != API_KEY:
            logger.warning(f"Unauthorized API key attempt")
            raise HTTPException(status_code=401, detail="Invalid API Key")

        # --- 2. INPUT VALIDATION & SANITIZATION ---
        last_message = (body.message.text or "").strip()
        history = body.conversationHistory or []
        history_len = len(history)
        
        if not last_message:
            logger.warning("Empty message received")
            raise HTTPException(status_code=400, detail="Message cannot be empty")

        logger.info(f"Processing message from {body.message.sender} | History: {history_len}")

        # --- 3. INTELLIGENCE EXTRACTION (ACCUMULATED) ---
        # Extract from current message
        current_extracted = extract_intelligence(last_message)
        
        # Accumulate from history
        historical_extracted = {}
        for msg in history:
            old_extracted = extract_intelligence(msg.text or "")
            for k, v in old_extracted.items():
                if k not in historical_extracted:
                    historical_extracted[k] = []
                historical_extracted[k].extend(v)

        # Merge current with historical
        extracted_dict = merge_extracted(historical_extracted, current_extracted)
        
        # --- 4. BEHAVIORAL SIGNAL DETECTION ---
        behavioral = extract_behavioral_signals(last_message)
        behavioral["repetition"] = detect_repetition(history, last_message)
        
        # --- 5. INSTRUCTION PATTERN DETECTION ---
        instruction = detect_instruction_pattern(last_message)
        
        # --- 6. SCAM DETECTION ---
        scam_detected = is_scam(last_message)
        logger.info(f"Scam detected: {scam_detected} | Instruction: {instruction}")
        
        # --- 7. CONVERSATION PHASE DETERMINATION ---
        phase = decide_phase(history_len, extracted_dict, behavioral, instruction)
        logger.info(f"Phase determined: {phase}")
        
        # --- 8. RESPONSE GENERATION ---
        history_text = [m.text for m in history]
        agent_reply = generate_agent_reply(phase, extracted_dict, instruction, history_len, history_text)
        
        # Final validation
        if not agent_reply or len(agent_reply) < 3:
            agent_reply = random.choice(SAFE_FALLBACKS[phase])
        
        # --- 9. CONFIDENCE CALCULATION ---
        confidence = calculate_confidence(extracted_dict, behavioral, history_len, instruction)
        
        # --- 10. ENGAGEMENT METRICS ---
        total_messages = history_len + 1
        est_duration = min(3600, total_messages * 45)  # 45 seconds average per message
        processing_time = time.time() - start_time
        
        # --- 11. CONSTRUCT RESPONSE ---
        response = HoneypotResponse(
            status="success",
            scamDetected=scam_detected,
            phase=phase,
            confidence=confidence,
            behavioralSignals=behavioral,
            instructionPattern=instruction,
            engagementMetrics=EngagementMetrics(
                totalMessagesExchanged=total_messages,
                engagementDurationSeconds=est_duration,
                averageResponseTime=est_duration / total_messages if total_messages > 0 else 0,
                sessionId=body.metadata.channel if body.metadata else None
            ),
            extractedIntelligence=ExtractedIntelligence(
                bankAccounts=extracted_dict.get("bankAccounts", []),
                upiIds=extracted_dict.get("upiIds", []),
                phishingLinks=extracted_dict.get("phishingLinks", []),
                emailAddresses=extracted_dict.get("emailAddresses", []),
                phoneNumbers=extracted_dict.get("phoneNumbers", []),
                otherPatterns=extracted_dict.get("otherPatterns", {})
            ),
            agentReply=agent_reply,
            agentNotes=f"Phase:{phase} | Scam:{scam_detected} | Confidence:{confidence:.2f} | ProcessTime:{processing_time:.3f}s"
        )
        
        logger.info(f"Response generated successfully | Confidence: {confidence:.2f}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CRITICAL ERROR: {e}", exc_info=True)
        return HoneypotResponse(
            status="error",
            scamDetected=True,
            phase="CONFUSION",
            confidence=0.5,
            behavioralSignals={
                "urgency": False,
                "authorityImpersonation": False,
                "fearInduction": False,
                "socialEngineering": False,
                "technicalPretext": False,
                "repetition": False
            },
            instructionPattern="general_instruction",
            engagementMetrics=EngagementMetrics(
                totalMessagesExchanged=1,
                engagementDurationSeconds=0,
                averageResponseTime=0.0,
                sessionId=None
            ),
            extractedIntelligence=ExtractedIntelligence(
                bankAccounts=[],
                upiIds=[],
                phishingLinks=[],
                emailAddresses=[],
                phoneNumbers=[],
                otherPatterns={}
            ),
            agentReply=random.choice(CONFUSION_REPLIES),
            agentNotes="Emergency fallback"
        )

# --- STARTUP/SHUTDOWN EVENTS ---
# --- EVENTS HANDLED VIA LIFESPAN ---

# --- MAIN ENTRY POINT ---
if __name__ == "__main__":
    import uvicorn
    # Make the URL clickable for Windows users
    logger.info(f"Documentation available at: http://{HOST}:{PORT}/docs")
    uvicorn.run(app, host=HOST, port=PORT)
