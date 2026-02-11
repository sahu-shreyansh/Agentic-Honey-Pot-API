
import os
from dotenv import load_dotenv

load_dotenv()

# --- API CONFIGURATION ---
API_KEY = os.getenv("HONEYPOT_API_KEY", "demo-key")
APP_NAME = "Agentic Honey-Pot API"
API_VERSION = "2.0.0"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8080))
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# --- GEMINI CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = "models/gemini-flash-latest"

# --- SCAM DETECTION CONFIGURATION ---
MAX_HISTORY_LENGTH = 50
MIN_CONFIDENCE_THRESHOLD = 0.3

# --- FALLBACK RESPONSES ---
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
