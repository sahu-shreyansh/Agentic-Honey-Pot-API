
from typing import List, Optional, Dict
from models.schemas import Message
from utils.phases import Phase
from config import MIN_CONFIDENCE_THRESHOLD

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

SCAM_TERMS = [
    "blocked", "suspended", "verify", "urgent", "immediate",
    "upi", "account", "refund", "claim", "winner",
    "click", "link", "update", "confirm", "password", "otp",
    "do it now", "why are you not responding", "fast", "asap",
    "bank", "verify identity", "pending", "pending approval",
    "transaction failed", "network issue", "settlement",
    "kyc", "aadhar", "pan", "secure", "official"
]

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

def decide_phase(history_len: int, extracted: dict, behavioral: dict, instruction: Optional[str]) -> Phase:
    """
    Determine conversation phase based on escalation logic.
    """

    # 1. EXIT conditions (highest priority)
    if behavioral.get("repetition") and history_len >= 4:
        return Phase.EXIT

    if behavioral.get("urgency") and history_len >= 4:
        return Phase.EXIT

    if history_len >= 10:
        return Phase.EXIT

    # 2. EXTRACTION phase (instruction or sensitive ask detected)
    if instruction and instruction != "general_instruction":
        return Phase.EXTRACTION

    extraction_targets = (
        extracted.get("upiIds", []) +
        extracted.get("bankAccounts", []) +
        extracted.get("emailAddresses", [])
    )
    if extraction_targets:
        return Phase.EXTRACTION

    if behavioral.get("urgency") or behavioral.get("fearInduction"):
        return Phase.EXTRACTION if history_len >= 2 else Phase.CONFUSION

    # 3. TRUST phase (ONLY very first interaction)
    if history_len == 0:
        return Phase.TRUST

    # 4. Default
    return Phase.CONFUSION

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
