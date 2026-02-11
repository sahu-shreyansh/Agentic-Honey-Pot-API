
import time
import random
import logging
from typing import List, Optional
from fastapi import APIRouter, Header, HTTPException, Depends
from models.schemas import (
    RequestBody, HoneypotResponse, EngagementMetrics, ExtractedIntelligence,
    Message
)
from core.security import verify_api_key
from services.intelligence_extractor import extract_intelligence, merge_extracted
from services.scam_detector import (
    is_scam, extract_behavioral_signals, detect_repetition, 
    detect_instruction_pattern, decide_phase, calculate_confidence,
    Phase
)
from services.gemini_service import GeminiService
from config import (
    SAFE_FALLBACKS, TRUST_PHASE_REPLIES, CONFUSION_REPLIES, 
    EXTRACTION_REPLIES, CONTEXT_EXTRACTION, HUMAN_VARIANTS, 
    DELAY_REPLIES, MIN_CONFIDENCE_THRESHOLD
)

router = APIRouter()
logger = logging.getLogger("api.honeypot")

# Initialize Gemini Service once
gemini_service = GeminiService()

@router.post("/agentic-honeypot", response_model=HoneypotResponse, tags=["Honeypot"])
async def agentic_honeypot(
    body: RequestBody, 
    x_api_key: str = Depends(verify_api_key)
):
    """
    Main honeypot endpoint.
    Analyzes incoming message, detects scam indicators, and generates contextual response.
    """
    start_time = time.time()
    
    try:
        # --- INPUT VALIDATION & SANITIZATION ---
        last_message = str(body.message.text).strip()
        history = body.conversationHistory or []
        history_len = len(history)
        
        if not last_message:
            logger.warning("Empty message received")
            raise HTTPException(status_code=400, detail="Message cannot be empty")

        logger.info(f"Processing message from {body.message.sender} | History: {history_len}")

        # --- INTELLIGENCE EXTRACTION (ACCUMULATED) ---
        current_extracted = extract_intelligence(last_message)
        
        # Accumulate from history
        historical_extracted = {}
        for msg in history:
            text_content = msg.text if isinstance(msg, Message) else str(msg.get("text", ""))
            old_extracted = extract_intelligence(text_content)
            for k, v in old_extracted.items():
                if k not in historical_extracted:
                    historical_extracted[k] = []
                historical_extracted[k].extend(v)

        # Merge current with historical
        extracted_dict = merge_extracted(historical_extracted, current_extracted)
        
        # --- BEHAVIORAL SIGNAL DETECTION ---
        behavioral = extract_behavioral_signals(last_message)
        behavioral["repetition"] = detect_repetition(history, last_message)
        
        # --- INSTRUCTION PATTERN DETECTION ---
        instruction = detect_instruction_pattern(last_message)
        
        # --- SCAM DETECTION ---
        scam_detected = is_scam(last_message)
        
        # --- CONVERSATION PHASE DETERMINATION ---
        phase = decide_phase(history_len, extracted_dict, behavioral, instruction)
        logger.info(f"Phase determined: {phase}")
        
        # --- RESPONSE GENERATION ---
        history_text = [
            m.text if isinstance(m, Message) else str(m.get("text", "")) 
            for m in history
        ]
        
        # 1. Try Gemini
        agent_reply = gemini_service.generate_response(
            phase.value, instruction, extracted_dict, history_text
        )
        
        # 2. Fallback if Gemini fails or is disabled
        if not agent_reply:
            logger.info("Using fallback response logic")
            if phase == Phase.EXTRACTION and instruction in CONTEXT_EXTRACTION:
                candidates = CONTEXT_EXTRACTION[instruction]
                agent_reply = random.choice(candidates)
            elif phase == Phase.CONFUSION:
                agent_reply = random.choice(CONFUSION_REPLIES)
            elif phase == Phase.EXTRACTION:
                agent_reply = random.choice(EXTRACTION_REPLIES)
            elif phase == Phase.TRUST:
                agent_reply = random.choice(TRUST_PHASE_REPLIES)
            else:
                # Default fallback based on phase
                fallback_list = SAFE_FALLBACKS.get(phase.value, SAFE_FALLBACKS["CONFUSION"])
                agent_reply = random.choice(fallback_list)
            
            # Add entropy - occasionally ask for clarification
            if random.random() < 0.15 and history_len >= 2:
                agent_reply = random.choice(HUMAN_VARIANTS)
            
            # Add delay response occasionally for EXIT phase
            if random.random() < 0.1 and phase == Phase.EXIT:
                agent_reply = random.choice(DELAY_REPLIES)
        
        # Final safety check
        if not agent_reply or len(agent_reply) < 2:
             agent_reply = "Sir I am confused, can you explain?"

        # --- CONFIDENCE CALCULATION ---
        confidence = calculate_confidence(extracted_dict, behavioral, history_len, instruction)
        
        # --- ENGAGEMENT METRICS ---
        total_messages = history_len + 1
        est_duration = min(3600, total_messages * 45)  # 45 seconds average per message
        processing_time = time.time() - start_time
        
        # --- CONSTRUCT RESPONSE ---
        return HoneypotResponse(
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
                sessionId=body.metadata.channel
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
            agentNotes=f"Phase:{phase.value} | Scam:{scam_detected} | Confidence:{confidence:.2f} | ProcessTime:{processing_time:.3f}s"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CRITICAL ERROR: {e}", exc_info=True)
        # Graceful Failure Mode
        return HoneypotResponse(
            status="error",
            scamDetected=True,
            phase=Phase.CONFUSION,
            confidence=0.5,
            behavioralSignals={},
            instructionPattern="general_instruction",
            engagementMetrics=EngagementMetrics(),
            extractedIntelligence=ExtractedIntelligence(),
            agentReply=random.choice(CONFUSION_REPLIES),
            agentNotes="Emergency fallback due to internal error"
        )
