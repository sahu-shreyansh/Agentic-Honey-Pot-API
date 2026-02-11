
import re
import logging
from typing import Dict, List, Any

# Enhanced regex patterns with better accuracy
UPI_REGEX = r"\b[a-zA-Z0-9][a-zA-Z0-9.\-_]*@[a-zA-Z]{2,}\b"
BANK_REGEX = r"\b\d{9,18}\b"
URL_REGEX = r"https?://[^\s]+"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
PHONE_REGEX = r"\b(?:\+91|91|0)?[6-9]\d{9}\b"

logger = logging.getLogger("intelligence_extractor")

def extract_intelligence(text: str) -> Dict[str, Any]:
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
    
    # Log extraction if anything found
    if any(result[k] for k in ["upiIds", "bankAccounts", "phishingLinks", "emailAddresses", "phoneNumbers"]):
        logger.info(f"Intelligence extracted: {result}")
    
    return result

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
