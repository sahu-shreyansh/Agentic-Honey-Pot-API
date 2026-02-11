
import os
import logging
from typing import Optional, List
from config import GEMINI_API_KEY, GEMINI_MODEL

logger = logging.getLogger("gemini_service")

class GeminiService:
    def __init__(self):
        self.client = None
        self.is_active = False
        
        if GEMINI_API_KEY:
            try:
                from google import genai
                self.client = genai.Client(api_key=GEMINI_API_KEY)
                self.is_active = True
                logger.info("Gemini client initialized successfully")
            except ImportError:
                logger.error("google-genai package not installed. Gemini disabled.")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
        else:
            logger.warning("GEMINI_API_KEY not found. Gemini disabled.")

    def generate_response(self, phase: str, instruction: str, extracted: dict, history_text: List[str]) -> Optional[str]:
        """
        Generate a human-like response using Gemini.
        Returns None if generation fails or service is inactive.
        """
        if not self.is_active or not self.client:
            return None

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
            
            # Using the v1alpha or similar API from google-genai
            # The user code used: client.models.generate_content(model="...", contents=prompt)
            # We will follow that pattern.
            
            response = self.client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )
            
            if response and response.text:
                text = response.text.replace('"', '').strip()
                # Clean up any potential prefixes like "Response:"
                if text.lower().startswith("response:"):
                    text = text[9:].strip()
                return text[:150] # Limit length to prevent rambling
            
            return None

        except Exception as e:
            logger.error(f"Gemini generation error with model {GEMINI_MODEL}: {e}")
            return None
