
from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field
from utils.phases import Phase

class Message(BaseModel):
    sender: str = Field(default="unknown")
    text: str = Field(...)
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class Metadata(BaseModel):
    channel: str = Field(default="unknown")
    language: str = Field(default="en")
    locale: str = Field(default="unknown")
    riskLevel: str = Field(default="medium")

class RequestBody(BaseModel):
    message: Message
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
    phase: Phase = Field(description="Current conversation phase (TRUST, CONFUSION, EXTRACTION, EXIT)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score of scam detection")
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    behavioralSignals: Dict[str, bool] = Field(default_factory=dict)
    instructionPattern: Optional[str] = Field(default=None)
    agentReply: str = Field(description="Generated response to continue engagement")
    agentNotes: str = Field(description="Internal analysis notes")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
