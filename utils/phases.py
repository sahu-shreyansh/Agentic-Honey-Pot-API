
from enum import Enum

class Phase(str, Enum):
    TRUST = "TRUST"
    CONFUSION = "CONFUSION"
    EXTRACTION = "EXTRACTION"
    EXIT = "EXIT"
