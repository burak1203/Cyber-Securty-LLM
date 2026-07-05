from pydantic import BaseModel, Field
from typing import Literal

class ThreatAnalysisResponse(BaseModel):
    """
    Enterprise data contract for the threat analysis returned from the LLM.
    The LLM cannot deviate from this schema, omit fields, or fabricate risk levels.
    """
    threat_vector: str = Field(
        ..., 
        description="Technical vector of the attack or anomaly (e.g., SQL Injection, Data Leakage)."
    )
    risk_level: Literal["Low", "Medium", "High", "Critical"] = Field(
        ..., 
        description="Strict risk level. Only these 4 words are accepted."
    )
    action_required: str = Field(
        ..., 
        description="A single-sentence, direct action the SOC analyst must take to secure the system."
    )