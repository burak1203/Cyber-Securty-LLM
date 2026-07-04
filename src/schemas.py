from pydantic import BaseModel, Field
from typing import Literal

class ThreatAnalysisResponse(BaseModel):
    """
    LLM'den dönen tehdit analizinin kurumsal veri sözleşmesi (Data Contract).
    LLM bu şema dışına çıkamaz, eksik alan gönderemez veya farklı bir risk seviyesi uyduramaz.
    """
    threat_vector: str = Field(
        ..., 
        description="Saldırının veya anomalinin teknik açıklamasını içeren vektör (örn: SQL Injection, Veri Sızıntısı)."
    )
    risk_level: Literal["Düşük", "Orta", "Yüksek", "Kritik"] = Field(
        ..., 
        description="Kesin ve katı bir risk seviyesi. Bu 4 kelime dışında hiçbir şey kabul edilmez."
    )
    action_required: str = Field(
        ..., 
        description="SOC analistinin sistemi korumak için alması gereken tek cümlelik, doğrudan aksiyon."
    )