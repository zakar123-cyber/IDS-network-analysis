"""
============================================
BLACK WALL — Pydantic Schemas
============================================
Request/response validation models for the API layer.
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "operational"
    service: str = "BLACK WALL"


class AnalysisSummary(BaseModel):
    total_detections: int = 0
    threat_level: str = "Vert"
    threat_label: str = "✅ Aucune menace détectée"
    average_risk_score: float = 0.0
    saved_to_database: int | None = None
    database_warning: str | None = None
    ai_analysis_summary: str | None = None


class DetectionItem(BaseModel):
    timestamp: str = ""
    detection_method: str = ""
    detection_detail: str = ""
    attack_type: str = ""
    attack_icon: str = "⚠️"
    risk_score: int = 0
    ml_confidence: float | None = None
    source_ip: str = "Inconnue"
    target: str = "Serveur"
    explication_vulgarisee: str = ""
    recommendation: str = ""
    agent_name: str = "System"
    raw_log: str = ""


class AnalysisResponse(BaseModel):
    summary: AnalysisSummary
    all_detections: list[DetectionItem] = []


class SaveDetectionsRequest(BaseModel):
    detections: list[dict] = Field(default_factory=list)
