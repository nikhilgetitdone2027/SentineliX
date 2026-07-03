# -*- coding: utf-8 -*-
"""
Pydantic schemas for AI Behaviour Engine request and response validation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from backend.feature_engine.models import BehaviouralFeatureVector

class TrainResponse(BaseModel):
    """
    Response schema for model training operations.
    """
    success: bool = Field(..., description="Whether training succeeded")
    message: str = Field(..., description="Detailed training message")
    total_trained: int = Field(..., description="Number of feature vectors used for training")
    model_type: str = Field(..., description="Type of primary model trained (e.g., Isolation Forest)")

class PredictRequest(BaseModel):
    """
    Request schema for predicting a single flow's anomaly status.
    """
    feature_vector: BehaviouralFeatureVector = Field(..., description="Flow behavioural feature vector to predict")

class PredictResponse(BaseModel):
    """
    Response schema for a single flow prediction.
    """
    flow_id: str = Field(..., description="Unique flow identifier")
    prediction: str = Field(..., description="Status ('Normal' or 'Anomaly')")
    anomaly_score: float = Field(..., description="Normalized machine learning model anomaly score [0, 1]")
    risk_score: float = Field(..., description="Combined risk score [0, 100]")
    confidence: float = Field(..., description="AI confidence score [0, 100] as percentage")
    top_reasons: List[str] = Field(default_factory=list, description="Top contributing features or risk indicators explaining the decision")
    risk_level: str = Field(..., description="Risk level (LOW, MEDIUM, HIGH, CRITICAL)")

class AnalyzeResponse(BaseModel):
    """
    Response schema for analyzing all extracted flows.
    """
    success: bool = Field(..., description="Whether the analysis succeeded")
    total_analyzed: int = Field(..., description="Total number of flows analyzed")
    predictions: List[PredictResponse] = Field(..., description="Individual flow prediction results")

class StatisticsResponse(BaseModel):
    """
    Response schema for behavior AI analytics statistics.
    """
    total_analyzed: int = Field(..., description="Total analyzed flows")
    normal_count: int = Field(..., description="Total normal flows")
    anomaly_count: int = Field(..., description="Total anomalous flows")
    average_risk_score: float = Field(..., description="Average risk score across all flows")
    highest_risk_score: float = Field(..., description="Highest individual risk score found")
    protocol_distribution: Dict[str, int] = Field(..., description="Flow count per protocol")
