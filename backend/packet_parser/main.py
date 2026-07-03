# -*- coding: utf-8 -*-
"""
Main entry point for the FastAPI packet parser service.
"""

# Monkeypatch Scapy's Linux rtnetlink IPv6 routing table loader before other imports
try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False
except Exception:
    pass

try:
    import scapy.arch
    scapy.arch.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

try:
    import scapy.arch.linux.rtnetlink
    scapy.arch.linux.rtnetlink.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

try:
    import scapy.route6
    scapy.route6.read_routes6 = lambda *args, **kwargs: []
except Exception:
    pass

import os
import shutil
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List

from .schemas import UploadResponse, PacketSchema, StatisticsResponse
from .service import PacketParserService

app = FastAPI(
    title="SentinelX Network Packet Parser API",
    description="Microservice for parsing network PCAP captures and exposing parsed telemetry.",
    version="2.0.0"
)

# Enable CORS for clean cross-service calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = PacketParserService()

@app.get("/health", tags=["Monitoring"])
def health_check():
    """
    Standard microservice health probe.
    """
    return {
        "status": "ONLINE",
        "service": "packet_parser_microservice",
        "stored_packets_count": len(service.packets)
    }

@app.post("/packet-parser/upload", response_model=UploadResponse, tags=["Packet Operations"])
async def upload_pcap(file: UploadFile = File(...)):
    """
    Accepts a PCAP file, parses its packet layers using Scapy, stores the parsed records
    in memory, and returns protocol distributions and stream statistics.
    """
    # Validate file extension
    filename = file.filename or "capture.pcap"
    if not (filename.endswith(".pcap") or filename.endswith(".pcapng") or filename.endswith(".cap")):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a standard PCAP or PCAPNG capture.")

    # Save to a temporary file on disk for Scapy to read streamingly
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"sentinelx_{os.urandom(8).hex()}_{filename}")

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write uploaded file to temporary disk buffer: {exc}")

    try:
        # Parse and store the packets
        total_packets, protocol_dist, basic_stats = service.add_packets_from_pcap(temp_path)
        
        return UploadResponse(
            success=True,
            filename=filename,
            total_packets=total_packets,
            protocol_distribution=protocol_dist,
            basic_statistics=basic_stats
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DPI Engine failed to process PCAP: {exc}")
    finally:
        # Cleanup temporary file from disk immediately
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

@app.get("/packet-parser/packets", response_model=List[PacketSchema], tags=["Packet Operations"])
def get_packets():
    """
    Exposes all parsed packet records stored in the in-memory database.
    """
    try:
        raw_packets = service.get_all_packets()
        # Convert domain objects to dictionaries conforming to PacketSchema
        return [p.to_dict() for p in raw_packets]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch parsed packets list: {exc}")

@app.get("/packet-parser/statistics", response_model=StatisticsResponse, tags=["Telemetry Analytics"])
def get_statistics():
    """
    Retrieves full packet telemetry analytics, including transport protocols, top DNS/HTTP,
    and top source/destination IPs.
    """
    try:
        stats = service.get_statistics()
        return StatisticsResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to calculate telemetry statistics: {exc}")

@app.post("/packet-parser/clear", tags=["Maintenance"])
def clear_packets():
    """
    Utility endpoint to clear stored packets from the in-memory database.
    """
    service.clear_packets()
    return {"status": "cleared", "message": "In-memory packet cache flushed successfully."}

# ============================================================================
# Flow Reconstruction Engine Endpoints
# ============================================================================

from backend.flow_engine.schemas import FlowBuildResponse, FlowSchema, FlowStatisticsResponse
from backend.flow_engine.service import FlowEngineService

flow_service = FlowEngineService()

@app.post("/flow/build", response_model=FlowBuildResponse, tags=["Flow Engine"])
def build_flows(idle_timeout: float = 60.0):
    """
    Reconstructs bidirectional network flows from the currently parsed packets in memory.
    """
    try:
        total_flows, stats = flow_service.build_flows(idle_timeout_seconds=idle_timeout)
        return FlowBuildResponse(
            success=True,
            total_flows=total_flows,
            summary_statistics=stats
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to reconstruct network flows: {exc}")

@app.get("/flow/list", response_model=List[FlowSchema], tags=["Flow Engine"])
def list_flows():
    """
    Returns the list of all reconstructed bidirectional network flows.
    """
    try:
        flows = flow_service.get_all_flows()
        return [f.to_dict() for f in flows]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve flow list: {exc}")

@app.get("/flow/statistics", response_model=FlowStatisticsResponse, tags=["Flow Engine"])
def get_flow_statistics():
    """
    Computes and retrieves analytical statistics over all reconstructed network flows.
    """
    try:
        stats = flow_service.get_statistics()
        return FlowStatisticsResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to calculate flow statistics: {exc}")


# ============================================================================
# Feature Extraction Engine Endpoints
# ============================================================================

from backend.feature_engine.schemas import FeatureBuildResponse, FeatureStatisticsResponse
from backend.feature_engine.models import BehaviouralFeatureVector
from backend.feature_engine.service import FeatureEngineService

feature_service = FeatureEngineService()

@app.post("/features/build", response_model=FeatureBuildResponse, tags=["Feature Engine"])
def build_features(idle_timeout: float = 60.0):
    """
    Generates behavioural feature vectors from reconstructed flows and packets.
    """
    try:
        total_features, stats = feature_service.build_features(idle_timeout_seconds=idle_timeout)
        return FeatureBuildResponse(
            success=True,
            total_features=total_features,
            summary_statistics=stats
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to extract behavioral features: {exc}")

@app.get("/features/list", response_model=List[BehaviouralFeatureVector], tags=["Feature Engine"])
def list_features():
    """
    Returns the list of all extracted flow behavioural feature vectors.
    """
    try:
        features = feature_service.get_all_features()
        return features
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve features list: {exc}")

@app.get("/features/statistics", response_model=FeatureStatisticsResponse, tags=["Feature Engine"])
def get_feature_statistics():
    """
    Computes and retrieves summary analytical statistics over all feature vectors.
    """
    try:
        stats = feature_service.get_statistics()
        return FeatureStatisticsResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to calculate feature statistics: {exc}")


# ============================================================================
# AI Behaviour Engine Endpoints
# ============================================================================

from backend.ai.behavior.schemas import TrainResponse, PredictRequest, PredictResponse as AIPredictResponse, AnalyzeResponse, StatisticsResponse as AIStatisticsResponse
from backend.ai.behavior.anomaly_service import AnomalyService

anomaly_service = AnomalyService()

@app.post("/ai/train", response_model=TrainResponse, tags=["AI Behavior Engine"])
def train_ai_model(model_type: str = "IsolationForest"):
    """
    Trains the unsupervised behavior model using all currently extracted feature vectors.
    """
    try:
        total_trained = anomaly_service.train_model(model_type=model_type)
        return TrainResponse(
            success=True,
            message=f"Successfully trained {model_type} model.",
            total_trained=total_trained,
            model_type=model_type
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to train behaviour model: {exc}")

@app.post("/ai/predict", response_model=AIPredictResponse, tags=["AI Behavior Engine"])
def predict_single_flow(request: PredictRequest):
    """
    Evaluates a single flow's behavioural feature vector to predict its anomaly status.
    """
    try:
        result = anomaly_service.predict_single(request.feature_vector)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to run behavior prediction: {exc}")

@app.post("/ai/analyze", response_model=AnalyzeResponse, tags=["AI Behavior Engine"])
def analyze_all_flows():
    """
    Runs unsupervised model prediction and heuristic risk scoring over all extracted flows.
    """
    try:
        total_analyzed, predictions = anomaly_service.analyze_flows()
        return AnalyzeResponse(
            success=True,
            total_analyzed=total_analyzed,
            predictions=predictions
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to run batch flow behavior analysis: {exc}")

@app.get("/ai/results", response_model=List[AIPredictResponse], tags=["AI Behavior Engine"])
def get_analysis_results():
    """
    Returns the cached list of previously evaluated flow predictions.
    """
    try:
        results = anomaly_service.get_results()
        return results
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve behavior analysis results: {exc}")

@app.get("/ai/statistics", response_model=AIStatisticsResponse, tags=["AI Behavior Engine"])
def get_analysis_statistics():
    """
    Computes summary analytical metrics over previous prediction runs.
    """
    try:
        stats = anomaly_service.get_statistics()
        return AIStatisticsResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to calculate behavior analysis statistics: {exc}")


# ============================================================================
# Threat Correlation Engine Endpoints
# ============================================================================

from backend.correlation_engine.schemas import Incident, AnalyzeResponse as CorrAnalyzeResponse, StatisticsResponse as CorrStatisticsResponse
from backend.correlation_engine.service import CorrelationService

correlation_service = CorrelationService()

@app.post("/correlation/analyze", response_model=CorrAnalyzeResponse, tags=["Threat Correlation Engine"])
def analyze_correlations():
    """
    Correlates active network flows and anomalies into security incidents.
    """
    try:
        incidents = correlation_service.analyze_incidents()
        return CorrAnalyzeResponse(
            success=True,
            total_incidents=len(incidents),
            incidents=incidents
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to analyze and correlate security incidents: {exc}")

@app.get("/correlation/incidents", response_model=List[Incident], tags=["Threat Correlation Engine"])
def get_correlated_incidents():
    """
    Returns the cached or newly analyzed list of correlated security incidents.
    """
    try:
        incidents = correlation_service.get_incidents()
        return incidents
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve correlated incidents: {exc}")

@app.get("/correlation/statistics", response_model=CorrStatisticsResponse, tags=["Threat Correlation Engine"])
def get_correlation_statistics():
    """
    Retrieves statistical summaries and distributions of correlated incidents.
    """
    try:
        stats = correlation_service.get_statistics()
        return CorrStatisticsResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to calculate threat correlation statistics: {exc}")


# ============================================================================
# MITRE ATT&CK Mapping Endpoints
# ============================================================================

from typing import Optional
from backend.mitre.schemas import MitreMapping, MapRequest, MapResponse, MitreStatisticsResponse
from backend.mitre.service import MitreService as PyMitreService

mitre_service = PyMitreService()

@app.post("/mitre/map", response_model=MapResponse, tags=["MITRE ATT&CK Engine"])
def map_mitre_techniques(request: Optional[MapRequest] = None):
    """
    Map detected behaviours and incidents to MITRE ATT&CK tactics and techniques.
    """
    try:
        if request and request.incident_id:
            mappings = mitre_service.map_incident_by_id(request.incident_id)
            return MapResponse(
                success=True,
                mapped_incidents={request.incident_id: mappings}
            )
        else:
            mapped = mitre_service.map_all_incidents()
            return MapResponse(
                success=True,
                mapped_incidents=mapped
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to map incidents to MITRE: {exc}")

@app.get("/mitre/incident/{id}", response_model=List[MitreMapping], tags=["MITRE ATT&CK Engine"])
def get_mitre_incident_mapping(id: str):
    """
    Retrieves MITRE ATT&CK technique mappings for a specific incident.
    """
    try:
        mappings = mitre_service.map_incident_by_id(id)
        return mappings
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve MITRE mappings for incident {id}: {exc}")

@app.get("/mitre/statistics", response_model=MitreStatisticsResponse, tags=["MITRE ATT&CK Engine"])
def get_mitre_statistics():
    """
    Retrieves statistical summaries and distributions of MITRE mappings.
    """
    try:
        stats = mitre_service.get_statistics()
        return MitreStatisticsResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to calculate MITRE statistics: {exc}")


# ============================================================================
# 8. RAG Threat Intelligence Endpoints
# ============================================================================

from backend.packet_parser.rag_engine import RagEngine

rag_engine = RagEngine()

class RagQueryRequest(BaseModel):
    query: str
    k: Optional[int] = 4

class RagIndexRequest(BaseModel):
    title: str
    content: str
    externalId: str
    sourceType: str

@app.post("/rag/query", tags=["RAG Threat Intelligence"])
def query_threat_intelligence(request: RagQueryRequest):
    """
    Semantically queries the indexed threat intelligence vector store and returns a synthesis.
    """
    try:
        if not request.query.strip():
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        return rag_engine.query(request.query, request.k or 4)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to perform RAG query: {exc}")

@app.post("/rag/index", tags=["RAG Threat Intelligence"])
def index_threat_intelligence(request: RagIndexRequest):
    """
    Ingests a single threat intelligence document into the FAISS store and memory db.
    """
    try:
        if not request.title or not request.content or not request.externalId or not request.sourceType:
            raise HTTPException(status_code=400, detail="Missing mandatory document properties")
        doc = rag_engine.ingest_document(
            title=request.title,
            content=request.content,
            external_id=request.externalId,
            source_type=request.sourceType
        )
        return {"success": True, "document": doc}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to index document: {exc}")

@app.get("/rag/status", tags=["RAG Threat Intelligence"])
def get_rag_status():
    """
    Returns the diagnostic status of the RAG engine and model load state.
    """
    try:
        return rag_engine.get_status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch RAG status: {exc}")







