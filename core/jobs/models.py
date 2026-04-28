"""
Pydantic models and enums for the job system.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Lifecycle states for a forensic analysis job."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobInfo(BaseModel):
    """Public-facing job metadata."""
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    result_available: bool = False
    created_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None
    dump_path: str
    dump_hash: Optional[str] = None
    job_type: str = "single"  # "single" or "multi"


class AnalyzeRequest(BaseModel):
    """Request body for POST /jobs/analyze."""
    dump_path: str


class MultiAnalyzeRequest(BaseModel):
    """Request body for POST /jobs/analyze/multi."""
    dump_paths: List[str] = Field(..., min_length=2, max_length=10)


class JobResult(BaseModel):
    """Internal container for analysis results."""
    correlation: Optional[List[Dict[str, Any]]] = None
    timeline: Optional[List[Dict[str, Any]]] = None
    graph: Optional[Dict[str, Any]] = None
    alerts: Optional[List[Dict[str, Any]]] = None
    diff: Optional[Dict[str, Any]] = None
    validation_warnings: Optional[List[str]] = None
    cached: bool = False
