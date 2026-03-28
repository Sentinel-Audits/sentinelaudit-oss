from pydantic import BaseModel
from typing import List, Optional

class FileIn(BaseModel):
    path: str
    content: str

class RunReq(BaseModel):
    jobId: Optional[str] = None
    projectId: str
    entrypoints: List[str]
    files: List[FileIn]
    solc_version: Optional[str] = None
    callbackURL: Optional[str] = None
    vendors: Optional[dict] = None  # e.g. {"openzeppelin": "4.9.6"}
    importPolicy: Optional[dict] = None

class JobResponse(BaseModel):
    jobId: str
    projectId: str
    status: str
    createdAt: str
    updatedAt: str
    completedAt: Optional[str] = None
    events: List[dict]
    result: Optional[dict] = None
    error: Optional[str] = None
