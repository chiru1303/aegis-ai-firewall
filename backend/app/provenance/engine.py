import uuid
import hashlib
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from app.core.time import now_ist, format_ist

class ContentProvenance(BaseModel):
    content_id: str
    source_type: str
    origin: str
    trust_level: str
    received_at: str
    parent_content_id: Optional[str]
    transformation_chain: List[str]
    content_hash: str
    metadata: Dict[str, Any]

class ProvenanceEngine:
    def __init__(self):
        self.trust_rules = {
            "system": "TRUSTED",
            "user_authenticated": "SEMI_TRUSTED",
            "user_anonymous": "UNTRUSTED",
            "web": "UNTRUSTED",
            "pdf": "UNTRUSTED",
            "docx": "UNTRUSTED",
            "email": "UNTRUSTED",
            "api": "SEMI_TRUSTED",
            "ocr": "UNTRUSTED",
            "database": "SEMI_TRUSTED",
            "code": "UNTRUSTED",
            "unknown": "UNTRUSTED"
        }
        self.graphs = {}

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    async def track_content(self, content: str, source_type: str, origin: str, parent_id: Optional[str] = None, transform: Optional[str] = None) -> ContentProvenance:
        content_id = str(uuid.uuid4())
        trust_level = self.trust_rules.get(source_type, "UNTRUSTED")

        transform_chain = []
        if parent_id and parent_id in self.graphs:
            parent_prov = self.graphs[parent_id]
            transform_chain = list(parent_prov.transformation_chain)
            if transform:
                transform_chain.append(transform)

        prov = ContentProvenance(
            content_id=content_id,
            source_type=source_type,
            origin=origin,
            trust_level=trust_level,
            received_at=format_ist(now_ist()),
            parent_content_id=parent_id,
            transformation_chain=transform_chain,
            content_hash=self._hash_content(content),
            metadata={}
        )
        self.graphs[content_id] = prov
        while len(self.graphs) > 2000:
            self.graphs.pop(next(iter(self.graphs)))
        return prov
