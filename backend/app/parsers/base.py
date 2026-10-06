from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from app.models.schemas import Segment

@dataclass
class ExtractedContent:
    text: str
    metadata: Dict = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    hidden_content: List[str] = field(default_factory=list)
    embedded_objects: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    suspicious_elements: List[dict] = field(default_factory=list)
    source_type: str = 'unknown'
    content_hash: str = ''
    extraction_warnings: List[str] = field(default_factory=list)
    segments: List[Segment] = field(default_factory=list)

class BaseParser(ABC):
    supported_types: List[str]

    @abstractmethod
    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        pass

    @abstractmethod
    def can_parse(self, mime_type: str, filename: str) -> bool:
        pass
