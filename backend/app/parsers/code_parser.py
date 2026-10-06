"""
Universal Source Code Parser with comment, docstring, and literal segment extraction.
Extracts line/block comments with line numbers, docstrings, string literals,
and suspicious execution primitives without executing any code.
"""
import hashlib
import re
import uuid
from typing import List, Dict, Any
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

class CodeParser(BaseParser):
    supported_types = [
        'text/x-python', 'text/javascript', 'text/x-java-source',
        'text/x-c', 'text/x-c++', 'text/x-go', 'text/x-ruby', 'application/x-httpd-php', 'application/x-sh',
        'text/x-code'
    ]
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h', '.go', '.rb', '.php', '.sh', '.bash', '.rs'}

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or any(filename.lower().endswith(ext) for ext in self.extensions)

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='code'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []

        try:
            code_text = content.decode('utf-8', errors='replace')
            extracted.text = code_text
            lines = code_text.splitlines()

            # 1. Multi-line docstrings and block comments
            # Python triple-quotes
            py_docstring_pattern = re.compile(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')')
            for match in py_docstring_pattern.finditer(code_text):
                matched_str = match.group(1)
                start_pos = match.start()
                line_no = code_text[:start_pos].count('\n') + 1
                inner_text = matched_str.strip('"\'').strip()
                if inner_text:
                    extracted.comments.append(inner_text)
                    segments.append(Segment(
                        id=f"seg-code-docstring-{line_no}-{uuid.uuid4().hex[:6]}",
                        text=inner_text,
                        source_type="code",
                        location=f"code:docstring:line {line_no}",
                        visibility="visible",
                        trust="UNTRUSTED"
                    ))

            # C/Java/JS block comments /* ... */
            c_block_pattern = re.compile(r'/\*([\s\S]*?)\*/')
            for match in c_block_pattern.finditer(code_text):
                matched_str = match.group(1).strip()
                start_pos = match.start()
                line_no = code_text[:start_pos].count('\n') + 1
                if matched_str:
                    extracted.comments.append(matched_str)
                    segments.append(Segment(
                        id=f"seg-code-block-cmt-{line_no}-{uuid.uuid4().hex[:6]}",
                        text=matched_str,
                        source_type="code",
                        location=f"code:comment:line {line_no}",
                        visibility="visible",
                        trust="UNTRUSTED"
                    ))

            # 2. Single line comments (# and //)
            for idx, line in enumerate(lines):
                line_no = idx + 1
                line_str = line.strip()

                # Python/Shell/Ruby comment
                if line_str.startswith('#'):
                    cmt_text = line_str.lstrip('#').strip()
                    if cmt_text:
                        extracted.comments.append(cmt_text)
                        segments.append(Segment(
                            id=f"seg-code-cmt-{line_no}-{uuid.uuid4().hex[:6]}",
                            text=cmt_text,
                            source_type="code",
                            location=f"code:comment:line {line_no}",
                            visibility="visible",
                            trust="UNTRUSTED"
                        ))
                # C/JS/Java single line comment
                elif line_str.startswith('//'):
                    cmt_text = line_str.lstrip('/').strip()
                    if cmt_text:
                        extracted.comments.append(cmt_text)
                        segments.append(Segment(
                            id=f"seg-code-cmt-{line_no}-{uuid.uuid4().hex[:6]}",
                            text=cmt_text,
                            source_type="code",
                            location=f"code:comment:line {line_no}",
                            visibility="visible",
                            trust="UNTRUSTED"
                        ))

            # 3. String literals (longer than 10 characters or containing instruction verbs)
            str_pattern = re.compile(r'([\'"])(.*?)\1')
            for match in str_pattern.finditer(code_text):
                lit = match.group(2).strip()
                start_pos = match.start()
                line_no = code_text[:start_pos].count('\n') + 1
                if len(lit) >= 12 or any(v in lit.lower() for v in ['ignore', 'system', 'override', 'prompt', 'admin', 'password', 'api_key']):
                    segments.append(Segment(
                        id=f"seg-code-lit-{line_no}-{uuid.uuid4().hex[:6]}",
                        text=lit,
                        source_type="code",
                        location=f"code:string_literal:line {line_no}",
                        visibility="visible",
                        trust="UNTRUSTED"
                    ))

            # 4. Whole code body segment
            segments.append(Segment(
                id=f"seg-code-body-{uuid.uuid4().hex[:6]}",
                text=code_text,
                source_type="code",
                location="code:body",
                visibility="visible",
                trust="UNTRUSTED"
            ))

            # Security checks
            urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', code_text)
            extracted.links.extend(urls)

            os_patterns = [r'os\.system', r'subprocess\.', r'exec\(', r'eval\(', r'shell_exec', r'system\(']
            for pat in os_patterns:
                if re.search(pat, code_text):
                    extracted.suspicious_elements.append({
                        "type": "os_execution",
                        "description": f"OS command execution pattern found: {pat}"
                    })

        except Exception as e:
            extracted.extraction_warnings.append(f"Code parsing error: {str(e)}")

        extracted.segments = segments
        return extracted
