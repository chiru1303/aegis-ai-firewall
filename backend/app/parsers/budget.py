"""Bound parser concurrency and isolate production parsing with a hard deadline."""
import asyncio
import json
import multiprocessing
from dataclasses import asdict
from app.core.config import settings
from app.parsers.base import ExtractedContent

_slots = asyncio.Semaphore(4)


def _worker(connection, content, filename, mime):
    try:
        from app.parsers.registry import registry
        import os
        if os.name == "posix":
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
            resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        parser = registry.get_parser(mime, filename)
        if parser is None:
            raise ValueError("Unsupported format")
        result = asyncio.run(parser.parse(content, filename, mime))
        document = asdict(result)
        document["segments"] = [segment.model_dump(mode="json") for segment in result.segments]
        encoded = json.dumps(document).encode()
        if len(encoded) > settings.MAX_CONTENT_LENGTH * 4:
            raise ValueError("Extraction exceeds output budget")
        connection.send_bytes(encoded)
    except Exception:
        connection.send_bytes(b'{"text":"","source_type":"unknown","extraction_warnings":["Isolated parser failed"]}')
    finally:
        connection.close()


def _isolated(content, filename, mime, timeout):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(child, content, filename, mime), daemon=True)
    try:
        process.start()
        child.close()
        if not parent.poll(timeout):
            raise TimeoutError("Parser deadline exceeded")
        raw = parent.recv_bytes(settings.MAX_CONTENT_LENGTH * 4)
        document = json.loads(raw)
        from app.models.schemas import Segment
        document["segments"] = [Segment.model_validate(segment) for segment in document.get("segments", [])]
        return ExtractedContent(**document)
    finally:
        parent.close()
        child.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)


async def parse_with_budget(parser, content, filename, mime=""):
    acquired = False
    try:
        await asyncio.wait_for(_slots.acquire(), timeout=2)
        acquired = True
        deadline = min(30, settings.REQUEST_TIMEOUT)
        if settings.ENVIRONMENT == "production":
            return await asyncio.to_thread(_isolated, content, filename, mime, deadline)
        # Development allows instrumented parsers and avoids process startup cost.
        return await asyncio.wait_for(asyncio.to_thread(lambda: asyncio.run(parser.parse(content, filename, mime))), timeout=deadline)
    except Exception:
        return ExtractedContent(text="", source_type="unknown", extraction_warnings=["Parser unavailable or extraction budget exceeded"])
    finally:
        if acquired:
            _slots.release()
