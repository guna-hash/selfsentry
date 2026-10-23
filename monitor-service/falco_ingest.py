"""
falco_ingest.py
-----------------
Reliable, restartable tail of Falco's JSON alert log for the continuous monitor.

Guarantees and limits:
  - Only COMPLETE lines (ending in a newline) are delivered; a half-written line is
    held back until the rest arrives.
  - Delivery is at-least-once. The caller processes a batch and then commit()s it; the
    file position and the hashes of recently seen lines are checkpointed atomically, so
    after a crash the unprocessed lines are re-read and lines already processed are
    recognised and skipped.
  - Falco events carry no unique id, so deduplication hashes the whole raw line. Two
    byte-identical lines are treated as one event.
  - Log rotation by replacement (new inode) is detected and the new file is read from its
    start. Lines written to the old file between our last read and the rotation are not
    recoverable. Truncation in place (copytruncate) restarts from the beginning.
  - If no checkpoint exists the tail starts at the END of the file (history is not
    replayed), unless the file did not exist yet when we first looked: then it is read
    from the start.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 4 * 1024 * 1024


class IngestUnavailable(RuntimeError):
    """The Falco log cannot be read right now (missing file, permissions, ...)."""


@dataclass
class Batch:
    lines: list[str]
    keys: list[str]
    inode: int
    end_offset: int
    skipped_duplicates: int = 0
    discarding_line: bool = False


class FalcoTailer:
    def __init__(
        self,
        log_path,
        checkpoint_path,
        start_from: str = "end",
        dedup_window: int = 2000,
        max_batch_lines: int = 500,
    ):
        if start_from not in ("beginning", "end"):
            raise ValueError("start_from must be beginning or end")
        if any(type(value) is not int or value <= 0 for value in (dedup_window, max_batch_lines)):
            raise ValueError("dedup_window and max_batch_lines must be positive integers")
        self._path = Path(log_path)
        self._checkpoint_path = Path(checkpoint_path)
        self._start_from = start_from
        self._dedup_window = dedup_window
        self._max_batch_lines = max_batch_lines
        self._inode: int | None = None
        self._offset = 0
        self._saw_missing = False
        self._discarding_line = False
        self._checkpoint_error: str | None = None
        self._recent: OrderedDict[str, None] = OrderedDict()
        try:
            self._load_checkpoint()
        except IngestUnavailable as exc:
            self._checkpoint_error = str(exc)

        # Establish the initial position immediately.
        # Otherwise, lines appended before the first read_batch()
        # would incorrectly be treated as existing history.
        if self._inode is None and self._checkpoint_error is None:
            try:
                stat = os.stat(self._path)
            except OSError:
                self._saw_missing = True
            else:
                self._sync_position(stat)

    @property
    def offset(self) -> int:
        return self._offset

    def _load_checkpoint(self) -> None:
        try:
            data = json.loads(self._checkpoint_path.read_text())
            if not isinstance(data, dict):
                raise ValueError("checkpoint must be an object")
            inode, offset = data["inode"], data["offset"]
            keys = data.get("recent_keys", [])
            discarding = data.get("discarding_line", False)
            if (
                type(inode) is not int or inode < 0
                or type(offset) is not int or offset < 0
                or type(discarding) is not bool
                or not isinstance(keys, list)
                or any(not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{20}", key)
                       for key in keys)
            ):
                raise ValueError("invalid checkpoint fields")
        except FileNotFoundError:
            if self._checkpoint_error is not None or self._checkpoint_path.is_symlink():
                raise IngestUnavailable(
                    "Checkpoint missing or unreadable after corruption; operator repair required"
                )
            return
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise IngestUnavailable(
                "Checkpoint unreadable or invalid; restore or review replay position "
                "before resuming"
            ) from exc
        self._inode, self._offset = inode, offset
        self._discarding_line = discarding
        self._checkpoint_error = None
        self._recent.clear()
        for key in keys[-self._dedup_window:]:
            self._recent[key] = None

    def _write_checkpoint(self) -> None:
        payload = {
            "inode": self._inode,
            "offset": self._offset,
            "recent_keys": list(self._recent),
            "discarding_line": self._discarding_line,
        }
        tmp_path = None
        try:
            self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, filename = tempfile.mkstemp(
                prefix=f".{self._checkpoint_path.name}.", dir=self._checkpoint_path.parent
            )
            tmp_path = Path(filename)
            with os.fdopen(descriptor, "w") as handle:
                json.dump(payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._checkpoint_path)
            directory = os.open(self._checkpoint_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise IngestUnavailable(
                "Cannot durably persist Falco checkpoint; batch remains replayable"
            ) from exc
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not remove unused checkpoint temporary file")

    def _sync_position(self, stat: os.stat_result) -> None:
        if self._inode is None:
            self._inode = stat.st_ino
            if self._saw_missing or self._start_from == "beginning":
                self._offset = 0
            else:
                self._offset = stat.st_size
        elif self._inode != stat.st_ino:
            logger.warning("Falco log was replaced (rotation); reading the new file from the start")
            self._inode = stat.st_ino
            self._offset = 0
            self._discarding_line = False
        elif self._offset > stat.st_size:
            logger.warning("Falco log was truncated; restarting from the beginning")
            self._offset = 0
            self._discarding_line = False

    def read_batch(self) -> Batch:
        """Read new complete lines. Nothing is consumed until commit() is called."""
        if self._checkpoint_error is not None:
            self._load_checkpoint()
        try:
            with open(self._path, "rb") as handle:
                self._sync_position(os.fstat(handle.fileno()))
                handle.seek(self._offset)
                chunk = handle.read(MAX_READ_BYTES)
        except OSError as exc:
            self._saw_missing = True
            raise IngestUnavailable(f"cannot read {self._path}: {exc}") from exc
        return self._split(chunk)

    def _split(self, chunk: bytes) -> Batch:
        if self._inode is None:
            raise IngestUnavailable("Falco log identity has not been established")
        offset = self._offset
        if self._discarding_line:
            boundary = chunk.find(b"\n")
            if boundary == -1:
                return Batch([], [], self._inode, offset + len(chunk), discarding_line=True)
            offset += boundary + 1
            chunk = chunk[boundary + 1:]
        last_newline = chunk.rfind(b"\n")
        if last_newline == -1:
            if len(chunk) >= MAX_READ_BYTES:
                # A single oversized line must not stall ingestion forever.
                logger.error("discarding an oversized (>= %d bytes) log line", MAX_READ_BYTES)
                return Batch([], [], self._inode, offset + len(chunk), discarding_line=True)
            return Batch([], [], self._inode, offset)

        lines: list[str] = []
        keys: list[str] = []
        seen: set[str] = set()
        consumed = skipped = processed = 0
        for raw in chunk[: last_newline + 1].split(b"\n")[:-1]:
            if processed >= self._max_batch_lines:
                break
            processed += 1
            consumed += len(raw) + 1
            text = raw.replace(b"\x00", b"").decode("utf-8", errors="replace").strip()
            if not text:
                continue
            key = hashlib.sha1(text.encode("utf-8")).hexdigest()[:20]
            if key in self._recent or key in seen:
                skipped += 1
                continue
            seen.add(key)
            lines.append(text)
            keys.append(key)
        return Batch(lines, keys, self._inode, offset + consumed, skipped)

    def commit(self, batch: Batch) -> None:
        """Mark a batch as fully handled and persist the checkpoint atomically."""
        previous = self._inode, self._offset, self._recent.copy(), self._discarding_line
        self._inode, self._offset = batch.inode, batch.end_offset
        self._discarding_line = batch.discarding_line
        for key in batch.keys:
            self._recent[key] = None
            self._recent.move_to_end(key)
        while len(self._recent) > self._dedup_window:
            self._recent.popitem(last=False)
        try:
            self._write_checkpoint()
        except IngestUnavailable:
            self._inode, self._offset, self._recent, self._discarding_line = previous
            raise
