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


class FalcoTailer:
    def __init__(
        self,
        log_path,
        checkpoint_path,
        start_from: str = "end",
        dedup_window: int = 2000,
        max_batch_lines: int = 500,
    ):
        self._path = Path(log_path)
        self._checkpoint_path = Path(checkpoint_path)
        self._start_from = start_from
        self._dedup_window = dedup_window
        self._max_batch_lines = max_batch_lines
        self._inode: int | None = None
        self._offset = 0
        self._saw_missing = False
        self._recent: OrderedDict[str, None] = OrderedDict()
        self._load_checkpoint()

        # Establish the initial position immediately.
        # Otherwise, lines appended before the first read_batch()
        # would incorrectly be treated as existing history.
        if self._inode is None:
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
            inode, offset = int(data["inode"]), int(data["offset"])
            keys = [str(key) for key in data.get("recent_keys", [])]
        except FileNotFoundError:
            return
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("Ignoring unreadable checkpoint %s: %s", self._checkpoint_path, exc)
            return
        self._inode, self._offset = inode, offset
        for key in keys:
            self._recent[key] = None

    def _write_checkpoint(self) -> None:
        payload = {
            "inode": self._inode,
            "offset": self._offset,
            "recent_keys": list(self._recent),
        }
        try:
            self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._checkpoint_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(payload))
            os.replace(tmp_path, self._checkpoint_path)
        except OSError as exc:
            logger.error("could not write checkpoint %s: %s", self._checkpoint_path, exc)

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
        elif self._offset > stat.st_size:
            logger.warning("Falco log was truncated; restarting from the beginning")
            self._offset = 0

    def read_batch(self) -> Batch:
        """Read new complete lines. Nothing is consumed until commit() is called."""
        try:
            stat = os.stat(self._path)
        except OSError as exc:
            self._saw_missing = True
            raise IngestUnavailable(f"cannot read {self._path}: {exc}") from exc
        self._sync_position(stat)
        try:
            with open(self._path, "rb") as handle:
                handle.seek(self._offset)
                chunk = handle.read(MAX_READ_BYTES)
        except OSError as exc:
            raise IngestUnavailable(f"cannot read {self._path}: {exc}") from exc
        return self._split(chunk)

    def _split(self, chunk: bytes) -> Batch:
        last_newline = chunk.rfind(b"\n")
        if last_newline == -1:
            if len(chunk) >= MAX_READ_BYTES:
                # A single oversized line must not stall ingestion forever.
                logger.error("discarding an oversized (>= %d bytes) log line", MAX_READ_BYTES)
                return Batch([], [], self._inode, self._offset + len(chunk))
            return Batch([], [], self._inode, self._offset)

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
        return Batch(lines, keys, self._inode, self._offset + consumed, skipped)

    def commit(self, batch: Batch) -> None:
        """Mark a batch as fully handled and persist the checkpoint atomically."""
        self._inode, self._offset = batch.inode, batch.end_offset
        for key in batch.keys:
            self._recent[key] = None
            self._recent.move_to_end(key)
        while len(self._recent) > self._dedup_window:
            self._recent.popitem(last=False)
        self._write_checkpoint()
