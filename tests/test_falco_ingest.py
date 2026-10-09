"""Tests for monitor-service/falco_ingest.py using temporary files only."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import falco_ingest  # noqa: E402


class TailerTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log = self.dir / "alerts.json"
        self.checkpoint = self.dir / "checkpoint.json"
        self.log.write_bytes(b"")

    def tailer(self, **kwargs):
        kwargs.setdefault("start_from", "end")
        return falco_ingest.FalcoTailer(str(self.log), self.checkpoint, **kwargs)

    def append(self, data: bytes):
        with open(self.log, "ab") as handle:
            handle.write(data)


class TestPosition(TailerTestCase):
    def test_start_at_end_ignores_existing_history(self):
        self.append(b"old\n")
        tailer = self.tailer()
        self.append(b"new\n")
        self.assertEqual(tailer.read_batch().lines, ["new"])

    def test_start_from_beginning_reads_history(self):
        self.append(b"old\n")
        self.assertEqual(self.tailer(start_from="beginning").read_batch().lines, ["old"])

    def test_file_that_appears_later_is_read_from_its_start(self):
        self.log.unlink()
        tailer = self.tailer()
        with self.assertRaises(falco_ingest.IngestUnavailable):
            tailer.read_batch()
        self.append(b"first\n")
        self.assertEqual(tailer.read_batch().lines, ["first"])

    def test_missing_file_raises_unavailable(self):
        self.log.unlink()
        with self.assertRaises(falco_ingest.IngestUnavailable):
            self.tailer().read_batch()

    def test_rotation_reads_the_new_file_from_the_start(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"one\n")
        tailer.commit(tailer.read_batch())
        fresh = self.dir / "fresh.json"
        fresh.write_bytes(b"fresh\n")
        os.replace(fresh, self.log)
        self.assertEqual(tailer.read_batch().lines, ["fresh"])

    def test_truncation_restarts_from_the_beginning(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"aaaaaaaaaa\n")
        tailer.commit(tailer.read_batch())
        self.log.write_bytes(b"b\n")
        self.assertEqual(tailer.read_batch().lines, ["b"])


class TestLines(TailerTestCase):
    def test_partial_line_is_held_until_its_newline_arrives(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"complete\npartial")
        batch = tailer.read_batch()
        self.assertEqual(batch.lines, ["complete"])
        tailer.commit(batch)
        self.append(b" rest\n")
        self.assertEqual(tailer.read_batch().lines, ["partial rest"])

    def test_nul_bytes_and_bad_utf8_do_not_crash(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"ab\x00c\xff\xfed\n")
        line = tailer.read_batch().lines[0]
        self.assertTrue(line.startswith("abc"))
        self.assertNotIn("\x00", line)

    def test_blank_lines_are_skipped_but_consumed(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"\n\nreal\n")
        batch = tailer.read_batch()
        self.assertEqual(batch.lines, ["real"])
        tailer.commit(batch)
        self.assertEqual(tailer.read_batch().lines, [])

    def test_batch_size_is_limited_and_reading_continues(self):
        tailer = self.tailer(start_from="beginning", max_batch_lines=2)
        self.append(b"l1\nl2\nl3\nl4\nl5\n")
        seen = []
        for _ in range(4):
            batch = tailer.read_batch()
            seen.append(batch.lines)
            tailer.commit(batch)
        self.assertEqual(seen, [["l1", "l2"], ["l3", "l4"], ["l5"], []])


class TestDeduplicationAndCheckpoint(TailerTestCase):
    def test_duplicate_lines_in_one_batch_are_dropped(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"same\nsame\n")
        batch = tailer.read_batch()
        self.assertEqual(batch.lines, ["same"])
        self.assertEqual(batch.skipped_duplicates, 1)

    def test_uncommitted_batch_is_delivered_again(self):
        tailer = self.tailer(start_from="beginning")
        self.append(b"x\n")
        self.assertEqual(tailer.read_batch().lines, ["x"])
        self.assertEqual(tailer.read_batch().lines, ["x"])

    def test_checkpoint_lets_a_restarted_tailer_resume_without_loss(self):
        first = self.tailer(start_from="beginning")
        self.append(b"l1\nl2\n")
        first.commit(first.read_batch())
        self.append(b"l3\n")
        second = self.tailer()
        self.assertEqual(second.read_batch().lines, ["l3"])

    def test_replayed_lines_after_a_crash_are_recognised_and_skipped(self):
        first = self.tailer(start_from="beginning")
        self.append(b"l1\n")
        first.commit(first.read_batch())
        data = json.loads(self.checkpoint.read_text())
        data["offset"] = 0  # simulate a checkpoint written before l1 was processed
        self.checkpoint.write_text(json.dumps(data))
        batch = self.tailer().read_batch()
        self.assertEqual(batch.lines, [])
        self.assertEqual(batch.skipped_duplicates, 1)

    def test_corrupt_checkpoint_is_ignored(self):
        self.append(b"old\n")
        self.checkpoint.write_text("{not json")
        self.assertEqual(self.tailer().read_batch().lines, [])


if __name__ == "__main__":
    unittest.main()
