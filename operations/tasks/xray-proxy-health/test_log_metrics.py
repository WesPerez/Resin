import importlib.util
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("log_metrics", Path(__file__).with_name("log_metrics.py"))
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


class LogMetricsTests(unittest.TestCase):
    start = int(datetime.fromisoformat("2026-09-20T20:00:00+08:00").timestamp())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "access.log"

    def line(self, minute="00", status=101, duration="2.000", size=10):
        return f"[20/Sep/2026:20:{minute}:05 +0800] status={status} duration={duration} bytes={size}\n"

    def test_rotation_includes_previous_file_and_ignores_other_minutes(self):
        self.path.write_text(self.line(status=429) + self.line(minute="01"))
        self.path.with_suffix(".log.1").write_text(self.line(size=0) + self.line(status=503, duration="0.000"))
        counts, source = metrics.sample(self.path, "ws", self.start)
        self.assertEqual(source["status"], "ok")
        self.assertEqual(counts["ws_total"], 3)
        self.assertEqual(counts["ws_101_zero_bytes"], 1)
        self.assertEqual(counts["ws_503_zero_ms"], 1)
        self.assertEqual(counts["ws_101_short_ratio"], 1)

    def test_missing_and_permission_failure_are_null_not_zero(self):
        for error, expected in ((FileNotFoundError(), "missing"), (PermissionError(), "unreadable")):
            with self.subTest(expected=expected), patch.object(Path, "open", side_effect=error):
                counts, source = metrics.sample(self.path, "ws", self.start)
            self.assertEqual(source["status"], expected)
            self.assertTrue(all(value is None for value in counts.values()))

    def test_readable_empty_log_is_real_zero(self):
        self.path.write_text("")
        counts, source = metrics.sample(self.path, "xhttp", self.start)
        self.assertEqual(counts["xhttp_total"], 0)
        self.assertTrue(source["complete"])

    def test_tail_cutting_requested_minute_marks_incomplete(self):
        self.path.write_text(self.line() * 20)
        counts, source = metrics.sample(self.path, "ws", self.start, max_bytes=200)
        self.assertEqual(source["status"], "truncated")
        self.assertIsNone(counts["ws_total"])

    def test_duplicate_inode_during_rename_is_counted_once(self):
        self.path.write_text(self.line())
        os.link(self.path, str(self.path) + ".1")
        counts, _ = metrics.sample(self.path, "ws", self.start)
        self.assertEqual(counts["ws_total"], 1)

    def test_invalid_format_is_not_successful_empty_sample(self):
        self.path.write_text(self.line().replace("status=101", "status=invalid"))
        counts, source = metrics.sample(self.path, "ws", self.start)
        self.assertEqual(source["status"], "invalid_format")
        self.assertIsNone(counts["ws_total"])


if __name__ == "__main__":
    unittest.main()
