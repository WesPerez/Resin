from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import cn_candidates


class CNCandidatesTests(unittest.TestCase):
    def test_country_sources_and_old_candidates_are_not_starved_by_large_global_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "old"
            previous.write_text("http://1.1.1.1:8080\n")
            (root / "proxifly.txt").write_text("http://8.8.8.8:8080\n")
            (root / "dedeoglu.txt").write_text("".join(f"9.9.9.9:{port}\n" for port in range(1000, 3000)))
            rows, report = cn_candidates.select(previous, root, 3)
            self.assertEqual(rows[:2], ["1.1.1.1:8080", "8.8.8.8:8080"])
            self.assertEqual(len(rows), 3)
            self.assertEqual(report["previous_selected"], 1)

    def test_global_exploration_is_interleaved_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "speedx.txt").write_text("1.1.1.1:80\n1.1.1.1:81\n1.1.1.1:82\n")
            (root / "monosans.txt").write_text("1.1.1.1:80\n8.8.8.8:80\n")
            rows, _ = cn_candidates.select(root / "missing", root, 3)
            self.assertEqual(rows, ["1.1.1.1:80", "8.8.8.8:80", "1.1.1.1:81"])

    def test_untrusted_lists_cannot_probe_loopback_private_or_invalid_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source"
            path.write_text("127.0.0.1:80\n10.0.0.1:1080\n169.254.169.254:80\n999.1.1.1:80\n1.1.1.1:65536\nhttp://1.1.1.1:80/\n")
            self.assertEqual(cn_candidates.read_candidates(path), ["1.1.1.1:80"])


if __name__ == "__main__":
    unittest.main()
