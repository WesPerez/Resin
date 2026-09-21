"""The single timer must keep browser validation in every supported pool mode."""
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('rotation_entrypoint_test', Path(__file__).with_name('rotation-control.py'))
rotation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rotation
SPEC.loader.exec_module(rotation)


class EntrypointTests(unittest.TestCase):
    def test_balanced_mode_finishes_rotation_before_starting_site_worker(self):
        order = []
        with patch.object(sys, 'argv', ['rotation-control.py', 'refresh', '--wait-seconds', '30']), \
                patch.object(rotation.POOL, 'unified', return_value=False), \
                patch.object(rotation.POOL, 'enabled', return_value=True), \
                patch.object(rotation, 'refresh', side_effect=lambda **_: order.append('rotation-finished')), \
                patch.object(rotation.subprocess, 'run', side_effect=lambda *a, **k: order.append('site-started')) as run:
            rotation.main()
        self.assertEqual(order, ['rotation-finished', 'site-started'])
        self.assertEqual(run.call_args.args[0][2:], ['refresh', '--wait-seconds', '30'])
        self.assertTrue(run.call_args.kwargs['check'])

    def test_shared_mode_does_not_run_a_second_browser_phase(self):
        quality = SimpleNamespace(refresh=Mock())
        with patch.object(sys, 'argv', ['rotation-control.py', 'refresh']), \
                patch.object(rotation.POOL, 'unified', return_value=True), \
                patch.dict(sys.modules, {'unified_quality': quality}), \
                patch.object(rotation, 'refresh') as refresh, \
                patch.object(rotation.subprocess, 'run') as run:
            rotation.main()
        quality.refresh.assert_called_once()
        refresh.assert_not_called()
        run.assert_not_called()

    def test_site_phase_failure_is_not_reported_as_rotation_success(self):
        with patch.object(sys, 'argv', ['rotation-control.py', 'refresh']), \
                patch.object(rotation.POOL, 'unified', return_value=False), \
                patch.object(rotation.POOL, 'enabled', return_value=True), \
                patch.object(rotation, 'refresh'), \
                patch.object(rotation.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['site-control'])):
            with self.assertRaises(subprocess.CalledProcessError):
                rotation.main()


if __name__ == '__main__':
    unittest.main()
