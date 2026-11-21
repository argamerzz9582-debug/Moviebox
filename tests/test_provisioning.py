import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rex.provisioning.engine import Provisioner, environment


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = Provisioner(Path(self.tmp.name))

    def test_environment_reports_only_present_package_managers(self):
        with patch('rex.provisioning.engine.shutil.which', return_value=None):
            env = environment(self.tmp.name)
        self.assertEqual(env['package_managers'], [])
        self.assertIn('arch', env)
        self.assertGreater(env['disk_free_bytes'], 0)

    def test_dependencies_are_deduplicated_and_ordered(self):
        with patch.object(self.engine, 'inspect', return_value={'state': 'missing'}):
            plan = self.engine.plan(['jadx', 'apktool', 'jadx'])
        self.assertEqual([p['tool'] for p in plan], ['java', 'jadx', 'apktool'])

    def test_dependency_cycle_and_unknown_are_rejected(self):
        self.engine.specs = {'a': {'dependencies': ['b']}, 'b': {'dependencies': ['a']}}
        with self.assertRaisesRegex(ValueError, 'cycle'):
            self.engine.plan(['a'])
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            self.engine.plan(['missing'])

    def test_dry_run_offline_and_system_consent(self):
        step = {'tool': 'frida', 'dependencies': [], 'current': {'state': 'missing'},
                'method': {'kind': 'venv', 'package': 'frida-tools==13.6.1'}}
        with patch.object(self.engine, '_install_venv') as install:
            self.assertEqual(self.engine.install([step], dry_run=True)[0]['state'], 'planned')
            self.engine.offline = True
            self.assertEqual(self.engine.install([step])[0]['state'], 'skipped')
            install.assert_not_called()
        self.engine.offline = False
        step['method'] = {'kind': 'system', 'manager': 'apt-get', 'package': 'x'}
        with patch.object(self.engine, '_install_system') as install:
            self.assertEqual(self.engine.install([step])[0]['state'], 'skipped')
            install.assert_not_called()

    def test_failed_install_rolls_back_fresh_directory(self):
        import subprocess
        with patch('rex.provisioning.engine.subprocess.run', side_effect=subprocess.TimeoutExpired('venv', 1)):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.engine._install_venv('frida', 'frida-tools==13.6.1')
        self.assertFalse((self.engine.root / 'frida').exists())

    def test_existing_directory_is_never_overwritten(self):
        dest = self.engine.root / 'frida'
        dest.mkdir(parents=True)
        (dest / 'keep').write_text('safe')
        with self.assertRaisesRegex(RuntimeError, 'refusing'):
            self.engine._install_venv('frida', 'frida-tools==13.6.1')
        self.assertEqual((dest / 'keep').read_text(), 'safe')

    def test_uninstall_only_marked_managed_directory(self):
        dest = self.engine.root / 'frida'
        dest.mkdir(parents=True)
        with self.assertRaises(ValueError):
            self.engine.uninstall('frida')
        (dest / 'metadata.json').write_text(json.dumps({'tool': 'frida'}))
        self.assertEqual(self.engine.uninstall('frida', True)['state'], 'planned_removal')
        self.assertTrue(dest.exists())
        self.engine.uninstall('frida')
        self.assertFalse(dest.exists())

    def test_blocked_dependency_never_executes(self):
        plan = [{'tool': 'java', 'dependencies': [], 'current': {'state': 'missing'}, 'method': None},
                {'tool': 'jadx', 'dependencies': ['java'], 'current': {'state': 'missing'},
                 'method': {'kind': 'system', 'manager': 'brew', 'package': 'jadx'}}]
        with patch.object(self.engine, '_install_system') as install:
            self.assertEqual([r['state'] for r in self.engine.install(plan, allow_system=True)], ['unsupported', 'blocked'])
            install.assert_not_called()

    def test_system_command_uses_argument_array_and_verifies(self):
        step = {'tool': 'radare2', 'dependencies': [], 'current': {'state': 'missing'},
                'method': {'kind': 'system', 'manager': 'brew', 'package': 'radare2'}}
        with patch.object(self.engine, '_install_system') as install, patch.object(self.engine, 'inspect', return_value={'state': 'verified'}):
            self.assertEqual(self.engine.install([step], allow_system=True)[0]['state'], 'verified')
            install.assert_called_once()

if __name__ == '__main__':
    unittest.main()

class CliProvisioningTests(unittest.TestCase):
    def test_setup_dry_run_json_does_not_write(self):
        import contextlib
        import io
        from rex.cli import main
        with tempfile.TemporaryDirectory() as home, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(['--home', home, 'setup', '--dry-run', '--json']), 0)
            self.assertIn('plan', json.loads(out.getvalue()))
            self.assertFalse((Path(home) / '.rex').exists())

    def test_analysis_provisioning_failure_does_not_abort(self):
        import zipfile
        from rex.config import RexConfig
        from rex.orchestrator.engine import AnalysisOrchestrator
        with tempfile.TemporaryDirectory() as home:
            artifact = Path(home) / 'sample.jar'
            with zipfile.ZipFile(artifact, 'w') as archive:
                archive.writestr('com/example/Test.class', b'\xca\xfe\xba\xbe\x00\x00\x00\x34')
            cfg = RexConfig.load(home=Path(home), offline_mode=True)
            with patch('rex.orchestrator.engine.Provisioner.plan', side_effect=RuntimeError('failure')):
                result = AnalysisOrchestrator(cfg).execute(str(artifact), mode='deep', install_missing=True)
            self.assertTrue(result['tasks'])
            if result['provisioning']:
                self.assertEqual(result['provisioning'][0]['state'], 'failed')

class DriveUpdateCompatibilityTests(unittest.TestCase):
    def test_provision_dry_run_and_approval(self):
        import contextlib
        import io
        from rex.cli import main
        with tempfile.TemporaryDirectory() as home:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = main(['--home', home, '--json', 'provision', 'install', '--profile', 'core', '--dry-run'])
            self.assertEqual(code, 0)
            self.assertIn('keystone', [x['tool'] for x in json.loads(out.getvalue())['plan']])
            self.assertFalse((Path(home) / '.rex').exists())
            with patch.object(Provisioner, 'install') as install, contextlib.redirect_stdout(io.StringIO()) as out:
                code = main(['--home', home, '--json', 'provision', 'install', 'frida'])
                self.assertEqual(code, 1)
                install.assert_not_called()
                self.assertEqual(json.loads(out.getvalue())['results'][0]['state'], 'approval_required')

    def test_system_changes_require_both_flags(self):
        import contextlib
        import io
        from rex.cli import main
        with tempfile.TemporaryDirectory() as home, patch.object(Provisioner, 'install', return_value=[]) as install, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--home', home, 'provision', 'install', 'radare2', '--allow-system']), 1)
            install.assert_not_called()
            self.assertEqual(main(['--home', home, 'provision', 'install', 'radare2', '--yes', '--allow-system']), 0)
            self.assertTrue(install.call_args.kwargs['allow_system'])

    def test_plan_accepts_archive_tool_aliases(self):
        import contextlib
        import io
        from rex.cli import main
        with tempfile.TemporaryDirectory() as home, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(['--home', home, '--json', 'provision', 'plan', 'readelf', 'objdump', 'cfr']), 0)
            ids = [item['tool'] for item in json.loads(out.getvalue())['items']]
            self.assertIn('binutils-readelf', ids)
            self.assertIn('binutils-objdump', ids)
            self.assertIn('cfr', ids)
