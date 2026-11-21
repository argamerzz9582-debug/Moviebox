import hashlib
import io
import json
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rex.provisioning.releases import download, extract_zip, validate_url
from rex.provisioning.engine import Provisioner
from rex.mcp.health import verify_server


class ReleasesTest(unittest.TestCase):
    def test_url_policy(self):
        validate_url('https://github.com/skylot/jadx/releases/a.zip')
        for url in ('http://github.com/x', 'https://github.com.evil.test/x',
                    'https://github.com@evil.test/x', 'https://127.0.0.1/x',
                    'https://github.com:8443/x'):
            with self.assertRaises(ValueError):
                validate_url(url)

    def test_download_hash_and_size(self):
        class Response(io.BytesIO):
            headers = {}
            def geturl(self):
                return 'https://github.com/a'
        class Opener:
            def open(self, *args, **kw):
                return Response(b'content')
        with tempfile.TemporaryDirectory() as tmp, patch('rex.provisioning.releases.urllib.request.build_opener', return_value=Opener()):
            p = Path(tmp) / 'file'
            digest = hashlib.sha256(b'content').hexdigest()
            self.assertEqual(download('https://github.com/a', p, digest, 10), digest)
            p.unlink()
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                download('https://github.com/a', p, '0' * 64, 10)
            self.assertFalse(p.exists())
            with self.assertRaisesRegex(ValueError, 'limit'):
                download('https://github.com/a', p, digest, 3)
            self.assertFalse(p.exists())

    def test_reject_archive_traversal_symlinks_and_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('../escape', '/absolute', 'C:/escape', 'a\\..\\escape'):
                archive = root / 'test.zip'
                with zipfile.ZipFile(archive, 'w') as z:
                    z.writestr(name, 'bad')
                out = root / ('out' + str(len(list(root.iterdir()))))
                out.mkdir()
                with self.assertRaises(ValueError):
                    extract_zip(archive, out)
            with zipfile.ZipFile(archive, 'w') as z:
                item = zipfile.ZipInfo('link')
                item.create_system = 3
                item.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(item, '../escape')
            out = root / 'symlink'; out.mkdir()
            with self.assertRaises(ValueError):
                extract_zip(archive, out)

    def test_plan_selects_release_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Provisioner(Path(tmp))
            engine.env.update(os='linux', arch='x86_64', package_managers=[])
            with patch.object(engine, 'inspect', return_value={'state': 'missing'}):
                plan = engine.plan(['vineflower'])
            self.assertEqual(plan[-1]['method']['kind'], 'release')
            self.assertEqual(plan[-1]['method']['format'], 'jar')

    def test_java_version_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Provisioner(Path(tmp))
            result = subprocess.CompletedProcess(['java'], 0, stdout='', stderr='openjdk version "17.0.11"')
            with patch('rex.provisioning.engine.shutil.which', return_value='/java'), patch('rex.provisioning.engine.subprocess.run', return_value=result):
                self.assertEqual(engine._java_version(), 17)

    def test_staged_install_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Provisioner(Path(tmp))
            release = p.specs['vineflower']['release']
            def fake_download(url, target, checksum, maximum):
                Path(target).write_bytes(b'jar')
            with patch.object(p, '_java_version', return_value=17), patch('rex.provisioning.engine.download', side_effect=fake_download), patch.object(p, '_verify_release', return_value={'state': 'verified'}):
                p._install_release('vineflower', release)
            self.assertTrue((p.root / 'vineflower' / 'vineflower.jar').is_file())
            p.uninstall('vineflower')
            with patch.object(p, '_java_version', return_value=17), patch('rex.provisioning.engine.download', side_effect=fake_download), patch.object(p, '_verify_release', return_value={'state': 'failed'}):
                with self.assertRaises(RuntimeError):
                    p._install_release('vineflower', release)
            self.assertFalse((p.root / 'vineflower').exists())
            self.assertEqual(list(p.root.iterdir()), [])


class MCPHealthTest(unittest.TestCase):
    def test_actual_handshake(self):
        code = '''import sys,json
for line in sys.stdin:
 m=json.loads(line)
 if m.get("method")=="initialize":
  print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":{"protocolVersion":"2024-11-05","capabilities":{}}}),flush=True)
 if m.get("method")=="tools/list":
  print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":{"tools":[{"name":"inspect"}]}}),flush=True)
'''
        result = verify_server({'mcp_config': {'command': sys.executable, 'args': ['-u', '-c', code]}}, timeout=3)
        self.assertEqual(result['state'], 'VERIFIED')
        self.assertEqual(result['tools'], ['inspect'])

    def test_dummy_is_not_verified_and_runners_not_started(self):
        dummy = verify_server({'mcp_config': {'command': sys.executable, 'args': ['-c', 'pass']}}, timeout=2)
        self.assertEqual(dummy['state'], 'FAILED')
        self.assertEqual(verify_server({'mcp_config': {'command': 'npx', 'args': ['-y', 'anything']}})['state'], 'UNSUPPORTED')
