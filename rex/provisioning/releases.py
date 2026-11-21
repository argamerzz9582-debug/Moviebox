"""Bounded, pinned upstream release retrieval and safe ZIP extraction."""
import hashlib
import re
import stat
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ALLOWED_HOSTS = {'github.com', 'release-assets.githubusercontent.com'}


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS or
            parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443)):
        raise ValueError('Untrusted release URL or redirect')
    return url


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, target, expected_sha256, max_bytes, timeout=45):
    validate_url(url)
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('Missing or invalid pinned SHA-256')
    opener = urllib.request.build_opener(ReleaseRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'REX-provisioner/1'})
    digest = hashlib.sha256()
    count = 0
    try:
        with opener.open(request, timeout=timeout) as response, Path(target).open('xb') as out:
            validate_url(response.geturl())
            length = response.headers.get('Content-Length')
            if length is not None and int(length) > max_bytes:
                raise ValueError('Release exceeds download limit')
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > max_bytes:
                    raise ValueError('Release exceeds download limit')
                digest.update(block)
                out.write(block)
        if digest.hexdigest() != expected_sha256:
            raise ValueError('Release SHA-256 mismatch')
    except Exception:
        Path(target).unlink(missing_ok=True)
        raise
    return digest.hexdigest()


def extract_zip(archive, destination, max_uncompressed=2 * 1024 * 1024 * 1024, max_entries=100000):
    root = Path(destination).resolve()
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if len(infos) > max_entries or sum(i.file_size for i in infos) > max_uncompressed:
            raise ValueError('Archive exceeds extraction limits')
        seen = set()
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = info.external_attr >> 16
            if (not name or '\\' in name or name.startswith('/') or '..' in path.parts or
                    any(':' in part for part in path.parts) or stat.S_ISLNK(mode) or
                    (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError('Unsafe archive entry: ' + name)
            dest = root.joinpath(*path.parts)
            if dest in seen:
                raise ValueError('Duplicate archive entry: ' + name)
            seen.add(dest)
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, dest.open('xb') as out:
                    remaining = info.file_size
                    while remaining:
                        block = src.read(min(1024 * 1024, remaining))
                        if not block:
                            raise ValueError('Truncated archive entry')
                        out.write(block)
                        remaining -= len(block)
                dest.chmod(0o755 if mode & 0o111 else 0o644)
