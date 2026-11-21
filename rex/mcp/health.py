"""Explicit, time-limited MCP stdio handshake and tool discovery."""
import json
import queue
import shutil
import subprocess
import threading
import time


def verify_server(server, timeout=10):
    config = server.get('mcp_config', {})
    command = config.get('command', '')
    args = config.get('args', [])
    if command in ('npx', 'uvx'):
        return {'state': 'UNSUPPORTED', 'detail': 'Package runners may download code; automatic execution is disabled'}
    executable = shutil.which(command) if isinstance(command, str) else None
    if not executable:
        return {'state': 'MISSING_DEPENDENCIES', 'detail': 'Server executable not found'}
    if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
        return {'state': 'FAILED', 'detail': 'Invalid server arguments'}
    process = None
    messages = queue.Queue(maxsize=100)
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen([executable, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def reader():
            while True:
                line = process.stdout.readline(1024 * 1024 + 1)
                if not line or len(line) > 1024 * 1024:
                    break
                try:
                    messages.put_nowait(json.loads(line))
                except (ValueError, queue.Full):
                    break
            try:
                messages.put_nowait(None)
            except queue.Full:
                pass
        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        def send(obj):
            process.stdin.write((json.dumps(obj) + '\n').encode('utf-8'))
            process.stdin.flush()
        def receive(id):
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('MCP handshake timed out')
                try:
                    message = messages.get(timeout=remaining)
                except queue.Empty:
                    raise TimeoutError('MCP handshake timed out')
                if message is None:
                    raise ValueError('MCP server exited or sent invalid output')
                if isinstance(message, dict) and message.get('id') == id:
                    if 'error' in message or not isinstance(message.get('result'), dict):
                        raise ValueError('MCP server returned an error or invalid result')
                    return message['result']
        send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'rex-health', 'version': '1.0'}}})
        init = receive(1)
        if not isinstance(init.get('protocolVersion'), str) or not isinstance(init.get('capabilities'), dict):
            raise ValueError('Invalid MCP initialize response')
        send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        result = receive(2)
        tools = result.get('tools')
        if not isinstance(tools, list) or any(not isinstance(t, dict) or not isinstance(t.get('name'), str) for t in tools):
            raise ValueError('Invalid MCP tool list')
        return {'state': 'VERIFIED', 'protocol_version': init['protocolVersion'], 'tools': [t['name'] for t in tools], 'detail': 'Stdio handshake and first tools/list page succeeded; backend functionality is not tested'}
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as exc:
        return {'state': 'FAILED', 'detail': str(exc)}
    finally:
        if process:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            for stream in (process.stdin, process.stdout):
                if stream:
                    stream.close()
