"""
conftest.py -- pytest plugin for per-test OLED screenshot directories.

When KEEPKEY_SCREENSHOT=1, patches KeepKeyTest.setUp to set per-test
screenshot directories BEFORE setUp runs (so wipe_device captures go
to the right place).

FAIL-FAST: If KEEPKEY_SCREENSHOT=1 and zero PNGs are captured after
all tests complete, the session exits non-zero. This prevents silent
screenshot pipeline failures from going unnoticed.
"""
import pytest
import os
import glob
import ipaddress
import socket
import sys
from urllib.parse import urlparse

import requests

if os.environ.get('KEEPKEY_SCREENSHOT') == '1':
    import common

    _orig_setUp = common.KeepKeyTest.setUp

    def _patched_setUp(self):
        # Derive per-test screenshot directory BEFORE setUp runs,
        # so captures during wipe_device/load_device go to the right place.
        test_id = self.id()
        # pytest: "tests.test_msg_wipedevice.TestDeviceWipe.test_wipe_device"
        # unittest: "test_msg_wipedevice.TestDeviceWipe.test_wipe_device"
        # Extract module basename and test method name
        parts = test_id.split('.')
        test_name = parts[-1] if parts else 'unknown'
        # Find the module part (starts with test_msg_)
        module = 'unknown'
        for p in parts:
            if p.startswith('test_msg_') or p.startswith('test_sign_') or p.startswith('test_verify_'):
                module = p.replace('test_', '', 1)  # strip first test_ only
                break
        screenshot_dir = os.path.join(
            os.environ.get('SCREENSHOT_DIR', 'screenshots'),
            module, test_name
        )
        os.makedirs(screenshot_dir, exist_ok=True)

        # Now run original setUp (creates client, calls wipe_device)
        _orig_setUp(self)

        # Set screenshot dir on the client that setUp just created
        if hasattr(self, 'client') and self.client:
            self.client.screenshot_dir = screenshot_dir
            self.client.screenshot_id = 0

    common.KeepKeyTest.setUp = _patched_setUp


def _is_loopback_address(address):
    """Allow emulator traffic while rejecting every external destination."""
    if not isinstance(address, tuple):
        # Unix-domain sockets are local by construction.
        return True
    host = address[0]
    if isinstance(host, bytes):
        host = host.decode('ascii')
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except (TypeError, ValueError):
        return False


@pytest.fixture(autouse=True)
def deny_external_network(monkeypatch, request):
    """Fail an authoritative test at its first non-loopback network access."""
    nodeid = request.node.nodeid
    original_getaddrinfo = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_request = requests.sessions.Session.request

    def denied(destination):
        raise AssertionError(
            'authoritative test attempted external network access: '
            'test=%s destination=%r' % (nodeid, destination))

    def guarded_getaddrinfo(host, *args, **kwargs):
        if not _is_loopback_address((host, 0)):
            denied(host)
        return original_getaddrinfo(host, *args, **kwargs)

    def guarded_connect(sock, address):
        if not _is_loopback_address(address):
            denied(address)
        return original_connect(sock, address)

    def guarded_connect_ex(sock, address):
        if not _is_loopback_address(address):
            denied(address)
        return original_connect_ex(sock, address)

    def guarded_sendto(sock, data, *args):
        address = args[-1]
        if not _is_loopback_address(address):
            denied(address)
        return original_sendto(sock, data, *args)

    def guarded_request(session, method, url, *args, **kwargs):
        hostname = urlparse(url).hostname
        if not _is_loopback_address((hostname, 0)):
            raise AssertionError(
                'authoritative test attempted HTTP access: test=%s method=%s '
                'url=%s' % (nodeid, method, url))
        return original_request(session, method, url, *args, **kwargs)

    monkeypatch.setattr(socket, 'getaddrinfo', guarded_getaddrinfo)
    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)
    monkeypatch.setattr(socket.socket, 'connect_ex', guarded_connect_ex)
    monkeypatch.setattr(socket.socket, 'sendto', guarded_sendto)
    monkeypatch.setattr(requests.sessions.Session, 'request', guarded_request)


def pytest_sessionfinish(session, exitstatus):
    """Fail-fast: if screenshots were requested but none captured, fail the session."""
    if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
        return
    screenshot_dir = os.environ.get('SCREENSHOT_DIR', 'screenshots')
    pngs = glob.glob(os.path.join(screenshot_dir, '**', '*.png'), recursive=True)
    count = len(pngs)
    if count == 0:
        print("FATAL: KEEPKEY_SCREENSHOT=1 but 0 PNGs captured. Screenshot pipeline is broken.", file=sys.stderr)
        session.exitstatus = 1
    else:
        print("[SCREENSHOT] Session complete: %d PNGs captured" % count, file=sys.stderr)
