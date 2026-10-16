"""Static guarantees: the package is receive-only and dependency-free."""

import ast
import os

import pytest

import quietwire

PKG_DIR = os.path.dirname(quietwire.__file__)
SEND_NAMES = {"send", "sendall", "sendto", "sendmsg", "sendfile", "send_bytes", "sendmmsg"}


def modules():
    for root, _dirs, files in os.walk(PKG_DIR):
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def test_no_transmit_calls_anywhere_in_the_package():
    offenders = []
    for path in modules():
        tree = ast.parse(open(path).read(), path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in SEND_NAMES:
                offenders.append("%s:%d %s" % (os.path.relpath(path, PKG_DIR), node.lineno, node.func.attr))
    assert not offenders, offenders


def test_raw_sockets_are_only_opened_in_the_live_capture_module():
    for path in modules():
        src = open(path).read()
        if "socket.socket(" in src or "AF_PACKET" in src:
            assert os.path.relpath(path, PKG_DIR) == os.path.join("capture", "live.py"), path


def test_only_standard_library_imports():
    import sys

    if not hasattr(sys, "stdlib_module_names"):  # Python < 3.10
        pytest.skip("sys.stdlib_module_names needs Python 3.10+")
    stdlib = set(sys.stdlib_module_names)
    third_party = set()
    for path in modules():
        for node in ast.walk(ast.parse(open(path).read())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            third_party |= {n for n in names if n not in stdlib and n != "quietwire"}
    assert not third_party, third_party


def test_no_dynamic_code_execution():
    banned = {"eval", "exec", "compile", "__import__"}
    for path in modules():
        for node in ast.walk(ast.parse(open(path).read())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
                raise AssertionError("%s:%d uses %s" % (path, node.lineno, node.func.id))
        assert "pickle" not in open(path).read().lower().replace("pickle-free", "")
