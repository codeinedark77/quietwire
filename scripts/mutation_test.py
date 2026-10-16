#!/usr/bin/env python3
"""Small AST-based mutation tester (no dependencies) for quietwire's critical modules.

It applies ONE mutation at a time to a copy of the package (comparison/boolean/arithmetic
operators, integer and boolean constants, ``not``), runs the relevant test files, and reports
which mutants *survived* (no test failed). Survivors are either equivalent mutants or gaps in
the tests; ``--show`` prints them with source lines for triage.

    python scripts/mutation_test.py proto/modbus.py --budget 240 [--seed 1] [--start 0] [--show]

Mutants are visited in a seeded random order so that partial runs (``--budget`` seconds) are an
unbiased sample; ``--start N`` continues where a previous run stopped.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

TESTS = {
    "proto/modbus.py": ["tests/test_modbus.py", "tests/test_modbus_boundaries.py", "tests/test_validation_matrix.py", "tests/test_identify.py",
                        "tests/test_engine.py", "tests/test_rules.py"],
    "proto/dnp3.py": ["tests/test_dnp3.py", "tests/test_dnp3_tables.py", "tests/test_validation_matrix.py", "tests/test_rules.py"],
    "proto/s7comm.py": ["tests/test_s7comm.py", "tests/test_s7_tables.py", "tests/test_s7commplus.py", "tests/test_validation_matrix.py",
                        "tests/test_rules.py"],
    "proto/iec104.py": ["tests/test_iec104.py", "tests/test_iec104_tables.py", "tests/test_identify.py"],
    "net/reassembly.py": ["tests/test_reassembly.py", "tests/test_tcp_hardening.py", "tests/test_engine.py"],
    "net/fragments.py": ["tests/test_tunnels_fragments.py"],
    "net/decode.py": ["tests/test_decode.py", "tests/test_tunnels_fragments.py", "tests/test_validation_matrix.py",
                      "tests/test_tcp_hardening.py"],
    "detect/policy.py": ["tests/test_policy.py", "tests/test_functions_policy.py", "tests/test_rules.py"],
    "detect/rules.py": ["tests/test_rules.py", "tests/test_engine.py", "tests/test_functions_policy.py",
                        "tests/test_iec104.py"],
    "report/auditlog.py": ["tests/test_auditlog.py", "tests/test_multifile_keyed.py"],
}

CMP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.LtE: ast.Gt, ast.Gt: ast.LtE, ast.GtE: ast.Lt,
       ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In}
BIN = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.BitAnd: ast.BitOr, ast.BitOr: ast.BitAnd, ast.LShift: ast.RShift,
       ast.RShift: ast.LShift, ast.Mod: ast.Mult, ast.FloorDiv: ast.Mult}


def sites(tree):
    """Deterministically enumerate mutable nodes: list of (kind, lineno, description)."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in CMP:
            out.append(("cmp", node.lineno, "%s -> %s" % (type(node.ops[0]).__name__, CMP[type(node.ops[0])].__name__)))
        elif isinstance(node, ast.BoolOp):
            out.append(("bool", node.lineno, "%s -> %s" % (type(node.op).__name__,
                                                          "Or" if isinstance(node.op, ast.And) else "And")))
        elif isinstance(node, ast.BinOp) and type(node.op) in BIN:
            out.append(("bin", node.lineno, "%s -> %s" % (type(node.op).__name__, BIN[type(node.op)].__name__)))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            out.append(("not", node.lineno, "not x -> x"))
        elif isinstance(node, ast.Constant) and type(node.value) is bool:
            out.append(("bconst", node.lineno, "%s -> %s" % (node.value, not node.value)))
        elif isinstance(node, ast.Constant) and type(node.value) is int:
            out.append(("iconst", node.lineno, "%d -> %d" % (node.value, node.value + 1)))
        elif isinstance(node, ast.AugAssign) and type(node.op) in (ast.Add, ast.Sub):
            out.append(("aug", node.lineno, "%s= -> %s=" % (type(node.op).__name__, BIN[type(node.op)].__name__)))
    return out


def mutate(tree, index):
    tree = copy.deepcopy(tree)
    i = -1
    for node in ast.walk(tree):
        ok = False
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in CMP:
            ok = True
        elif isinstance(node, ast.BoolOp) or (isinstance(node, ast.BinOp) and type(node.op) in BIN):
            ok = True
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            ok = True
        elif isinstance(node, ast.Constant) and type(node.value) in (bool, int):
            ok = True
        elif isinstance(node, ast.AugAssign) and type(node.op) in (ast.Add, ast.Sub):
            ok = True
        if not ok:
            continue
        i += 1
        if i != index:
            continue
        if isinstance(node, ast.Compare):
            node.ops[0] = CMP[type(node.ops[0])]()
        elif isinstance(node, ast.BoolOp):
            node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        elif isinstance(node, ast.BinOp):
            node.op = BIN[type(node.op)]()
        elif isinstance(node, ast.AugAssign):
            node.op = BIN[type(node.op)]()
        elif isinstance(node, ast.UnaryOp):
            node.op, node.operand = ast.UAdd(), node.operand  # `not x` -> `+x` (truthiness preserved, negation removed)
            return _replace_not(tree, node)
        elif isinstance(node, ast.Constant):
            node.value = (not node.value) if type(node.value) is bool else node.value + 1
        return tree
    raise IndexError(index)


def _replace_not(tree, target):
    class T(ast.NodeTransformer):
        def visit_UnaryOp(self, node):
            self.generic_visit(node)
            return node.operand if node is target else node

    return ast.fix_missing_locations(T().visit(tree))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module", choices=sorted(TESTS))
    ap.add_argument("--budget", type=float, default=240.0, help="stop starting new mutants after N seconds")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--limit", type=int, default=0, help="max mutants this run (0 = unlimited)")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--out", default="/tmp/mutation_results.jsonl")
    args = ap.parse_args()

    src_file = os.path.join(ROOT, "src", "quietwire", args.module)
    source = open(src_file).read()
    tree = ast.parse(source)
    all_sites = sites(tree)
    order = list(range(len(all_sites)))
    random.Random(args.seed).shuffle(order)

    work = tempfile.mkdtemp(prefix="qwmut_")
    shutil.copytree(os.path.join(ROOT, "src"), os.path.join(work, "src"), ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(work, "tests"), ignore=shutil.ignore_patterns("__pycache__"))
    target = os.path.join(work, "src", "quietwire", args.module)
    tests = [t for t in TESTS[args.module]]
    t0 = time.time()
    killed = survived = timeouts = 0
    survivors = []
    done = 0
    for n, idx in enumerate(order):
        if n < args.start:
            continue
        if time.time() - t0 > args.budget or (args.limit and done >= args.limit):
            break
        kind, line, desc = all_sites[idx]
        mutated = ast.unparse(ast.fix_missing_locations(mutate(tree, idx)))
        with open(target, "w") as fh:
            fh.write(mutated)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        status = "survived"
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
                                   *tests], cwd=work, env=env, capture_output=True, text=True, timeout=60)
            status = "killed" if proc.returncode != 0 else "survived"
        except subprocess.TimeoutExpired:
            status = "timeout"
        done += 1
        if status == "survived":
            survived += 1
            survivors.append((line, desc, source.splitlines()[line - 1].strip()))
        else:
            killed += 1
            timeouts += status == "timeout"
        with open(args.out, "a") as fh:
            fh.write(json.dumps({"module": args.module, "seed": args.seed, "n": n, "line": line, "desc": desc,
                                 "status": status}) + "\n")
    shutil.rmtree(work, ignore_errors=True)
    total = killed + survived
    print("%s: tested %d of %d mutants (next --start %d): killed %d (%d by timeout), survived %d -> score %.1f%%"
          % (args.module, total, len(all_sites), args.start + done, killed, timeouts, survived,
             100.0 * killed / total if total else 0.0))
    if args.show:
        for line, desc, text in sorted(survivors):
            print("  line %d: %-22s %s" % (line, desc, text[:110]))


if __name__ == "__main__":
    main()
