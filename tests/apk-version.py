#!/usr/bin/env python3
import subprocess
import sys

binary = sys.argv[1]
pairs = [
    ("1", "1.0", "<"), ("1.0", "1.0.0", "<"),
    ("1.01", "1.1", "<"), ("1.02", "1.2", "<"),
    ("1.2a", "1.2", ">"), ("1.2a", "1.2b", "<"),
    ("1.2a", "1.2.1", "<"),
    ("1.2_alpha", "1.2_beta", "<"),
    ("1.2_beta", "1.2_pre", "<"),
    ("1.2_pre", "1.2_rc", "<"),
    ("1.2_rc", "1.2", "<"),
    ("1.2", "1.2_cvs", "<"),
    ("1.2_cvs", "1.2_svn", "<"),
    ("1.2_svn", "1.2_git", "<"),
    ("1.2_git", "1.2_hg", "<"),
    ("1.2_hg", "1.2_p", "<"),
    ("1.2_rc", "1.2_rc0", "<"),
    ("1.2_p", "1.2_p0", "<"),
    ("1.2_p1", "1.2_p2", "<"),
    ("1.2", "1.2-r0", "<"),
    ("1.2-r0", "1.2-r1", "<"),
    ("1.2-r01", "1.2-r1", "="),
]
for left, right, expected in pairs:
    for a, b, sign in ((left, right, expected),
                       (right, left, {"<": ">", ">": "<", "=": "="}[expected])):
        result = subprocess.run([binary, a, b], capture_output=True, text=True)
        assert result.returncode == 0 and result.stdout.strip() == sign, (a, b, result)
for invalid in ("1.2~abc", "1.2_foo", "1.2-rc1", "1.2-r", "", "1.2.3.4" * 9000):
    result = subprocess.run([binary, invalid, "1.2"], capture_output=True)
    assert result.returncode == 3, (invalid[:40], result)
print("APK v2 version fixtures passed")
