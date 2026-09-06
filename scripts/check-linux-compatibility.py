#!/usr/bin/env python3
"""Reject release binaries with a newer ABI than the Ubuntu 22.04 baseline."""
import pathlib
import re
import subprocess
import sys

baseline = (2, 35)
directory = pathlib.Path(sys.argv[1])
for name in ("nodewe", "node-runtime", "node-control-plane"):
    binary = directory / name
    header = subprocess.check_output(["readelf", "-h", str(binary)], text=True)
    if "ELF64" not in header or "Advanced Micro Devices X86-64" not in header:
        raise SystemExit(f"{name}: expected Linux x86_64 ELF")
    versions = subprocess.check_output(
        ["readelf", "--version-info", "--wide", str(binary)], text=True
    )
    requirements = {
        tuple(map(int, value.split(".")))
        for value in re.findall(r"GLIBC_(\d+\.\d+(?:\.\d+)?)", versions)
    }
    if not requirements or "GLIBC_PRIVATE" in versions:
        raise SystemExit(f"{name}: missing or unsupported GLIBC version metadata")
    maximum = max(requirements)
    if maximum > baseline:
        raise SystemExit(f"{name}: requires GLIBC {maximum}, exceeds {baseline}")
    print(f"{name}: x86_64 ELF, highest required GLIBC {'.'.join(map(str, maximum))}")
