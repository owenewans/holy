#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


report = Path(os.environ.get("REPORT", "out/hardware.json"))
scope = os.environ.get("HARDWARE_SCOPE", "holy")
result = {"schema": "holy-hardware-1", "scope": scope,
          "release_gate": scope == "holy", "checks": []}


def finish(status, message):
    result["status"] = "pass" if status == 0 else "missing-requirement" if status == 6 else "fail"
    result["message"] = message
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("holy-hardware: " + message, file=sys.stderr if status else sys.stdout)
    raise SystemExit(status)


def probe(name, argv, limit=15):
    start = time.monotonic()
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=limit)
    except subprocess.TimeoutExpired:
        result["checks"].append({"name": name, "argv": argv, "status": "fail", "reason": "timeout"})
        finish(1, name + " timed out")
    item = {"name": name, "argv": argv, "exit_code": completed.returncode,
            "seconds": round(time.monotonic() - start, 3),
            "stdout": completed.stdout[:16384], "stderr": completed.stderr[:4096]}
    result["checks"].append(item)
    return completed, item


if scope not in ("holy", "host"):
    finish(2, "HARDWARE_SCOPE must be holy or host")
release_file = Path("/etc/os-release")
release_lines = release_file.read_text().splitlines() if release_file.is_file() else []
result["host_os"] = next((line.split("=", 1)[1].strip().strip('"')
                          for line in release_lines
                          if line.startswith("ID=")), "unknown")
if scope == "holy":
    if not Path("/var/lib/holypkg/installed").is_dir():
        finish(6, "installed Holy database required; host probe uses HARDWARE_SCOPE=host")
    manager = shutil.which("holypkg")
    if not manager:
        finish(6, "installed holypkg required")
    state, item = probe("installed-state", [manager, "db", "status", "--root", "/", "--json"])
    if state.returncode:
        item["status"] = "fail"
        finish(6, "installed Holy database unavailable")
    item["status"] = "pass"

required = ("lspci", "vulkaninfo", "vkcube", "glxinfo", "glxgears", "timeout")
missing = [name for name in required if not shutil.which(name)]
if missing:
    finish(6, "required tools missing: " + ", ".join(missing))
if not os.environ.get("DISPLAY"):
    finish(6, "DISPLAY required for OpenGL presentation probe")
render_nodes = sorted(Path("/dev/dri").glob("renderD*"))
if not any(os.access(path, os.R_OK | os.W_OK) for path in render_nodes):
    finish(6, "accessible DRM render node required")
result["render_nodes"] = [str(path) for path in render_nodes]

pci, item = probe("nouveau-kernel", ["lspci", "-nnk", "-d", "10de:"])
gpu_blocks = re.split(r"(?=^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7] )", pci.stdout, flags=re.M)
if pci.returncode or not any(("VGA compatible controller" in block or "3D controller" in block)
                             and "Kernel driver in use: nouveau" in block for block in gpu_blocks):
    item["status"] = "fail"
    finish(1, "NVIDIA GPU bound to nouveau not found")
item["status"] = "pass"

vulkan, item = probe("vulkan-nvk", ["vulkaninfo", "--summary"])
devices = re.finditer(r"^GPU(\d+):\s*\n(.*?)(?=^GPU\d+:|\Z)", vulkan.stdout, flags=re.M | re.S)
gpu = next((int(match.group(1)) for match in devices
            if re.search(r"^\s*vendorID\s*=\s*0x10de\s*$", match.group(2), flags=re.M)
            and re.search(r"^\s*driverID\s*=\s*DRIVER_ID_MESA_NVK\s*$", match.group(2), flags=re.M)), None)
if vulkan.returncode or gpu is None:
    item["status"] = "fail"
    finish(1, "Mesa NVK Vulkan device not found")
item["status"] = "pass"
result["vulkan_gpu_index"] = gpu

wsi = "wayland" if os.environ.get("WAYLAND_DISPLAY") else "xlib"
cube, item = probe("vulkan-present", ["vkcube", "--gpu_number", str(gpu), "--wsi", wsi,
                                       "--c", "30", "--width", "320", "--height", "240"], 20)
cube_log = cube.stdout + cube.stderr
if cube.returncode or f"Selected GPU {gpu}:" not in cube_log or "NVK" not in cube_log:
    item["status"] = "fail"
    finish(1, "NVK presentation probe failed")
item["status"] = "pass"

gl, item = probe("opengl-context", ["glxinfo", "-B"])
renderer = re.search(r"^OpenGL renderer string:\s*(.+)$", gl.stdout, flags=re.M)
if gl.returncode or "direct rendering: Yes" not in gl.stdout or "Accelerated: yes" not in gl.stdout or \
        "(0x10de)" not in gl.stdout or not renderer or \
        any(name in renderer.group(1).lower() for name in ("llvmpipe", "softpipe")):
    item["status"] = "fail"
    finish(1, "accelerated NVIDIA OpenGL context not found")
item["status"] = "pass"
result["opengl_renderer"] = renderer.group(1)

gears, item = probe("opengl-present", ["timeout", "8", "glxgears", "-geometry", "320x240"], 12)
frames = re.search(r"(\d+) frames in [\d.]+ seconds = ([\d.]+) FPS", gears.stdout)
if gears.returncode != 124 or not frames or int(frames.group(1)) < 1 or float(frames.group(2)) <= 0:
    item["status"] = "fail"
    finish(1, "OpenGL presentation probe produced no measured frames")
item["status"] = "pass"
result["opengl_frames"] = int(frames.group(1))
result["opengl_fps"] = float(frames.group(2))
finish(0, "Nouveau/NVK and OpenGL presentation probes passed (" + scope + ")")
