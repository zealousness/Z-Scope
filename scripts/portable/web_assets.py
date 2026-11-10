"""Maintain pinned, locally served WebUI assets; no Node.js is shipped.

Run --update explicitly to download upstream assets and regenerate Tailwind CSS.
Normal release builds only verify the committed files against their SHA-256 lock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VENDOR = Path("zscope/web/static/vendor")
LOCK = Path("requirements/portable/web-assets.lock.json")
FIRST_PARTY = ("index.html", "offline_template.html")
SOURCES = {
    "tailwind-cli": (
        "3.4.17",
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64",
    ),
    "tailwind.LICENSE": (
        "3.4.17",
        "https://raw.githubusercontent.com/tailwindlabs/tailwindcss/v3.4.17/LICENSE",
    ),
    "daisyui.css": ("4.4.19", "https://cdn.jsdelivr.net/npm/daisyui@4.4.19/dist/full.css"),
    "daisyui.LICENSE": ("4.4.19", "https://cdn.jsdelivr.net/npm/daisyui@4.4.19/LICENSE"),
    "alpine.js": ("3.14.9", "https://cdn.jsdelivr.net/npm/alpinejs@3.14.9/dist/cdn.min.js"),
    "alpine.LICENSE": (
        "3.14.9",
        "https://raw.githubusercontent.com/alpinejs/alpine/v3.14.9/LICENSE.md",
    ),
    "prism.css": (
        "1.29.0",
        "https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css",
    ),
    "prism.js": ("1.29.0", "https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"),
    "prism-c.js": (
        "1.29.0",
        "https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-c.min.js",
    ),
    "prism-cpp.js": (
        "1.29.0",
        "https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-cpp.min.js",
    ),
    "prism-java.js": (
        "1.29.0",
        "https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-java.min.js",
    ),
    "markdown-it.js": (
        "14.1.1",
        "https://cdn.jsdelivr.net/npm/markdown-it@14.1.1/dist/markdown-it.min.js",
    ),
    "markdown-it.LICENSE": ("14.1.1", "https://cdn.jsdelivr.net/npm/markdown-it@14.1.1/LICENSE"),
    "js-yaml.js": ("4.1.1", "https://cdn.jsdelivr.net/npm/js-yaml@4.1.1/dist/js-yaml.min.js"),
    "js-yaml.LICENSE": ("4.1.1", "https://cdn.jsdelivr.net/npm/js-yaml@4.1.1/LICENSE"),
    "fflate.js": ("0.8.2", "https://cdn.jsdelivr.net/npm/fflate@0.8.2/umd/index.js"),
    "fflate.LICENSE": ("0.8.2", "https://cdn.jsdelivr.net/npm/fflate@0.8.2/LICENSE"),
    "prism.LICENSE": ("1.29.0", "https://cdn.jsdelivr.net/npm/prismjs@1.29.0/LICENSE"),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root=ROOT):
    lock = json.loads((root / LOCK).read_text())
    for name, entry in lock["files"].items():
        if Path(name).name != name or digest(root / VENDOR / name) != entry["sha256"]:
            raise ValueError(f"WebUI asset differs from its lock: {name}")
    for name in FIRST_PARTY:
        expected = lock.get("first_party", {}).get(name, {}).get("sha256")
        if digest(root / VENDOR.parent / name) != expected:
            raise ValueError(f"WebUI application asset differs from its lock: {name}")
    return lock


def update(root=ROOT):
    destination = root / VENDOR
    destination.mkdir(parents=True, exist_ok=True)
    lock = {"schema_version": "zscope.web-assets.v1", "inputs": {}, "files": {}}
    # A maintainer-only compiler creates static CSS. It is never installed in
    # the Python package or in a portable archive.
    with tempfile.TemporaryDirectory(prefix="zscope-web-assets-") as directory:
        temporary = Path(directory)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({})
            if os.environ.get("ZSCOPE_DOWNLOAD_DIRECT") == "1"
            else urllib.request.ProxyHandler()
        )
        for name, (version, url) in SOURCES.items():
            print("Fetching WebUI input:", name, flush=True)
            target = temporary / name if name == "tailwind-cli" else destination / name
            with opener.open(url, timeout=120) as response, target.open("wb") as output:
                expected = int(response.headers.get("Content-Length", 0))
                shutil.copyfileobj(response, output, 1024 * 1024)
            if expected and target.stat().st_size != expected:
                raise OSError("Truncated WebUI input: " + name)
            entry = {"version": version, "url": url, "sha256": digest(target), "license": "MIT"}
            lock["inputs"][name] = entry
            if name != "tailwind-cli":
                lock["files"][name] = entry
        compiler = temporary / "tailwind-cli"
        compiler.chmod(0o755)
        css = temporary / "input.css"
        css.write_text("@tailwind base;\n@tailwind components;\n@tailwind utilities;\n")
        subprocess.run(
            [
                str(compiler),
                "--input",
                str(css),
                "--content",
                str(root / "zscope/web/static/index.html"),
                "--output",
                str(destination / "tailwind.css"),
                "--minify",
            ],
            check=True,
            cwd=temporary,
            env=dict(os.environ, BROWSERSLIST_IGNORE_OLD_DATA="true"),
        )
        lock["files"]["tailwind.css"] = {
            "version": "3.4.17",
            "generated_from": "tailwind-cli",
            "license": "MIT",
            "sha256": digest(destination / "tailwind.css"),
        }
    lock["first_party"] = {
        name: {"sha256": digest(root / VENDOR.parent / name), "license": "MIT"}
        for name in FIRST_PARTY
    }
    (root / LOCK).write_text(json.dumps(lock, indent=2) + "\n")
    verify(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    update() if args.update else verify()
