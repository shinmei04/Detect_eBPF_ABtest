#!/usr/bin/env python3
"""Run existing offline evaluations with immutable output directories and provenance."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys

from analyze import validate_outputs

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = Path(__file__).resolve().parent
ENTRIES = {
    "synthetic_smoke": {"scripts/run_paper_reproduction_experiment.py"},
    "synthetic_evaluation": {"scripts/run_paper_reproduction_experiment.py", "scripts/run_detector_experiment.py"},
    "saved_pcap_evaluation": {"exp/detector_25ms_20260714/run.py"},
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_profile(path: Path) -> dict:
    profile = json.loads(path.read_text(encoding="utf-8"))
    required = {"schema_version", "kind", "entry", "args", "expected_outputs"}
    if set(profile) != required or profile["schema_version"] != 1:
        raise ValueError("profile must use schema_version 1 and exactly the documented fields")
    if profile["entry"] not in ENTRIES.get(profile["kind"], set()):
        raise ValueError("unsupported offline entry/kind combination")
    args = profile["args"]
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError("args must be a list of CLI tokens")
    # argparse accepts abbreviated options: reject every output/run-id prefix too.
    for token in args:
        option = token.split("=", 1)[0]
        if option.startswith("--") and any(x.startswith(option) for x in ("--output-dir", "--run-id")):
            raise ValueError("output location/run-id is controlled by the harness")
    outputs = profile["expected_outputs"]
    if not isinstance(outputs, list) or not outputs:
        raise ValueError("expected_outputs must be a nonempty list")
    for name in outputs:
        if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("expected outputs must stay inside payload")
    return profile


def source_files() -> list[Path]:
    paths = []
    for folder in ("src", "scripts", "tests", "exp", "mininet_experiment", "experiments", "configs"):
        for path in (ROOT / folder).rglob("*"):
            if any(x in path.parts for x in ("out", "archive_unused", "__pycache__")):
                continue
            if path.is_file() and path.suffix in (".py", ".sh", ".c", ".json", ".yaml", ".toml"):
                paths.append(path)
    paths.extend(ROOT / name for name in ("main.py", "requirements.txt", "AGENTS.md"))
    return sorted(set(paths))


def input_files(profile: dict) -> list[Path]:
    if profile["kind"] != "saved_pcap_evaluation":
        return []
    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump is required for the saved-pcap profile")
    # Read CaseSpec from its authoritative module; do not duplicate archived paths.
    path = ROOT / "exp/detector_25ms_20260714/analyze.py"
    spec = importlib.util.spec_from_file_location("harness_saved_pcap", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    specs = [module.TRAINING_SPEC, *module.EVALUATION_SPECS]
    module.validate_inputs(specs)
    paths = [ROOT / item for case in specs for item in (case.pcap, case.metadata)]
    comparison = ROOT / "experiments/main_ldos_tcp6m/detector_results/detector_summary_periodic.csv"
    if comparison.is_file():
        paths.append(comparison)
    return paths


def reserve_output(parent: Path, run_id: str) -> Path:
    if not re.fullmatch(r"[0-9]{8}_[0-9]{6}", run_id):
        raise ValueError("run-id must be YYYYMMDD_HHMMSS")
    datetime.strptime(run_id, "%Y%m%d_%H%M%S")
    parent.mkdir(parents=True, exist_ok=True)
    output = parent / run_id
    output.mkdir(exist_ok=False)  # Atomic reservation; never resume or reuse.
    return output


def git_output(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--profile", default="smoke", choices=sorted(p.stem for p in (ROOT / "configs").glob("*.json")))
    parser.add_argument("--dry-run", action="store_true", help="Validate inputs and print command without creating outputs")
    parser.add_argument("--run-id", help="Optional YYYYMMDD_HHMMSS; existing IDs are rejected")
    args = parser.parse_args()
    config_path = ROOT / "configs" / f"{args.profile}.json"
    profile = load_profile(config_path)
    inputs = input_files(profile)
    run_id = args.run_id or datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    if not re.fullmatch(r"[0-9]{8}_[0-9]{6}", run_id):
        raise ValueError("run-id must be YYYYMMDD_HHMMSS")
    datetime.strptime(run_id, "%Y%m%d_%H%M%S")
    output = EXPERIMENT / "out" / run_id
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to reuse output: {output}")
    command = [sys.executable, str(ROOT / profile["entry"]), *profile["args"], "--output-dir", str(output / "payload")]
    print(f"PROFILE={args.profile} KIND={profile['kind']}", flush=True)
    print(shlex.join(command), flush=True)
    if args.dry_run:
        print(f"DRY_RUN: checked {len(inputs)} input files; no evaluation or output writes")
        return 0
    output = reserve_output(EXPERIMENT / "out", run_id)
    manifest = {
        "profile_name": args.profile, "profile": profile, "command": command,
        "cwd": str(ROOT), "started_at": datetime.now().astimezone().isoformat(),
        "python": sys.version, "executable": sys.executable, "platform": platform.platform(),
        "status": "running", "inputs_sha256": {},
    }
    manifest_path = output / "manifest.json"

    def save_manifest():
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    save_manifest()
    try:
        manifest["git_head"] = git_output("rev-parse", "HEAD")
        manifest["git_status"] = git_output("status", "--short")
        manifest["config_sha256"] = sha256(config_path)
        manifest["source_sha256"] = {str(p.relative_to(ROOT)): sha256(p) for p in source_files()}
        manifest["inputs_sha256"] = {str(p.relative_to(ROOT)): sha256(p) for p in inputs}
        (output / "config.json").write_text(config_path.read_text(), encoding="utf-8")
        from importlib.metadata import version
        manifest["package_versions"] = {name: version(name) for name in ("numpy", "pandas", "matplotlib", "scikit-learn")}
        if inputs:
            manifest["tcpdump_version"] = subprocess.check_output(["tcpdump", "--version"], text=True).strip()
        save_manifest()
        environment = dict(os.environ, MPLBACKEND="Agg", PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
        with (output / "execution.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
        manifest["returncode"] = result.returncode
        if result.returncode:
            raise RuntimeError(f"evaluation exited {result.returncode}; see {output / 'execution.log'}")
        validate_outputs(output / "payload", profile["expected_outputs"])
        changed = [name for name, digest in manifest["inputs_sha256"].items() if sha256(ROOT / name) != digest]
        if changed:
            raise RuntimeError(f"input files changed during evaluation: {changed}")
        changed_sources = [name for name, digest in manifest["source_sha256"].items() if sha256(ROOT / name) != digest]
        if changed_sources:
            raise RuntimeError(f"source files changed during evaluation: {changed_sources}")
        manifest["output_sha256"] = {str(p.relative_to(output)): sha256(p) for p in sorted((output / "payload").rglob("*")) if p.is_file()}
        manifest["status"] = "succeeded"
        return 0
    except BaseException as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        manifest["finished_at"] = datetime.now().astimezone().isoformat()
        save_manifest()
        print(f"OUTPUT_DIR={output}", flush=True)
        print(f"STATUS={manifest['status']}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
