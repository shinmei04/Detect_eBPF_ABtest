#!/usr/bin/env python3
"""Transfer the current research source plus Git history; never run experiments."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import tarfile
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(root), *args])


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def build(root: Path, output: Path) -> None:
    root, output = root.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(root):
        raise ValueError('Use a new archive path outside the repository')
    # Explicit source scope: no captures, result directories, environments or secrets.
    directories = {'src', 'scripts', 'tests', 'configs', 'docs', 'mininet_experiment'}
    extensions = {'.py', '.md', '.json', '.sh', '.txt'}
    roots = {'.gitignore', 'AGENTS.md', 'README.md', 'RESEARCH_LOG.md',
             'EXPERIMENT_PLAN.md', 'NOVELTY_NOTES.md', 'main.py',
             'requirements.txt', 'requirements-replay.txt'}
    listing = git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    selected = []
    for rel in sorted(set(listing) - {''}):
        p = PurePosixPath(rel)
        if rel not in roots and not (p.parts[0] in directories and p.suffix in extensions):
            continue
        if '__pycache__' in p.parts or any(part.startswith('.') for part in p.parts[:-1]):
            continue
        source = root / rel
        if not source.is_file() or source.is_symlink():
            raise ValueError(f'Missing or symlink source requires review: {rel}')
        selected.append(rel)
    required = roots | {'docs/current_phase.md', 'docs/research_direction.md',
                        'docs/research_log.md', 'docs/experiment_plan.md', 'scripts/smoke_replay.py'}
    if not required.issubset(selected):
        raise ValueError(f'Missing required files: {sorted(required - set(selected))}')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='research-export-', dir=output.parent) as tmp:
        package = Path(tmp) / 'research-handoff'
        package.mkdir()
        for rel in selected:
            dest = package / 'source' / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / rel, dest)
        git(root, 'bundle', 'create', str(package / 'repository.bundle'), 'HEAD')
        write_json(package / 'origin.json', {
            'base_commit': git(root, 'rev-parse', 'HEAD').decode().strip(),
            'working_tree_status': git(root, 'status', '--short').decode(),
            'snapshot_kind': 'working tree including uncommitted and untracked source',
            'scope': 'P1-G0 offline replay; real-data experiment remains DRAFT',
            'source_files': selected,
        })
        (package / 'working_tree.diff').write_bytes(git(root, 'diff', '--binary', 'HEAD'))
        shutil.copy2(Path(__file__), package / 'restore.py')
        (package / 'README.md').write_text(
            '# Research handoff\n\n'
            'See [handoff instructions](source/docs/HANDOFF.md).\n\n'
            'Restore from this directory into a NEW destination on Linux:\n\n'
            '```sh\npython3 restore.py restore --destination ../implementation --machine-role experiment\n```\n\n'
            'Then read implementation/AGENTS.md and implementation/docs/HANDOFF.md.\n'
            'Real-data evaluation remains DRAFT. No experiment runs during restoration.\n'
        )
        hashes = {str(p.relative_to(package)): digest(p) for p in sorted(package.rglob('*')) if p.is_file()}
        write_json(package / 'SHA256SUMS.json', hashes)
        with output.open('xb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as archive:
            archive.add(package, arcname='research-handoff')
    print(json.dumps({'archive': str(output), 'sha256': digest(output), 'source_files': len(selected)}))


def restore(package: Path, destination: Path, role: str) -> None:
    package, destination = package.resolve(), destination.resolve()
    if destination.exists():
        raise ValueError('Destination must not exist; existing work will never be overwritten')
    if role == 'experiment' and platform.system() != 'Linux':
        raise ValueError('Experiment role requires an actual Linux experiment PC')
    hashes = json.loads((package / 'SHA256SUMS.json').read_text())
    actual = {str(p.relative_to(package)) for p in package.rglob('*') if p.is_file()}
    if actual != set(hashes) | {'SHA256SUMS.json'}:
        raise ValueError('Package has missing or unexpected files')
    for rel, expected in hashes.items():
        p = PurePosixPath(rel)
        source = package / rel
        if p.is_absolute() or '..' in p.parts or source.is_symlink() or not source.resolve().is_relative_to(package):
            raise ValueError(f'Invalid package path: {rel}')
        if digest(source) != expected:
            raise ValueError(f'Checksum mismatch: {rel}')
    origin = json.loads((package / 'origin.json').read_text())
    for rel in origin['source_files']:
        p = PurePosixPath(rel)
        if p.is_absolute() or '..' in p.parts or '.git' in p.parts or 'source/' + rel not in hashes:
            raise ValueError(f'Invalid source path: {rel}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'clone', str(package / 'repository.bundle'), str(destination)], check=True)
    # No stale local export path is left as a push/pull remote.
    git(destination, 'remote', 'remove', 'origin')
    git(destination, 'switch', '-c', 'handoff-work')
    if git(destination, 'rev-parse', 'HEAD').decode().strip() != origin['base_commit']:
        raise ValueError('Restored Git commit differs from recorded commit')
    for rel in origin['source_files']:
        dest = destination / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(package / 'source' / rel, dest)
        if digest(dest) != hashes['source/' + rel]:
            raise ValueError(f'Restored source mismatch: {rel}')
    write_json(destination / 'machine_role.local.json', {'role': role})
    shutil.copy2(package / 'origin.json', destination / 'handoff_origin.json')
    shutil.copy2(package / 'SHA256SUMS.json', destination / 'handoff_sha256.json')
    print(f'Restored and verified {len(origin["source_files"])} source files in {destination}')
    print('No experiment executed. Read AGENTS.md and docs/HANDOFF.md next.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build_parser = sub.add_parser('build')
    build_parser.add_argument('--output', type=Path, required=True)
    restore_parser = sub.add_parser('restore')
    restore_parser.add_argument('--destination', type=Path, required=True)
    restore_parser.add_argument('--machine-role', choices=['implementation', 'experiment'], required=True)
    args = parser.parse_args()
    if args.command == 'build':
        build(Path(__file__).resolve().parents[1], args.output)
    else:
        restore(Path(__file__).resolve().parent, args.destination, args.machine_role)


if __name__ == '__main__':
    main()
