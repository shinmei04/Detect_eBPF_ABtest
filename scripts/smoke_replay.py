#!/usr/bin/env python3
"""Short offline acceptance check. Synthetic data, no packets sent."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = [
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
        [sys.executable, 'scripts/make_research_fixture.py', '--output-dir', str(output/'fixture'),
         '--peak-rate-mbps', '0.05', '--window-sec', '0.025', '--step-sec', '0.025'],
        [sys.executable, 'scripts/analyze_research.py', '--config', str(output/'fixture/config.json'),
         '--output-dir', str(output/'analysis')],
    ]
    report = {'synthetic': True, 'python': sys.version, 'platform': platform.platform(),
              'cwd': str(root), 'commands': [], 'status': 'RUNNING'}
    def save() -> None:
        (output/'acceptance.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    save()
    for i, command in enumerate(commands):
        with (output/f'{i+1:02d}.log').open('w') as log:
            result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        report['commands'].append({'argv': command, 'returncode': result.returncode, 'log': f'{i+1:02d}.log'})
        if result.returncode:
            report['status'] = 'FAILED'
            save()
            raise SystemExit(f'Failed; inspect {output/f"{i+1:02d}.log"}')
        save()
    expected = ['config.json','provenance.json','source.diff','training_windows.csv','metrics.csv','metrics.json','COMPLETED']
    missing = [p for p in expected if not (output/'analysis'/p).is_file()]
    if missing:
        report.update(status='FAILED', missing=missing)
        save()
        raise SystemExit(f'Missing analysis files: {missing}')
    provenance=json.loads((output/'analysis/provenance.json').read_text())
    report.update(status='PASSED', numpy=provenance['numpy'], pandas=provenance['pandas'],
                  limitation='Synthetic offline smoke only; no real capture, network, plotting or performance validation')
    save()
    (output/'SMOKE_PASSED').write_text('Offline synthetic acceptance passed. Research hypothesis remains untested.\n')
    print(f'PASS: {output}/acceptance.json')


if __name__ == '__main__':
    main()
