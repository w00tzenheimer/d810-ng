"""Run bounded DAC and positive native shadow legs with unchanged admission.

This does not qualify the whole catalogue and does not activate canonical mode.
Use the maintained Docker runner; all live databases remain on native storage.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

# Direct script execution does not put the repository root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.bench.canonical_dac_probe import (
    NODE, POSITIVE_NODE, PROJECT, combine_evidence, validate_run, write_json, workload_segments,
)


def main():
    if not Path('/app/ida').is_dir():
        raise RuntimeError('Use maintained IDA Docker runner')
    root = Path.cwd()
    diagnostic = os.environ.get('D810_CANONICAL_DAC_WITNESSES') == '1'
    segments = workload_segments(diagnostic=diagnostic)
    output = root / '.tmp/canonical-dac-qualification' / os.environ['D810_RUN_ID']
    output.mkdir(parents=True, exist_ok=False)
    native = Path('/work/runs') / os.environ['D810_RUN_ID'] / 'canonical-dac-state'
    native.mkdir(parents=True, exist_ok=False)
    options = Path.home() / '.idapro/cfg/d810/options.json'
    initial = options.read_bytes() if options.exists() else None
    config = json.loads(initial) if initial else {}
    config['log_dir'] = str(native)
    options.parent.mkdir(parents=True, exist_ok=True)
    options.write_text(json.dumps(config))
    paths = ['samples/bins/libobfuscated.dll', 'src/d810/conf/' + PROJECT,
        'src/d810/backends/mba/ida.py', 'src/d810/mba/certified_catalogue.py',
        'src/d810/backends/mba/hexrays_island.py',
        'src/d810/ir/expr/dsl.py', 'src/d810/ir/expr/constraints.py',
        'src/d810/mba/canonical_pattern.py', 'src/d810/runtime_semantics_manifest.json',
        'src/d810/hexrays/hooks/optinsn_adapter.py',
        'src/d810/mba/rules/_base.py', 'src/d810/mba/rules/cst.py',
        'src/d810/mba/rules/predicates.py',
        'tests/system/e2e/test_canonical_reference_qualification.py',
        'src/d810/optimizers/microcode/instructions/pattern_matching/handler.py',
        'src/d810/manager/state.py', 'tools/bench/canonical_dac_probe.py',
        'tools/bench/canonical_dac_qualification.py']
    manifest = {'scope': ('XOR mismatch diagnosis only; no certificate'
        if diagnostic else 'DAC plus positive XOR under one catalogue; not per-rule empirical qualification'),
        'nodes': [node for _, node in segments], 'project': PROJECT,
        'sources': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in paths}}
    write_json(output / 'workload.json', manifest)
    env = dict(os.environ)
    for name in ('D810_CANONICAL_MATCH_FALLBACK', 'D810_STRUCTURAL_DSL_MATCHING'):
        env.pop(name, None)
    env.update(D810_LEGACY_DSL_PERMUTATIONS='1', D810_SHADOW_DSL_MATCHING='1')
    process = {'environment': {k: v for k, v in env.items() if k.startswith('D810_')},
               'exit': None, 'scope': manifest['scope']}
    write_json(output / 'shadow-process.json', process)
    stamp = time.perf_counter()
    try:
        receipts = []
        for segment_id, node in segments:
            segment = output / segment_id
            segment.mkdir()
            segment_env = env | {'D810_CANONICAL_DAC_OUT': str(segment / 'shadow.json'),
                                 'IDALOG': str(segment / 'ida.log')}
            command = [sys.executable, '-u', '-m', 'pytest', '-p', 'no:cacheprovider',
                       '-p', 'tools.bench.canonical_dac_probe', node,
                       '-q', '-s', '-o', 'addopts=']
            segment_process = {'segment_id': segment_id, 'command': command,
                'environment': {k: v for k, v in segment_env.items() if k.startswith('D810_')},
                'exit': None}
            write_json(segment / 'process.json', segment_process)
            segment_start = time.perf_counter()
            with (segment / 'pytest.log').open('w') as log:
                result = subprocess.run(command, env=segment_env, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=900)
            segment_process.update(exit=result.returncode,
                                   process_seconds=time.perf_counter() - segment_start)
            write_json(segment / 'process.json', segment_process)
            receipt = json.loads((segment / 'shadow.json').read_text())
            receipt.update(exit=result.returncode, segment_id=segment_id)
            validate_run(receipt)
            receipts.append(receipt)
        selected = combine_evidence(receipts)
        runtime = selected['toolchain']['matcher_backend']['backend']
        evidence = {'schema_version': 1, 'runtime_mode': runtime,
            'snapshot': selected['snapshot'], 'ledger': selected['ledger'],
            'coverage_limit': manifest['scope'], 'segments': selected['segments'],
            'enrollment': selected['enrollment'],
            'canonical_status_by_rule_width': selected['canonical_status_by_rule_width'],
            'snapshot_widths': selected['snapshot_widths'],
            'legacy_only_observation_count': selected['legacy_only_observation_count'],
            'legacy_only_match_count': selected['legacy_only_match_count']}
        write_json(output / 'evidence.json', evidence)
        write_json(output / 'toolchain.json', selected['toolchain'])
        if diagnostic:
            write_json(output / 'admission.json', {'admitted': False,
                'reason': 'diagnostic_only', 'scope': manifest['scope']})
            process.update(exit=0, process_seconds=time.perf_counter() - stamp)
            write_json(output / 'shadow-process.json', process)
            print('Diagnostic witnesses captured; certificate admission not attempted.', flush=True)
            return
        tool = root / 'tools/scripts/mba_structural_matcher_certificate.py'
        spec = importlib.util.spec_from_file_location('dac_certificate_tool', tool)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        certificate = module.build_certificate(evidence, manifest=output / 'workload.json',
                                               toolchain=output / 'toolchain.json')
        write_json(output / 'certificate.json', certificate)
        write_json(output / 'admission.json', {'admitted': True, 'scope': manifest['scope'],
            'next': 'Fresh-process activation and matched measurement still required.'})
        process.update(exit=0, process_seconds=time.perf_counter() - stamp)
        write_json(output / 'shadow-process.json', process)
        print('Bounded shadow evidence accepted by unchanged certificate builder.', flush=True)
    except BaseException as exc:
        process['error'] = repr(exc)
        process['process_seconds'] = time.perf_counter() - stamp
        write_json(output / 'shadow-process.json', process)
        write_json(output / 'admission.json', {'admitted': False, 'error': repr(exc),
                                            'scope': manifest['scope']})
        raise
    finally:
        if initial is not None:
            options.write_bytes(initial)
        elif options.exists():
            options.unlink()


if __name__ == '__main__':
    main()
