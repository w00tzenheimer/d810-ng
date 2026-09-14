"""Execute release workflow scripts against isolated source/receipt fixtures."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _script(workflow: str, step: str) -> str:
    text = (ROOT / '.github/workflows' / workflow).read_text()
    marker = f'- name: {step}\n'
    assert marker in text, f'Missing {step} step'
    section = text.split(marker, 1)[1].split('\n            - ', 1)[0]
    lines = section.split('run: |\n', 1)[1].splitlines()
    body = []
    for line in lines:
        if line.strip() and not line.startswith('                  '):
            break
        body.append(line)
    return textwrap.dedent('\n'.join(body)).replace('python -', f'{shlex.quote(sys.executable)} -')


def _run(workflow, step, tmp_path, **env):
    return subprocess.run(
        ['bash', '-eu', '-o', 'pipefail', '-c', _script(workflow, step)],
        cwd=tmp_path,
        env={**os.environ, 'GITHUB_OUTPUT': str(tmp_path / 'outputs'), **env},
        text=True, capture_output=True,
    )


@pytest.mark.parametrize(('version', 'expected'), [('1.0.0b2', 'true'), ('1.0.0rc1', 'true'), ('1.0.0', 'false')])
def test_release_receipt_records_checked_out_commit_and_pep440_prerelease(tmp_path, version, expected):
    source = tmp_path / 'src/d810'
    source.mkdir(parents=True)
    (source / '__init__.py').write_text(f'__version__ = {version!r}\n')
    for command in (
        ['git', 'init', '-q'], ['git', 'add', 'src'],
        ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'fixture'],
        ['git', 'tag', f'v{version}'],
    ):
        subprocess.run(command, cwd=tmp_path, check=True)
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=tmp_path, text=True).strip()
    result = _run('release.yml', 'Record release source', tmp_path, RELEASE_TAG=f'v{version}')
    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / '.release-source/receipt.json').read_text()) == {'tag': f'v{version}', 'sha': sha}
    assert f'prerelease={expected}' in (tmp_path / 'outputs').read_text()
    assert 'prerelease: ${{ steps.source.outputs.prerelease }}' in (ROOT / '.github/workflows/release.yml').read_text()


def test_workflow_run_resolves_receipt_not_default_branch_sha(tmp_path):
    (tmp_path / '.release-source').mkdir()
    sha = 'a' * 40
    (tmp_path / '.release-source/receipt.json').write_text(json.dumps({'tag': 'v1.0.0b2', 'sha': sha}))
    result = _run('deploy.yml', 'Resolve source', tmp_path, EVENT_NAME='workflow_run', EVENT_SHA='b' * 40)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'outputs').read_text().strip() == f'sha={sha}'


@pytest.mark.parametrize('event', ['workflow_dispatch', 'release'])
def test_direct_deploy_uses_event_sha(tmp_path, event):
    result = _run('deploy.yml', 'Resolve source', tmp_path, EVENT_NAME=event, EVENT_SHA='c' * 40)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'outputs').read_text().strip() == f'sha={"c" * 40}'


@pytest.mark.parametrize('receipt', [{'tag': 'v1.0.0b2', 'sha': 'main'}, {'tag': 'v1.0.0\ninjected=true', 'sha': 'a' * 40}, {'sha': 'a' * 40}])
def test_invalid_receipt_fails_closed(tmp_path, receipt):
    (tmp_path / '.release-source').mkdir()
    (tmp_path / '.release-source/receipt.json').write_text(json.dumps(receipt))
    result = _run('deploy.yml', 'Resolve source', tmp_path, EVENT_NAME='workflow_run', EVENT_SHA='b' * 40)
    assert result.returncode != 0
    assert not (tmp_path / 'outputs').exists()


def test_deploy_gates_upstream_success_and_exact_repository_and_run():
    text = (ROOT / '.github/workflows/deploy.yml').read_text()
    build = text.split('    build_wheels:', 1)[1].split('        strategy:', 1)[0]
    assert "github.event.workflow_run.conclusion == 'success'" in build
    assert 'github.event.workflow_run.head_repository.full_name == github.repository' in build
    assert 'run-id: ${{ github.event.workflow_run.id }}' in text
    assert 'repository: ${{ github.repository }}' in text
    assert 'ref: ${{ steps.source.outputs.sha }}' in text
    assert 'needs: [build_wheels]' in text


@pytest.mark.parametrize('tag', ['v1.0.0b1', 'main', 'v1.0.0b2\nsha=injected'])
def test_release_rejects_wrong_version_or_malformed_tag_before_receipt(tmp_path, tag):
    source = tmp_path / 'src/d810'
    source.mkdir(parents=True)
    (source / '__init__.py').write_text('__version__ = "1.0.0b2"\n')
    result = _run('release.yml', 'Record release source', tmp_path, RELEASE_TAG=tag)
    assert result.returncode != 0
    assert not (tmp_path / '.release-source/receipt.json').exists()


def test_release_rejects_tag_on_different_commit(tmp_path):
    source = tmp_path / 'src/d810'
    source.mkdir(parents=True)
    (source / '__init__.py').write_text('__version__ = "1.0.0b2"\n')
    for command in (
        ['git', 'init', '-q'], ['git', 'add', 'src'],
        ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'tagged'],
        ['git', 'tag', 'v1.0.0b2'],
        ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '--allow-empty', '-qm', 'different head'],
    ):
        subprocess.run(command, cwd=tmp_path, check=True)
    result = _run('release.yml', 'Record release source', tmp_path, RELEASE_TAG='v1.0.0b2')
    assert result.returncode != 0
    assert 'Release tag does not match checked-out commit' in result.stderr
    assert not (tmp_path / '.release-source/receipt.json').exists()


@pytest.mark.parametrize('requested', ['v1.0.0b2', 'refs/tags/v1.0.0b2'])
def test_manual_release_tag_overrides_default_branch(tmp_path, requested):
    result = _run('release.yml', 'Resolve tag', tmp_path, EVENT_NAME='workflow_dispatch', REQUESTED_TAG=requested, CURRENT_REF='refs/heads/main')
    assert result.returncode == 0, result.stderr
    assert 'ref=refs/tags/v1.0.0b2' in (tmp_path / 'outputs').read_text()


def test_missing_workflow_run_receipt_fails_closed(tmp_path):
    result = _run('deploy.yml', 'Resolve source', tmp_path, EVENT_NAME='workflow_run', EVENT_SHA='b' * 40)
    assert result.returncode != 0
    assert not (tmp_path / 'outputs').exists()
