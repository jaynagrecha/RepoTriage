from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx

LOG = logging.getLogger(__name__)

DEFAULT_MODEL = 'gpt-4o-mini'
MAX_CODE_CHARS = int(os.getenv('SEMANTIC_LLM_MAX_CODE_CHARS', '12000'))
TIMEOUT = float(os.getenv('SEMANTIC_LLM_TIMEOUT', '45'))


def llm_configured() -> bool:
    if os.getenv('SEMANTIC_LLM_ENABLED', 'true').lower() in {'0', 'false', 'no', 'off'}:
        return False
    provider = (os.getenv('SEMANTIC_LLM_PROVIDER') or 'openai').lower()
    if provider == 'openai':
        return bool(os.getenv('OPENAI_API_KEY'))
    if provider == 'anthropic':
        return bool(os.getenv('ANTHROPIC_API_KEY'))
    return False


def _model_name() -> str:
    provider = (os.getenv('SEMANTIC_LLM_PROVIDER') or 'openai').lower()
    if provider == 'anthropic':
        return os.getenv('ANTHROPIC_MODEL', 'claude-sonnet-4-20250514')
    return os.getenv('OPENAI_MODEL', DEFAULT_MODEL)


def _build_prompt(
    semantic: dict[str, Any],
    *,
    filename: str,
    sample_text: str,
) -> tuple[str, str]:
    caps = semantic.get('capabilities') or []
    cap_lines = [
        f"- {c.get('id')}: {c.get('label')} (evidence: {'; '.join(c.get('evidence') or [])[:120]})"
        for c in caps
    ]
    functions = semantic.get('functions') or []
    fn_lines = [
        f"- {f.get('name')}({', '.join(f.get('args') or [])})"
        for f in functions[:10]
    ]
    code_excerpt = (sample_text or '')[:MAX_CODE_CHARS]

    system = (
        'You are a senior malware triage analyst. You receive structured capability facts extracted '
        'deterministically from a file (AST, imports, regex). Your job is to write a clear, accurate '
        'analyst-facing interpretation.\n\n'
        'Rules:\n'
        '1. Ground every claim in the provided capabilities, functions, and code excerpt — do not invent IOCs, '
        'C2, or network behavior unless capability facts support it.\n'
        '2. Distinguish dual-use security tooling from outright malware.\n'
        '3. If capabilities show no network_http, do not claim network exfiltration or C2.\n'
        '4. If capabilities show no subprocess_exec/dynamic_exec, do not claim execution of payloads.\n'
        '5. Respond with JSON only — no markdown fences.\n'
        '6. Keep summary to 2-4 sentences. what_it_does: 2-5 bullet strings.\n'
        '7. threat_category must be one of: malware, abuse_tool, dual_use_security_tool, unknown.'
    )

    user = (
        f'Filename: {filename}\n'
        f'Language: {semantic.get("language")}\n'
        f'Entry point: {semantic.get("entry_point")}\n'
        f'Deterministic rule matched: {semantic.get("purpose_rule_id") or "none (composed)"}\n'
        f'Data flow: {semantic.get("data_flow") or "unknown"}\n'
        f'Deterministic title: {semantic.get("behavior_title")}\n'
        f'Deterministic summary: {semantic.get("summary")}\n\n'
        f'Capabilities:\n{chr(10).join(cap_lines) or "- none"}\n\n'
        f'Functions:\n{chr(10).join(fn_lines) or "- none"}\n\n'
        f'Code excerpt:\n```\n{code_excerpt}\n```\n\n'
        'Return JSON:\n'
        '{"behavior_title":"...","summary":"...","what_it_does":["..."],"threat_category":"...",'
        '"recommended_action":"...","confidence":"high|medium|low"}'
    )
    return system, user


def _parse_llm_json(content: str) -> dict[str, Any]:
    text = (content or '').strip()
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError('LLM response is not a JSON object')
    return parsed


def _validate_llm_output(parsed: dict[str, Any], semantic: dict[str, Any]) -> dict[str, Any]:
    cap_ids = {c.get('id') for c in (semantic.get('capabilities') or [])}
    summary = str(parsed.get('summary') or '')
    lower = summary.lower()

    network_claim = bool(re.search(r'\b(?:c2|command.?and.?control|exfil|beacon|callback)\b', lower))
    if network_claim and 'network_http' not in cap_ids and 'webhook_exfil' not in cap_ids:
        raise ValueError('LLM claimed network/C2 behavior not supported by capabilities')

    exec_claim = bool(re.search(r'\b(?:executes? payload|drops? malware|remote code execution)\b', lower))
    if exec_claim and not (cap_ids & {'subprocess_exec', 'dynamic_exec', 'download_remote'}):
        raise ValueError('LLM claimed execution behavior not supported by capabilities')

    category = str(parsed.get('threat_category') or 'unknown')
    if category not in {'malware', 'abuse_tool', 'dual_use_security_tool', 'unknown'}:
        category = semantic.get('threat_category') or 'unknown'

    confidence = str(parsed.get('confidence') or 'medium')
    if confidence not in {'high', 'medium', 'low'}:
        confidence = semantic.get('confidence') or 'medium'

    bullets = parsed.get('what_it_does') or []
    if not isinstance(bullets, list):
        bullets = [str(bullets)]
    bullets = [str(b).strip() for b in bullets if str(b).strip()][:6]

    return {
        'behavior_title': str(parsed.get('behavior_title') or semantic.get('behavior_title') or '')[:120],
        'summary': summary[:1200],
        'what_it_does': bullets,
        'threat_category': category,
        'recommended_action': str(parsed.get('recommended_action') or semantic.get('recommended_action') or '')[:600],
        'confidence': confidence,
    }


async def _call_openai(system: str, user: str) -> str:
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY not configured')
    model = _model_name()
    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
        'temperature': 0.2,
        'response_format': {'type': 'json_object'},
    }
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(
            'https://api.openai.com/v1/chat/completions',
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        return data['choices'][0]['message']['content']


async def _call_anthropic(system: str, user: str) -> str:
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        raise RuntimeError('ANTHROPIC_API_KEY not configured')
    model = _model_name()
    payload = {
        'model': model,
        'max_tokens': 1024,
        'system': system,
        'messages': [{'role': 'user', 'content': user}],
        'temperature': 0.2,
    }
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(
            'https://api.anthropic.com/v1/messages',
            headers={
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json',
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        parts = data.get('content') or []
        return ''.join(p.get('text', '') for p in parts if p.get('type') == 'text')


async def enrich_semantic_with_llm(
    semantic: dict[str, Any],
    *,
    filename: str,
    sample_text: str,
) -> dict[str, Any]:
    """Optional LLM narrative layer grounded on deterministic capability facts."""
    out = dict(semantic)
    if not llm_configured():
        out['llm'] = {'status': 'disabled', 'reason': 'no API key or SEMANTIC_LLM_ENABLED=false'}
        return out

    provider = (os.getenv('SEMANTIC_LLM_PROVIDER') or 'openai').lower()
    model = _model_name()
    try:
        system, user = _build_prompt(out, filename=filename, sample_text=sample_text)
        if provider == 'anthropic':
            raw = await _call_anthropic(system, user)
        else:
            raw = await _call_openai(system, user)
        parsed = _parse_llm_json(raw)
        validated = _validate_llm_output(parsed, out)

        out['llm'] = {
            'status': 'ok',
            'provider': provider,
            'model': model,
            'grounded_on': 'semantic_capabilities',
        }
        out['behavior_title'] = validated['behavior_title'] or out.get('behavior_title')
        out['summary'] = validated['summary'] or out.get('summary')
        out['what_it_does'] = validated['what_it_does'] or out.get('what_it_does')
        out['threat_category'] = validated['threat_category']
        out['recommended_action'] = validated['recommended_action'] or out.get('recommended_action')
        out['confidence'] = validated['confidence']
        if validated['confidence'] == 'high':
            out['confidence_score'] = max(int(out.get('confidence_score') or 0), 72)
        elif validated['confidence'] == 'medium':
            out['confidence_score'] = max(int(out.get('confidence_score') or 0), 48)
        out['inference_method'] = f"{out.get('inference_method', 'capability')}+llm"
        return out
    except Exception as exc:
        LOG.warning('semantic LLM enrichment failed: %s', exc)
        out['llm'] = {
            'status': 'error',
            'provider': provider,
            'model': model,
            'error': str(exc)[:240],
        }
        return out
