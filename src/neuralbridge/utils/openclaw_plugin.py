"""
NeuralBridge OpenClaw Integration Helper.

Provides utilities for:
* Generating OpenClaw-compatible skill YAML from adapter configs.
* Auto-discovering a running NeuralBridge instance from OpenClaw.
* Translating OpenClaw action schemas to NeuralBridge adapter calls.

Usage from OpenClaw
-------------------
1. Copy ``examples/openclaw/neuralbridge_skill.yaml`` into your OpenClaw
   skills directory.
2. Set ``NEURALBRIDGE_URL`` in your environment.
3. OpenClaw will auto-discover all registered adapters as available tools.
"""

from __future__ import annotations

from typing import Any

import yaml


def generate_skill_yaml(
    adapters: list[dict[str, Any]],
    neuralbridge_url: str = "http://localhost:8000",
) -> str:
    """
    Generate an OpenClaw-compatible skill YAML from registered adapters.

    Parameters
    ----------
    adapters : list[dict]
        List of adapter metadata dicts (name, description, input_schema).
    neuralbridge_url : str
        Base URL of the NeuralBridge instance.

    Returns
    -------
    str
        YAML string ready to be saved as an OpenClaw skill file.
    """
    tools = []
    for adapter in adapters:
        tools.append({
            "name": f"neuralbridge_{adapter['name']}",
            "description": adapter.get("description", f"NeuralBridge {adapter['name']} adapter"),
            "parameters": adapter.get("input_schema", {}),
            "endpoint": f"{neuralbridge_url}/api/v1/adapters/{adapter['name']}/execute",
        })

    skill = {
        "name": "NeuralBridge Enterprise Middleware",
        "version": "0.1.0",
        "description": (
            "Universal adapter layer — connect to Salesforce, SAP, Gmail, Slack, "
            "databases, and 50+ enterprise systems through NeuralBridge."
        ),
        "author": "NeuralBridge Contributors",
        "server": {
            "url": neuralbridge_url,
            "transport": "streamable_http",
            "auth": {"type": "bearer", "token": "${NEURALBRIDGE_API_KEY}"},
        },
        "tools": tools,
    }
    return str(yaml.dump(skill, default_flow_style=False, sort_keys=False))


def translate_openclaw_action(action: dict[str, Any]) -> dict[str, Any]:
    """
    Translate an OpenClaw action payload into a NeuralBridge adapter call.

    Parameters
    ----------
    action : dict
        OpenClaw action with ``tool_name`` and ``parameters``.

    Returns
    -------
    dict
        NeuralBridge-formatted request body.
    """
    tool_name = action.get("tool_name", "")
    # Strip the "neuralbridge_" prefix if present
    adapter_name = tool_name.removeprefix("neuralbridge_")

    return {
        "adapter": adapter_name,
        "operation": action.get("parameters", {}).get("operation", "execute"),
        "params": action.get("parameters", {}),
    }
