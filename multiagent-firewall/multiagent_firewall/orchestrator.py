from __future__ import annotations

import json
import importlib
import logging
from typing import cast, Any, Callable
from functools import partial
from pathlib import Path

from langgraph.graph import END, StateGraph

from .config.env import GuardConfig
from .config.registry import NODE_REGISTRY, ROUTER_REGISTRY
from .types import GuardState
from .utils import debug_ainvoke

logger = logging.getLogger(__name__)


class GuardOrchestrator:
    """Orchestrates the sensitive data detection pipeline."""

    def __init__(self, config: GuardConfig) -> None:
        self._config = config
        self._graph = self._build_graph()

    async def run(
        self,
        text: str | None = None,
        *,
        file_paths: list[str] | None = None,
        min_block_level: str | None = None,
    ) -> GuardState:
        """
        Run the detection pipeline.

        Args:
            text: Direct text input
            file_paths: List of file paths to process (can be single file in list)
            min_block_level: Minimum risk level ("none", "low", "medium", "high") required to trigger blocking actions

        Returns:
            GuardState with detection results
        """
        initial_state: GuardState = {
            "raw_text": text or "",
            "file_paths": file_paths if file_paths else None,
            "min_block_level": _normalize_risk(min_block_level),
            "llm_provider": self._config.llm.provider,
            "force_llm_detector": self._config.force_llm_detector,
            "metadata": {},
            "warnings": [],
            "errors": [],
            "decision": "allow",
            "risk_level": "none",
        }
        if self._config.debug:
            return await debug_ainvoke(self._graph, initial_state)
        return cast(GuardState, await self._graph.ainvoke(initial_state))

    def _build_graph(self):
        graph = StateGraph(GuardState)
        config_data = self._load_pipeline_config()

        # Add Nodes
        for node in config_data.get("nodes", []):
            node_id = node["id"]
            action_name = node["action"]
            inject_config = node.get("inject_config", False)
            params = node.get("params", {})

            func = self._resolve_action(action_name, NODE_REGISTRY)

            if inject_config:
                func = partial(func, fw_config=self._config)

            if params:
                func = partial(func, **params)

            graph.add_node(node_id, func)

        # Add Edges
        for edge in config_data.get("edges", []):
            target = edge["target"]
            if target == "__end__":
                target = END
            graph.add_edge(edge["source"], target)

        # Add Conditional Edges
        for edge in config_data.get("conditional_edges", []):
            router_name = edge["router"]
            router_func = self._resolve_action(router_name, ROUTER_REGISTRY)
            graph.add_conditional_edges(edge["source"], router_func)

        # Set Entry Point
        entry_point = config_data.get("entry_point")
        if entry_point:
            if (
                isinstance(entry_point, dict)
                and entry_point.get("type") == "conditional"
            ):
                router_name = entry_point["router"]
                router_func = self._resolve_action(router_name, ROUTER_REGISTRY)
                graph.set_conditional_entry_point(router_func)
            elif isinstance(entry_point, str):
                graph.set_entry_point(entry_point)

        return graph.compile()

    def _load_pipeline_config(self) -> dict[str, Any]:
        p = Path(__file__).parent / "config" / "pipeline.json"
        if not p.exists():
            raise FileNotFoundError(f"Pipeline config not found at {p}")
        with open(p, "r") as f:
            return json.load(f)

    def _resolve_action(self, name: str, registry: dict[str, Callable]) -> Callable:
        if name in registry:
            return registry[name]

        # Dynamic import attempt
        try:
            module_path, func_name = name.rsplit(".", 1)
            mod = importlib.import_module(module_path)
            return getattr(mod, func_name)
        except (ValueError, ImportError, AttributeError) as e:
            raise ValueError(f"Could not resolve action '{name}': {e}")


def _normalize_risk(value: str | None) -> str:
    allowed = {"none", "low", "medium", "high"}
    if value is None:
        return "low"
    normalized = value.strip().lower()
    if normalized not in allowed:
        return "low"
    return normalized
