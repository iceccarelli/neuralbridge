"""
NeuralBridge Token Estimator — Cost Prediction Before Execution.

AI agent operations can be expensive.  OpenClaw instances have been
reported to cost $800–$1 500/month in API fees.  The token estimator
helps teams:

* **Predict** the token count of a request *before* it is sent.
* **Estimate** the dollar cost using a configurable pricing table.
* **Warn** when a single operation exceeds a cost threshold.
* **Track** cumulative spend across adapters and users.

The estimator uses ``tiktoken`` for accurate GPT-family tokenisation and
falls back to a character-based heuristic for other models.

Usage::

    estimator = TokenEstimator()
    report = estimator.estimate_cost("Summarise this 10-page PDF ...", model="gpt-4o")
    if report.exceeds_threshold:
        logger.warning("cost_threshold_exceeded", cost=report.estimated_cost_usd)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Model Pricing Table (USD per 1 000 tokens) ──────────────
# Prices as of early 2026 — update as vendors change pricing.

MODEL_PRICING: dict[str, dict[str, float]] = {
    "gpt-4o": {"input": 0.0025, "output": 0.0100},
    "gpt-4o-mini": {"input": 0.000150, "output": 0.000600},
    "gpt-4-turbo": {"input": 0.0100, "output": 0.0300},
    "gpt-4": {"input": 0.0300, "output": 0.0600},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "claude-3-opus": {"input": 0.0150, "output": 0.0750},
    "claude-3-sonnet": {"input": 0.0030, "output": 0.0150},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-3.5-sonnet": {"input": 0.0030, "output": 0.0150},
    "gemini-1.5-pro": {"input": 0.00125, "output": 0.00500},
    "gemini-1.5-flash": {"input": 0.000075, "output": 0.000300},
}

DEFAULT_COST_THRESHOLD_USD = 0.50  # Warn if a single call exceeds this


@dataclass
class CostReport:
    """
    Detailed cost estimate for a single operation.

    Attributes
    ----------
    input_tokens : int
        Estimated input token count.
    output_tokens : int
        Estimated output token count (based on heuristic ratio).
    model : str
        Model used for pricing lookup.
    input_cost_usd : float
        Estimated cost of input tokens.
    output_cost_usd : float
        Estimated cost of output tokens.
    estimated_cost_usd : float
        Total estimated cost.
    exceeds_threshold : bool
        True if the estimate exceeds the configured warning threshold.
    threshold_usd : float
        The threshold that was checked.
    timestamp : datetime
        When the estimate was generated.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    model: str = "gpt-4o"
    input_cost_usd: float = 0.0
    output_cost_usd: float = 0.0
    estimated_cost_usd: float = 0.0
    exceeds_threshold: bool = False
    threshold_usd: float = DEFAULT_COST_THRESHOLD_USD
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "model": self.model,
            "input_cost_usd": round(self.input_cost_usd, 6),
            "output_cost_usd": round(self.output_cost_usd, 6),
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "exceeds_threshold": self.exceeds_threshold,
            "threshold_usd": self.threshold_usd,
            "timestamp": self.timestamp.isoformat(),
        }


class TokenEstimator:
    """
    Estimate token counts and costs for AI operations.

    Parameters
    ----------
    cost_threshold_usd : float
        Per-operation cost threshold that triggers a warning.
    output_ratio : float
        Heuristic ratio of output tokens to input tokens (default 0.5).
    pricing : dict | None
        Custom pricing table; defaults to ``MODEL_PRICING``.
    """

    def __init__(
        self,
        cost_threshold_usd: float = DEFAULT_COST_THRESHOLD_USD,
        output_ratio: float = 0.5,
        pricing: dict[str, dict[str, float]] | None = None,
    ) -> None:
        self._threshold = cost_threshold_usd
        self._output_ratio = output_ratio
        self._pricing = pricing or MODEL_PRICING
        self._encoder: Any = None  # Lazy-loaded tiktoken encoder
        self._cumulative_cost: float = 0.0
        self._cumulative_tokens: int = 0

    # ── Token Counting ───────────────────────────────────────

    def estimate_tokens(self, text: str, model: str = "gpt-4o") -> int:
        """
        Estimate the number of tokens in *text*.

        Uses ``tiktoken`` for GPT-family models and a character-based
        heuristic (1 token ≈ 4 characters) for others.
        """
        try:
            import tiktoken

            try:
                enc = tiktoken.encoding_for_model(model)
            except KeyError:
                enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except ImportError:
            # Fallback: ~4 chars per token
            return max(1, len(text) // 4)

    # ── Cost Estimation ──────────────────────────────────────

    def estimate_cost(
        self,
        text: str,
        model: str = "gpt-4o",
        output_tokens: int | None = None,
    ) -> CostReport:
        """
        Estimate the dollar cost of processing *text* with *model*.

        Parameters
        ----------
        text : str
            The input text to be sent to the model.
        model : str
            Model name for pricing lookup.
        output_tokens : int | None
            Explicit output token count; if None, estimated via ratio.

        Returns
        -------
        CostReport
            Detailed cost breakdown.
        """
        input_tokens = self.estimate_tokens(text, model)
        est_output = output_tokens or int(input_tokens * self._output_ratio)

        pricing = self._pricing.get(model, {"input": 0.0025, "output": 0.0100})
        input_cost = (input_tokens / 1000) * pricing["input"]
        output_cost = (est_output / 1000) * pricing["output"]
        total = input_cost + output_cost

        report = CostReport(
            input_tokens=input_tokens,
            output_tokens=est_output,
            model=model,
            input_cost_usd=input_cost,
            output_cost_usd=output_cost,
            estimated_cost_usd=total,
            exceeds_threshold=total > self._threshold,
            threshold_usd=self._threshold,
        )

        # Track cumulative
        self._cumulative_cost += total
        self._cumulative_tokens += input_tokens + est_output

        if report.exceeds_threshold:
            logger.warning(
                "cost_threshold_exceeded",
                model=model,
                estimated_cost=round(total, 4),
                threshold=self._threshold,
                input_tokens=input_tokens,
            )

        return report

    # ── Cumulative Stats ─────────────────────────────────────

    def get_cumulative_stats(self) -> dict[str, Any]:
        """Return cumulative cost and token statistics."""
        return {
            "cumulative_cost_usd": round(self._cumulative_cost, 4),
            "cumulative_tokens": self._cumulative_tokens,
            "threshold_usd": self._threshold,
        }

    def reset_stats(self) -> None:
        """Reset cumulative counters."""
        self._cumulative_cost = 0.0
        self._cumulative_tokens = 0

    # ── Pricing Management ───────────────────────────────────

    def update_pricing(self, model: str, input_price: float, output_price: float) -> None:
        """
        Update or add pricing for a model.

        Parameters
        ----------
        model : str
            Model name.
        input_price : float
            USD per 1 000 input tokens.
        output_price : float
            USD per 1 000 output tokens.
        """
        self._pricing[model] = {"input": input_price, "output": output_price}
        logger.info("pricing_updated", model=model, input=input_price, output=output_price)

    def list_models(self) -> list[str]:
        """Return all models with known pricing."""
        return sorted(self._pricing.keys())
