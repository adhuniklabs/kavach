"""Fan-out planning: batches the skill dispatches, or runs them for --headless.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable


def plan_batches(items: list, cap: int) -> list[list]:
    cap = max(1, cap)
    return [items[i:i + cap] for i in range(0, len(items), cap)]


def run_batch(thunks: list[Callable[[], Any]], cap: int) -> list:
    results: list = [None] * len(thunks)

    def _run(i_thunk):
        i, thunk = i_thunk
        try:
            return i, thunk()
        except Exception as exc:  # capture, don't abort the batch
            return i, exc

    with ThreadPoolExecutor(max_workers=max(1, cap)) as pool:
        for i, res in pool.map(_run, list(enumerate(thunks))):
            results[i] = res
    return results
