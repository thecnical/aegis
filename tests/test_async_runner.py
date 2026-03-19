"""Unit tests for AsyncRunner."""
from __future__ import annotations


import pytest

from aegis.core.async_runner import AsyncTask, run_parallel, run_single


@pytest.mark.asyncio
async def test_run_single_echo() -> None:
    cmd = ["python", "-c", "print('hello')"]
    result = await run_single(cmd, timeout=10, label="echo")
    assert result.label == "echo"
    assert result.returncode == 0
    assert "hello" in result.stdout


@pytest.mark.asyncio
async def test_run_single_timeout() -> None:
    cmd = ["python", "-c", "import time; time.sleep(60)"]
    result = await run_single(cmd, timeout=1, label="slow")
    assert result.returncode == 124
    assert "Timed out" in result.stderr


@pytest.mark.asyncio
async def test_run_parallel_result_count() -> None:
    tasks = [
        AsyncTask(cmd=["python", "-c", "print('a')"], timeout=10, label="a"),
        AsyncTask(cmd=["python", "-c", "print('b')"], timeout=10, label="b"),
        AsyncTask(cmd=["python", "-c", "print('c')"], timeout=10, label="c"),
    ]
    results = await run_parallel(tasks)
    assert len(results) == 3


@pytest.mark.asyncio
async def test_run_parallel_label_correspondence() -> None:
    tasks = [
        AsyncTask(cmd=["python", "-c", "print('x')"], timeout=10, label="label-x"),
        AsyncTask(cmd=["python", "-c", "print('y')"], timeout=10, label="label-y"),
    ]
    results = await run_parallel(tasks)
    for i, result in enumerate(results):
        assert result.label == tasks[i].label


@pytest.mark.asyncio
async def test_run_parallel_sibling_independence() -> None:
    """A failing task should not prevent siblings from completing."""
    tasks = [
        AsyncTask(cmd=["python", "-c", "import time; time.sleep(60)"], timeout=1, label="slow"),
        AsyncTask(cmd=["python", "-c", "print('fast')"], timeout=10, label="fast"),
    ]
    results = await run_parallel(tasks)
    fast = next(r for r in results if r.label == "fast")
    assert fast.returncode == 0
    assert "fast" in fast.stdout
