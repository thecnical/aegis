from __future__ import annotations
import asyncio
from dataclasses import dataclass


@dataclass
class AsyncTask:
    cmd: list[str]
    timeout: int
    label: str


@dataclass
class TaskResult:
    label: str
    returncode: int
    stdout: str
    stderr: str


async def run_single(cmd: list[str], timeout: int, label: str) -> TaskResult:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        raw_stdout, raw_stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return TaskResult(
            label=label,
            returncode=proc.returncode if proc.returncode is not None else 0,
            stdout=raw_stdout.decode("utf-8", errors="replace"),
            stderr=raw_stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return TaskResult(label=label, returncode=124, stdout="", stderr="Timed out")


async def run_parallel(tasks: list[AsyncTask]) -> list[TaskResult]:
    coroutines = [run_single(t.cmd, t.timeout, t.label) for t in tasks]
    raw = await asyncio.gather(*coroutines, return_exceptions=True)
    output: list[TaskResult] = []
    for i, result in enumerate(raw):
        if isinstance(result, BaseException):
            output.append(
                TaskResult(
                    label=tasks[i].label,
                    returncode=1,
                    stdout="",
                    stderr=str(result),
                )
            )
        else:
            output.append(result)
    return output
