"""Expected behavior test for CI/CD lint failures fix.

**Property 1: Expected Behavior - Lint Check Passes on Fixed Code**
**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**

This test verifies that the fix works correctly by checking that Ruff reports
zero lint violations on fixed code. The following violations have been fixed:
- aegis/api/app.py:5 - F401 unused import 'io' (REMOVED)
- aegis/api/app.py:13 - F401 unused import 'JSONResponse' (REMOVED)
- aegis/api/app.py:289 - F401 unused import 'PHASE_TOOLS' (REMOVED)
- aegis/core/burp_importer.py:7 - F401 unused import 'field' (REMOVED)
- aegis/core/burp_importer.py:130 - F841 unused variable 'exc' (FIXED)

EXPECTED OUTCOME: Test PASSES (proves bug is fixed)
"""
from __future__ import annotations

import subprocess

from hypothesis import given, settings
from hypothesis import strategies as st


def test_expected_behavior_lint_passes() -> None:
    """Verify that Ruff reports zero lint violations on fixed code.
    
    This test verifies the expected behavior after the fix. The code should
    pass all Ruff lint checks with zero violations.
    
    The test runs: ruff check aegis/api/app.py aegis/core/burp_importer.py
    
    Previously fixed violations:
    1. aegis/api/app.py:5:8: F401 [*] `io` imported but unused (REMOVED)
    2. aegis/api/app.py:13:45: F401 [*] `fastapi.responses.JSONResponse` imported but unused (REMOVED)
    3. aegis/api/app.py:289:48: F401 [*] `aegis.core.ai_orchestrator.PHASE_TOOLS` imported but unused (REMOVED)
    4. aegis/core/burp_importer.py:7:36: F401 [*] `dataclasses.field` imported but unused (REMOVED)
    5. aegis/core/burp_importer.py:130:37: F841 Local variable `exc` is assigned to but never used (FIXED)
    """
    # Run ruff check on the two files
    result = subprocess.run(
        ["ruff", "check", "aegis/api/app.py", "aegis/core/burp_importer.py"],
        capture_output=True,
        text=True,
    )
    
    # On fixed code, we expect:
    # - Exit code 0 (ruff found no violations)
    # - Output showing "All checks passed!"
    
    output = result.stdout + result.stderr
    
    # Verify that Ruff passes with zero violations
    assert result.returncode == 0, (
        f"Expected Ruff to pass with zero violations on fixed code, but it failed. "
        f"Exit code: {result.returncode}. "
        f"Ruff output:\n{output}"
    )
    
    # Verify the success message
    assert "All checks passed!" in output, (
        f"Expected 'All checks passed!' message in output, but got:\n{output}"
    )


@given(st.just(None))
@settings(max_examples=1)
def test_property_expected_behavior_lint_passes(dummy) -> None:
    """Property-based wrapper for expected behavior verification.
    
    **Property 1: Expected Behavior - Lint Check Passes on Fixed Code**
    **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**
    
    For the fixed codebase, running Ruff on the two affected files
    SHALL report zero violations and exit with code 0.
    
    This test verifies that all 5 lint violations have been successfully fixed.
    """
    test_expected_behavior_lint_passes()
