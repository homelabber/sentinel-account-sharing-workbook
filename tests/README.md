# Tests

A workbook can be valid JSON containing valid KQL and still be completely broken
in the Azure portal. These checks cover both layers.

## Run everything

```powershell
# once, to fetch the Microsoft Kusto parser (not committed)
.\tests\fetch-parser.ps1

# structure and schema
python tests\check_structure.py     # portal contract: params, tabs, visualizations, names
python tests\check_dynamic.py       # post-union dynamic access (runtime-only failure)
python tests\compare_schema.py      # dropdowns vs. Microsoft's shipping schema

# KQL
pwsh -File tests\validate.ps1       # syntax, via Kusto.Language
pwsh -File tests\semantic.ps1       # semantic analysis against real table schemas

# the checkers themselves
python tests\test_checker.py        # 11 regressions
python tests\test_dynamic.py        # 3 regressions
```

## What each one catches

| Check | Catches |
|---|---|
| `check_structure.py` | Required parameters with no default (renders as an unsatisfiable mandatory pill and blocks every bound query) · JSON dropdowns with a stray `queryType` (hangs on `<unset>` behind a spinner) · settings objects in the `visualization` slot (`Unable to find visualization: [object Object]`) · HTML entities in labels (render literally) · undeclared tab state (blank page) · duplicate item names · bogus `fallbackResourceIds` |
| `check_dynamic.py` | Dot or index access on a dynamic column *after* a `union`. The Kusto parser accepts this — the column is dynamic in every leg — but Log Analytics rejects it at runtime with `Failed to resolve expression 'DeviceDetail.deviceId'`. |
| `compare_schema.py` | Dropdown parameters that deviate from the schema used by all 280 JSON dropdowns in the shipping Azure-Sentinel workbook repository. |
| `validate.ps1` | KQL syntax, using Microsoft's own grammar. |
| `semantic.ps1` | Column and function resolution against declared Entra / Defender XDR / Sentinel table schemas. Catches typos and wrong argument counts. |

## Why the checkers are themselves tested

`test_checker.py` and `test_dynamic.py` reintroduce bugs that genuinely broke the
portal, then assert the corresponding checker fails.

This is not ceremony. `check_dynamic.py` passed clean on its first run — and when
tested, caught **0 of 3** real bugs, because function-call parentheses were being
counted as union-leg parentheses. A green check from an untested checker is worse
than no checker at all, because it reads like evidence.

Every entry in the table above has at least one regression test behind it.
