"""
A name imported inside a function makes that name local to the WHOLE function, so a use before the
import fails with UnboundLocalError (it broke `veritas support-bundle` in the packaged build while
every unit test passed). The module imports Path once at the top; no function may re-import it.
"""
import ast
from pathlib import Path

SOURCE = Path(__file__).with_name("run_pipeline.py")


def test_main_does_not_shadow_module_level_imports():
    tree = ast.parse(SOURCE.read_text())
    top = {a.asname or a.name for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    offenders = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for n in ast.walk(fn):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    name = (a.asname or a.name).split(".")[0]
                    if name in top:
                        offenders.append(f"{fn.name}: line {n.lineno} re-imports {name}")
    assert not offenders, offenders
