from pathlib import Path

import pytest

from conclear.adapters.parsing import json_value
from conclear.errors import OperationalError
from conclear.jsonutil import load_json


def test_json_file_rejects_excessive_nesting(tmp_path: Path) -> None:
    path = tmp_path / "nested.json"
    path.write_text("[" * 66 + "0" + "]" * 66, encoding="utf-8")

    with pytest.raises(OperationalError, match="nesting limit"):
        load_json(path)


def test_external_tool_json_rejects_excessive_nesting() -> None:
    value = "[" * 66 + "0" + "]" * 66

    with pytest.raises(OperationalError, match="nesting limit"):
        json_value(value, label="tool")
