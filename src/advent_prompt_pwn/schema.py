"""Bundled JSON Schemas for versioned public document formats."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from importlib.resources import files
from typing import Any

SCHEMA_NAMES = ("corpus-v1", "engagement-v1", "report-v1", "reproducers-v1")


def get_schema(name: str) -> dict[str, Any]:
    """Load a bundled schema by its stable public name."""

    if name not in SCHEMA_NAMES:
        raise KeyError(f"unknown schema: {name}")
    resource = files("advent_prompt_pwn").joinpath("data").joinpath(f"{name}.schema.json")
    value: Any = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"bundled schema {name!r} is not a JSON object")
    return value


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise RuntimeError(f"unsupported bundled schema type: {expected}")


def _validate_schema_value(value: Any, schema: Mapping[str, Any], path: str) -> None:
    expected = schema.get("type")
    if expected is not None:
        choices = [expected] if isinstance(expected, str) else expected
        if not isinstance(choices, list) or not all(isinstance(item, str) for item in choices):
            raise RuntimeError(f"invalid bundled schema type at {path}")
        if not any(_matches_type(value, item) for item in choices):
            raise ValueError(f"{path} must have type {' or '.join(choices)}")

    if "const" in schema:
        constant = schema["const"]
        bool_number_mismatch = isinstance(value, bool) != isinstance(constant, bool) and (
            isinstance(value, (bool, int, float))
            and isinstance(constant, (bool, int, float))
        )
        if value != constant or bool_number_mismatch:
            raise ValueError(f"{path} must equal {constant!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} must be one of {schema['enum']!r}")

    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            raise ValueError(f"{path} is shorter than {minimum_length} characters")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            raise ValueError(f"{path} does not match the required pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} must be at most {schema['maximum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise ValueError(f"{path} must be greater than {schema['exclusiveMinimum']}")

    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise RuntimeError(f"invalid bundled schema properties at {path}")
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise RuntimeError(f"invalid bundled schema required list at {path}")
        missing = [name for name in required if name not in value]
        if missing:
            raise ValueError(f"{path} is missing required field(s): {', '.join(missing)}")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string field name")
            child_path = f"{path}.{key}"
            child_schema = properties.get(key)
            if isinstance(child_schema, Mapping):
                _validate_schema_value(item, child_schema, child_path)
            elif additional is False:
                raise ValueError(f"{path} contains unknown field {key!r}")
            elif isinstance(additional, Mapping):
                _validate_schema_value(item, additional, child_path)

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema_value(item, item_schema, f"{path}[{index}]")


def validate_schema_document(value: Any, name: str) -> None:
    """Validate a document against the strict subset used by bundled schemas."""

    _validate_schema_value(value, get_schema(name), name)
