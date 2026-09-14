"""Custom JSON response class backed by orjson.

FastAPI's built-in ``ORJSONResponse`` triggers a deprecation warning on every
request because FastAPI now serializes typed endpoints (those with a
``response_model``) via Pydantic, which is faster and doesn't need a custom
response class.  However, for the 117 untyped endpoints that return raw dicts,
stdlib ``json`` is noticeably slower than orjson — it creates more intermediate
Python objects (string → encode → bytes) and lacks orjson's C-level direct-to-
bytes serialization.

This class subclasses ``JSONResponse`` and overrides only ``render`` to use
orjson, avoiding the deprecation warning entirely while keeping orjson's speed
for untyped endpoints.  Typed endpoints are unaffected — FastAPI uses Pydantic
serialization for them regardless of ``default_response_class``.
"""

from __future__ import annotations

import orjson
from fastapi.responses import JSONResponse


class OrjsonResponse(JSONResponse):
    """JSONResponse that serializes via orjson (C extension, direct to bytes).

    Unlike FastAPI's deprecated ``ORJSONResponse``, this does not trigger
    deprecation warnings because it subclasses ``JSONResponse`` directly and
    only overrides ``render``.
    """

    def render(self, content: object) -> bytes:
        return orjson.dumps(
            content,
            option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY,
        )
