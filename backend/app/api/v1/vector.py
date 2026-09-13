"""Vector log pipeline API — admin-only management of log sources and sinks."""
import os
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..deps import get_db, require_admin, rate_limit
from ...core.config import get_settings
from ...models.logging import VectorSink
from ...schemas.vector import (
    SECRET_MASK,
    SECRET_OPTIONS,
    VectorPipelineResponse,
    VectorPreviewResponse,
    VectorSinkCreate,
    VectorSinkResponse,
    VectorSinkTestRequest,
    VectorSinkTestResponse,
    VectorSinkUpdate,
    VectorValidateResponse,
)
from ...services import vector_pipeline as vp

router = APIRouter()
settings = get_settings()


def _to_response(sink: VectorSink) -> VectorSinkResponse:
    return VectorSinkResponse(
        id=sink.id,
        name=sink.name,
        type=sink.type,
        source=sink.source or "corex",
        options=vp.mask_sink_options(sink.type, sink.options or {}),
        enabled=bool(sink.enabled),
    )


def _resolve_masked_options(sink_type: str, incoming: Dict[str, Any],
                            stored: Dict[str, Any]) -> Dict[str, Any]:
    """Merge client options with stored encrypted values.

    A secret field submitted as the mask sentinel keeps the stored value;
    a secret field submitted empty/masked on create is dropped.
    """
    out = dict(incoming or {})
    for key in SECRET_OPTIONS.get(sink_type, []):
        if out.get(key) == SECRET_MASK:
            stored_val = (stored or {}).get(key)
            if stored_val:
                out[key] = stored_val
            else:
                out.pop(key, None)
    return out


@router.get("/vector/pipeline", response_model=VectorPipelineResponse)
def get_pipeline(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    from ...services.runtime import get_runtime
    sinks = db.query(VectorSink).order_by(VectorSink.name).all()
    applied = False
    try:
        applied = os.path.exists(f"{settings.VECTOR_CONFIG_PATH}.applied")
    except Exception:
        applied = False
    return VectorPipelineResponse(
        sources=vp.get_vector_sources(db),
        sinks=[_to_response(s) for s in sinks],
        applied=applied,
        runtime=get_runtime().describe(),
        vector_status=get_runtime().describe_vector(),
    )


@router.get("/vector/sinks", response_model=List[VectorSinkResponse])
def list_sinks(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    sinks = db.query(VectorSink).order_by(VectorSink.name).all()
    return [_to_response(s) for s in sinks]


@router.post("/vector/sinks", response_model=VectorSinkResponse)
def create_sink(
    body: VectorSinkCreate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    existing = db.query(VectorSink).filter(VectorSink.name == body.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="A sink with this name already exists")
    options = _resolve_masked_options(body.type, body.options, {})
    options = vp.encrypt_sink_options(body.type, options)
    sink = VectorSink(
        name=body.name,
        type=body.type,
        source=body.source,
        options=options,
        enabled=body.enabled,
    )
    db.add(sink)
    db.commit()
    db.refresh(sink)
    return _to_response(sink)


@router.put("/vector/sinks/{sid}", response_model=VectorSinkResponse)
def update_sink(
    sid: int,
    body: VectorSinkUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    sink = db.get(VectorSink, sid)
    if not sink:
        raise HTTPException(status_code=404, detail="Sink not found")
    options = _resolve_masked_options(body.type, body.options, sink.options or {})
    sink.name = body.name
    sink.type = body.type
    sink.source = body.source
    sink.options = vp.encrypt_sink_options(body.type, options)
    sink.enabled = body.enabled
    db.commit()
    db.refresh(sink)
    return _to_response(sink)


@router.delete("/vector/sinks/{sid}")
def delete_sink(
    sid: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    sink = db.get(VectorSink, sid)
    if not sink:
        raise HTTPException(status_code=404, detail="Sink not found")
    db.delete(sink)
    db.commit()
    return {"status": "ok"}


@router.get("/vector/preview", response_model=VectorPreviewResponse)
def preview_config(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return VectorPreviewResponse(config=vp.generate_vector_toml_redacted(db))


def _container_path(local_path: str) -> str:
    """Map a backend-side vector config path to the container-side path.

    Both containers mount the shared data volume at /app/data, so the
    basename under the vector config dir is preserved.
    """
    base = os.path.basename(local_path)
    cdir = os.path.dirname(settings.VECTOR_CONTAINER_CONFIG_PATH)
    return f"{cdir}/{base}"


@router.post("/vector/sinks/test", response_model=VectorSinkTestResponse)
def test_sink(
    body: VectorSinkTestRequest,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Stage a vector.toml exercising a candidate sink and check it inside
    the vector container via ``vector validate`` (which runs sink
    healthchecks — real connectivity/auth tests for most sink types).
    The ``send_test_event`` flag controls whether the staging config
    includes a ``demo_logs`` source, but both modes use ``validate`` because
    the vector image's ``ENTRYPOINT ["vector"]`` prevents running shell
    pipelines (``sh`` is not a vector subcommand)."""
    from ...services.runtime import get_runtime
    import logging
    logger = logging.getLogger(__name__)

    # Resolve masked secrets against the stored sink when testing an edit.
    options = dict(body.options or {})
    if body.sink_id:
        stored = db.get(VectorSink, body.sink_id)
        if stored:
            options = _resolve_masked_options(body.type, options, stored.options or {})
    # Decrypt any enc: values so the staging config renders plaintext.
    try:
        options, plaintexts = vp.decrypt_sink_options(body.type, options)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Secret decryption failed: {exc}")

    try:
        toml_text, secrets = vp.generate_staging_sink_toml(
            db, body.type, body.source, options, body.send_test_event)
        secrets.extend(plaintexts)

        staging_local = os.path.join(
            os.path.dirname(settings.VECTOR_CONFIG_PATH), "vector.sink-test.toml")
        staging_container = _container_path(staging_local)
        vp._write_file(staging_local, toml_text)
    except Exception as exc:
        logger.exception("Failed to generate staging vector config for sink check")
        raise HTTPException(status_code=500, detail=f"Failed to generate staging config: {exc}")

    runtime = get_runtime()
    # docker exec does NOT use the image ENTRYPOINT, so we run the full
    # "vector validate" command. Vector 0.58+ uses positional paths (not
    # --config). Both modes use `validate` (which runs sink healthchecks —
    # real connectivity/auth tests). The send_test_event flag controls
    # whether the staging config includes a demo_logs source.
    ok, output = runtime.vector_exec(
        ["vector", "validate", staging_container], timeout=45)
    if not ok and ("not available" in output.lower() or "not found" in output.lower()):
        raise HTTPException(status_code=503, detail=output)
    return VectorSinkTestResponse(ok=ok, output=vp.redact_text(output, secrets))


@router.post("/vector/validate", response_model=VectorValidateResponse)
def validate_config(
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Run ``vector validate`` against the live vector.toml in the container."""
    from ...services.runtime import get_runtime
    # Vector 0.58+ uses positional paths (not --config).
    ok, output = get_runtime().vector_exec(
        ["vector", "validate", settings.VECTOR_CONTAINER_CONFIG_PATH],
        timeout=45)
    return VectorValidateResponse(valid=ok, output=output)


@router.post("/vector/restart")
def restart_vector(
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    from ...services.runtime import get_runtime
    ok = get_runtime().restart_vector()
    if not ok:
        raise HTTPException(status_code=503, detail="Vector container not available")
    return {"status": "ok"}
