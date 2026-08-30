import logging
import os
import signal
import threading
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..core.valkey_client import dequeue, enqueue, is_available, queue_length
from ..models.models import Certificate, Task
from . import certificates, haproxy
from .scheduler import PeriodicTask

settings = get_settings()
QUEUE_NAME = "haproxy_tasks"

# Track task IDs that should be cancelled. The worker checks this set
# before and after long-running operations (e.g. acme.sh subprocess).
_cancelled_tasks: Set[int] = set()
_cancelled_lock = threading.Lock()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def cancel_task(task_id: int) -> bool:
    """Mark a task for cancellation. Returns True if the task was running."""
    with _cancelled_lock:
        _cancelled_tasks.add(task_id)
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        if task and task.status in ("running", "pending"):
            task.status = "cancelled"
            task.result = {"status": "error", "message": "Task cancelled by user."}
            task.error = None
            db.commit()
            return True
        return False
    finally:
        db.close()


def _is_cancelled(task_id: int) -> bool:
    with _cancelled_lock:
        return task_id in _cancelled_tasks


def _clear_cancelled(task_id: int) -> None:
    with _cancelled_lock:
        _cancelled_tasks.discard(task_id)


def queue_task(task_type: str, payload: Optional[Dict[str, Any]] = None) -> int:
    """Create a task record and optionally enqueue it for the background worker.

    Returns the task id. If the task queue is available, the task is queued for
    background processing; otherwise it is processed synchronously before returning.
    """
    db = SessionLocal()
    try:
        task = Task(
            task_type=task_type,
            payload=payload or {},
            status="pending",
        )
        db.add(task)
        db.commit()
        db.refresh(task)

        if settings.TASK_QUEUE_ENABLED and is_available():
            item = {
                "task_id": task.id,
                "task": task_type,
                "payload": payload or {},
                "queued_at": _utcnow(),
            }
            if not enqueue(QUEUE_NAME, item):
                # Valkey became unavailable; process in background thread
                # for issue_certificate (long-running), synchronously otherwise.
                print(f"[TASK] Task {task.id}: Valkey enqueue failed, dispatching synchronously", flush=True)
                _dispatch_task(task, db)
            else:
                print(f"[TASK] Task {task.id}: enqueued to Valkey worker", flush=True)
        else:
            print(f"[TASK] Task {task.id}: task queue disabled, dispatching synchronously", flush=True)
            _dispatch_task(task, db)

        return task.id
    finally:
        db.close()


def _dispatch_task(task: Task, db) -> None:
    """Run a task either synchronously or in a background thread.

    issue_certificate runs in a separate thread (acme.sh can take minutes).
    All other task types run synchronously.
    """
    if task.task_type == "issue_certificate":
        task_id = task.id
        def _run_in_thread():
            tdb = SessionLocal()
            try:
                t = tdb.query(Task).filter(Task.id == task_id).first()
                if t:
                    _run_task(t, tdb)
            finally:
                tdb.close()
        thread = threading.Thread(target=_run_in_thread, daemon=True)
        thread.start()
    else:
        _run_task(task, db)


def _run_task(task: Task, db) -> None:
    """Execute the task and update the DB record with the result."""
    # Check if the task was cancelled before we started
    if _is_cancelled(task.id):
        _clear_cancelled(task.id)
        task.status = "cancelled"
        task.result = {"status": "error", "message": "Task cancelled by user."}
        db.commit()
        return

    task.status = "running"
    db.commit()

    try:
        result: Dict[str, Any] = {}
        if task.task_type == "apply_config":
            print(f"[TASK] Task {task.id}: starting write_config", flush=True)
            logger.info("Task %s: starting write_config", task.id)
            haproxy.write_config(db, created_by=task.payload.get("created_by"), comment=task.payload.get("comment"))
            print(f"[TASK] Task {task.id}: write_config complete, starting reload_haproxy", flush=True)
            logger.info("Task %s: write_config complete, starting reload_haproxy", task.id)
            result = haproxy.reload_haproxy()
            print(f"[TASK] Task {task.id}: reload_haproxy complete: {result.get('status')}", flush=True)
            logger.info("Task %s: reload_haproxy complete: %s", task.id, result.get("status"))
        elif task.task_type == "revert_config":
            result = haproxy.revert_to_applied_config(db, created_by=task.payload.get("created_by"))
        elif task.task_type == "rollback_snapshot":
            result = haproxy.rollback_to_snapshot(
                db,
                task.payload.get("snapshot_id"),
                created_by=task.payload.get("created_by"),
            )
        elif task.task_type == "renew_certificates":
            result = certificates.renew_certificates(db)
        elif task.task_type == "auto_renew":
            renew_result = certificates.renew_certificates(db)
            if renew_result.get("status") == "ok":
                results = renew_result.get("results", [])
                renewed = [r for r in results if r.get("result", {}).get("status") == "ok"]
                errors = [r for r in results if r.get("result", {}).get("status") != "ok"]
                if renewed:
                    haproxy.write_config(db)
                    reload_result = haproxy.reload_haproxy()
                    result = {
                        "status": reload_result.get("status", "error"),
                        "message": f"Renewed {len(renewed)} certificate(s); reload: {reload_result.get('message')}",
                        "renewed": [r["cert"] for r in renewed],
                        "errors": [r["cert"] for r in errors],
                        "reload_result": reload_result,
                    }
                elif errors:
                    result = {
                        "status": "error",
                        "message": f"Failed to renew {len(errors)} certificate(s)",
                        "errors": errors,
                    }
                else:
                    result = {"status": "ok", "message": "No certificates due for renewal"}
            else:
                result = renew_result
        elif task.task_type == "issue_certificate":
            cert_id = (task.payload or {}).get("cert_id")
            # Check if the cert was deleted (cancelled) before we start
            if _is_cancelled(task.id):
                _clear_cancelled(task.id)
                result = {"status": "error", "message": "Task cancelled by user."}
                task.status = "cancelled"
                task.result = result
                db.commit()
                return
            cert = db.query(Certificate).filter(Certificate.id == cert_id).first()
            if cert:
                result = certificates.generate_certificate(cert, db)
                # Check if the cert was deleted while acme.sh was running
                if _is_cancelled(task.id):
                    _clear_cancelled(task.id)
                    # Cert was deleted during issue — clean up orphaned files
                    from ..services.certificates import delete_cert_files
                    delete_cert_files(cert.domain or cert.name)
                    logger.info("Cert %s was deleted during issue; cleaned up orphaned files", cert_id)
                    return
            else:
                result = {"status": "error", "message": f"Certificate {cert_id} not found"}
        else:
            result = {"status": "error", "message": f"Unknown task type {task.task_type}"}

        task.status = "success" if result.get("status") == "ok" else "failed"
        task.result = result
    except Exception as e:
        logger.error("Task %s failed: %s", task.task_type, e, exc_info=True)
        # On PostgreSQL, a failed DB operation (e.g. FK violation) puts the
        # transaction in an aborted state — all subsequent commands fail with
        # "current transaction is aborted" until ROLLBACK is issued. Without
        # this rollback, the task.status update below would silently fail and
        # the task would be stuck in "running" forever.
        task_id = task.id
        db.rollback()
        task = db.query(Task).filter(Task.id == task_id).first()
        if task:
            task.status = "failed"
            task.result = {"status": "error", "message": str(e)}
            task.error = traceback.format_exc()

    try:
        db.commit()
    except Exception:
        # The task record may have been deleted (e.g. cert was deleted while
        # issue was running). Roll back and move on — nothing to update.
        db.rollback()
        logger.info("Task %s record no longer exists; skipping status update", task.id if task else "?")


def process_task(item: Dict[str, Any]) -> None:
    """Worker entry point: load the Task row and run it.

    issue_certificate tasks are run in a separate thread so they don't block
    the worker loop (acme.sh can take minutes). All other task types run
    synchronously in the worker thread.
    """
    task_id = item.get("task_id")
    task_type = item.get("task")

    if task_type == "issue_certificate":
        # Run in a separate thread with its own DB session so the worker
        # loop can continue processing apply_config and other tasks.
        def _run_in_thread():
            db = SessionLocal()
            try:
                task = db.query(Task).filter(Task.id == task_id).first() if task_id else None
                if not task:
                    logger.warning("Task %s not found in database", task_id)
                    return
                _run_task(task, db)
            finally:
                db.close()

        thread = threading.Thread(target=_run_in_thread, daemon=True)
        thread.start()
        return

    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id).first() if task_id else None
        if not task:
            logger.warning("Task %s not found in database", task_id)
            return
        _run_task(task, db)
    finally:
        db.close()


def _worker_loop() -> None:
    while True:
        if not settings.TASK_QUEUE_ENABLED or not is_available():
            time.sleep(5)
            continue
        try:
            item = dequeue(QUEUE_NAME, timeout=2)
            if item:
                logger.info("Processing task: %s", item.get("task"))
                process_task(item)
        except Exception as e:
            logger.error("Task queue worker error: %s", e, exc_info=True)


def start_task_worker() -> None:
    cleanup_stale_tasks()
    thread = threading.Thread(target=_worker_loop, daemon=True)
    thread.start()


def cleanup_stale_tasks() -> None:
    """Reconcile tasks left in 'running' or 'pending' state after a restart.

    On process restart, any task that was mid-execution is orphaned — the
    background thread that was running it is gone. For issue_certificate tasks,
    check whether the cert was actually written to disk; if so, mark the task
    as 'success' rather than 'failed'. For all other task types (and cert tasks
    where the files are missing), mark as 'failed' so the user knows to retry.
    """
    import os as _os

    db = SessionLocal()
    try:
        stale = db.query(Task).filter(Task.status.in_(["running", "pending"])).all()
        for task in stale:
            if task.task_type == "issue_certificate":
                cert_id = (task.payload or {}).get("cert_id")
                cert = db.query(Certificate).filter(Certificate.id == cert_id).first() if cert_id else None
                if cert and cert.cert_path and _os.path.exists(cert.cert_path):
                    # Cert files exist on disk — the issue succeeded before the
                    # process died; the task just never got its status updated.
                    task.status = "success"
                    task.result = {
                        "status": "ok",
                        "message": "Certificate was issued successfully "
                        "(task status reconciled on startup — the process restarted "
                        "before the task record was updated).",
                    }
                    task.error = None
                    continue
            task.status = "failed"
            task.result = {
                "status": "error",
                "message": "Task was interrupted by a process restart. "
                "The operation may have partially completed — please retry.",
            }
            task.error = None
        if stale:
            db.commit()
            logger.info("Reconciled %d stale task(s) on startup", len(stale))
    finally:
        db.close()


class AutoRenewScheduler(PeriodicTask):
    """Restart-safe ACME.sh auto-renew scheduler.

    On startup, if a previous ``auto_renew_last_run_at`` is recent (within
    ``AUTO_RENEW_INTERVAL_SECONDS``), the scheduler sleeps for the remaining
    time instead of resetting the interval. The actual renewal work runs
    asynchronously through the task queue; ``renew_certificates`` has its own
    per-cert 30-day expiry check that prevents redundant ACME calls.
    """

    def __init__(self):
        super().__init__(
            name="auto_renew",
            interval_seconds=settings.AUTO_RENEW_INTERVAL_SECONDS,
        )

    def _tick(self) -> bool:
        if not settings.AUTO_RENEW_ENABLED or settings.AUTO_RENEW_INTERVAL_SECONDS <= 0:
            # Disabled: stamp to avoid re-checking on every interval.
            return True
        queue_task("auto_renew")
        return True


def get_queue_length() -> int:
    return queue_length(QUEUE_NAME)


def get_task(db, task_id: int) -> Optional[Task]:
    return db.query(Task).filter(Task.id == task_id).first()
