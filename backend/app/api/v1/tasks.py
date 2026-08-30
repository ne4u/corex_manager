from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_write, rate_limit
from ...schemas.tasks import TaskResponse
from ...services.tasks import cancel_task, get_task

router = APIRouter()


@router.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task_status(
    task_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    task = get_task(db, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.post("/tasks/{task_id}/cancel")
def cancel_task_route(
    task_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    task = get_task(db, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("running", "pending"):
        raise HTTPException(status_code=400, detail=f"Task is not running or pending (current status: {task.status})")
    cancel_task(task_id)
    return {"status": "ok", "message": "Task cancelled"}
