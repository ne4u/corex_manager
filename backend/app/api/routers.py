from fastapi import APIRouter

from ..core.config import get_settings
from ..models.models import *
from ..schemas.schemas import *

router = APIRouter()
settings = get_settings()
