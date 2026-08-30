from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from starlette.background import BackgroundTask
from sqlalchemy import or_
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import base64
import io
import pyotp
import qrcode
from qrcode.image.svg import SvgImage

from ..core.database import get_db
from ..core.config import get_settings
from ..core.dependencies import get_current_user, oauth2_scheme, rate_limit, rate_limit_by_ip, require_admin, require_write
from ..core.security import create_access_token, decode_access_token, get_password_hash, verify_password
from ..core.valkey_client import revoke_token
from ..schemas.schemas import *
from ..models.models import *
from ..services.haproxy import write_config, reload_haproxy
from ..services.certificates import generate_certificate, renew_certificates, upload_custom_certificate
from ..services.dns_providers import get_active_acme_client, list_dns_providers
from ..services.acme_cas import list_acme_cas
from ..services.settings import get_setting, list_settings, set_setting, get_maxmind_license_key
from ..services.geoip import download_maxmind_dbs
import csv
import difflib
import io
import json
import os
from ..services.stats import get_stats
from ..services.tasks import queue_task, get_task

router = APIRouter()
settings = get_settings()


