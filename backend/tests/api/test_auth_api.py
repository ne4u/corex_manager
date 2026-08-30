"""Integration tests for /auth endpoints: preferences (language) and change-password."""
import pytest

from app.core.dependencies import get_current_user
from app.core.security import get_password_hash, verify_password
from app.main import app
from app.models.models import User, UserPreference


@pytest.fixture
def real_user(db):
    """Create a real user row and override get_current_user to return it."""
    user = User(
        username="auth-test-user",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("OldPass123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    def _get_current_user():
        return db.merge(user)

    app.dependency_overrides[get_current_user] = _get_current_user
    yield user
    app.dependency_overrides.pop(get_current_user, None)


def test_get_preferences_creates_default(client, db, real_user):
    res = client.get("/api/v1/auth/preferences")
    assert res.status_code == 200
    body = res.json()
    assert body["theme"] is None
    assert body["custom_themes"] is None
    assert body["language"] is None
    assert body["datetime_format"] is None
    assert body["timezone"] is None


def test_update_preferences_language(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"language": "es"})
    assert res.status_code == 200
    assert res.json()["language"] == "es"

    pref = db.query(UserPreference).filter(UserPreference.user_id == real_user.id).first()
    assert pref is not None
    assert pref.language == "es"


def test_update_preferences_datetime_format(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"datetime_format": "yyyy-MM-dd HH:mm:ss"})
    assert res.status_code == 200
    assert res.json()["datetime_format"] == "yyyy-MM-dd HH:mm:ss"

    pref = db.query(UserPreference).filter(UserPreference.user_id == real_user.id).first()
    assert pref is not None
    assert pref.datetime_format == "yyyy-MM-dd HH:mm:ss"


def test_update_preferences_timezone(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"timezone": "America/New_York"})
    assert res.status_code == 200
    assert res.json()["timezone"] == "America/New_York"

    pref = db.query(UserPreference).filter(UserPreference.user_id == real_user.id).first()
    assert pref is not None
    assert pref.timezone == "America/New_York"


def test_update_preferences_timezone_local(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"timezone": "local"})
    assert res.status_code == 200
    assert res.json()["timezone"] == "local"


def test_update_preferences_timezone_utc(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"timezone": "utc"})
    assert res.status_code == 200
    assert res.json()["timezone"] == "utc"


def test_update_preferences_timezone_invalid(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"timezone": "Fake/Zone"})
    assert res.status_code == 400
    assert "timezone" in res.json()["detail"]


def test_update_preferences_datetime_format_empty(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"datetime_format": ""})
    assert res.status_code == 400
    assert "datetime_format" in res.json()["detail"]


def test_update_preferences_datetime_format_too_long(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"datetime_format": "x" * 65})
    assert res.status_code == 400
    assert "datetime_format" in res.json()["detail"]


def test_update_preferences_language(client, db, real_user):
    res = client.put("/api/v1/auth/preferences", json={"language": "es"})
    assert res.status_code == 200
    assert res.json()["language"] == "es"

    pref = db.query(UserPreference).filter(UserPreference.user_id == real_user.id).first()
    assert pref is not None
    assert pref.language == "es"


def test_update_preferences_partial_keeps_language(client, db, real_user):
    client.put("/api/v1/auth/preferences", json={"language": "fr"})
    client.put("/api/v1/auth/preferences", json={"theme": "dracula"})
    res = client.get("/api/v1/auth/preferences")
    body = res.json()
    assert body["language"] == "fr"
    assert body["theme"] == "dracula"


def test_change_password_service_success(db):
    from app.services.auth import change_password

    user = User(
        username="pw-user",
        role="operator",
        is_admin=False,
        hashed_password=get_password_hash("OldPass123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    change_password(user, "OldPass123", "NewSecurePass456")
    db.commit()
    db.refresh(user)

    assert verify_password("NewSecurePass456", user.hashed_password)
    assert not verify_password("OldPass123", user.hashed_password)


def test_change_password_service_wrong_current():
    from app.services.auth import change_password

    user = User(
        username="pw-user-2",
        role="operator",
        is_admin=False,
        hashed_password=get_password_hash("OldPass123"),
    )
    with pytest.raises(ValueError, match="Current password is incorrect"):
        change_password(user, "WrongPassword", "NewSecurePass456")


def test_change_password_endpoint_success(client, db, real_user):
    res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123", "new_password": "NewSecurePass456"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    db.expire_all()
    refreshed = db.query(User).filter(User.id == real_user.id).first()
    assert verify_password("NewSecurePass456", refreshed.hashed_password)


def test_change_password_endpoint_wrong_current(client, db, real_user):
    res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "wrong", "new_password": "NewSecurePass456"},
    )
    assert res.status_code == 400
    assert "Current password is incorrect" in res.json()["detail"]


def test_change_password_endpoint_short_new_rejected(client, db, real_user):
    res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123", "new_password": "short"},
    )
    # Pydantic min_length=8 -> 422
    assert res.status_code == 422
