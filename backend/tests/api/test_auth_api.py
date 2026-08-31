"""Integration tests for /auth endpoints: preferences (language) and change-password."""
from datetime import datetime, timedelta, timezone

import pytest

from app.core.dependencies import get_current_user
from app.core.security import create_access_token, get_password_hash, verify_password
from app.main import app
from app.models.models import Setting, User, UserPreference


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

    change_password(db, user, "OldPass123", "NewSecurePass456")
    db.commit()
    db.refresh(user)

    assert verify_password("NewSecurePass456", user.hashed_password)
    assert not verify_password("OldPass123", user.hashed_password)
    assert user.password_changed_at is not None


def test_change_password_service_wrong_current(db):
    from app.services.auth import change_password

    user = User(
        username="pw-user-2",
        role="operator",
        is_admin=False,
        hashed_password=get_password_hash("OldPass123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    with pytest.raises(ValueError, match="Current password is incorrect"):
        change_password(db, user, "WrongPassword", "NewSecurePass456")


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
    # Service-level complexity validation (default min 8) -> 400
    assert res.status_code == 400
    assert "at least 8 characters" in res.json()["detail"]


# ---------------------------------------------------------------------------
# Login: last_login_at tracking + password_expired response
# ---------------------------------------------------------------------------

def test_login_sets_last_login_at(client, db):
    """A successful /auth/token login records last_login_at on the user."""
    user = User(
        username="login-tracker",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("GoodPass123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    assert user.last_login_at is None

    res = client.post(
        "/api/v1/auth/token",
        content="username=login-tracker&password=GoodPass123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 200
    db.expire_all()
    refreshed = db.query(User).filter(User.username == "login-tracker").first()
    assert refreshed.last_login_at is not None


def test_login_response_includes_password_expired_false(client, db):
    user = User(
        username="not-expired-user",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("GoodPass123"),
        password_changed_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()

    res = client.post(
        "/api/v1/auth/token",
        content="username=not-expired-user&password=GoodPass123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 200
    assert res.json()["password_expired"] is False


def test_login_response_password_expired_true(client, db):
    """When rotation is enabled and the password is past expiry, login returns
    password_expired=true."""
    db.add(Setting(key="password_rotation_months", value="1"))
    user = User(
        username="expired-user",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("GoodPass123"),
        password_changed_at=datetime.now(timezone.utc) - timedelta(days=60),
    )
    db.add(user)
    db.commit()

    res = client.post(
        "/api/v1/auth/token",
        content="username=expired-user&password=GoodPass123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 200
    assert res.json()["password_expired"] is True


def test_session_endpoint_reports_password_expired(client, db, real_user):
    """/auth/session includes password_expired + password_policy."""
    res = client.get("/api/v1/auth/session")
    assert res.status_code == 200
    body = res.json()
    assert "password_expired" in body
    assert "password_policy" in body
    assert body["password_policy"]["min_length"] >= 8


# ---------------------------------------------------------------------------
# Password expiry middleware (403 password_change_required)
# ---------------------------------------------------------------------------

def test_expired_password_blocks_non_auth_endpoint(client, db):
    """A JWT with pwd_exp=true gets 403 on a non-auth endpoint."""
    db.add(Setting(key="password_rotation_months", value="1"))
    user = User(
        username="mw-expired",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("GoodPass123"),
        password_changed_at=datetime.now(timezone.utc) - timedelta(days=60),
    )
    db.add(user)
    db.commit()

    # Log in to get a token with pwd_exp=true
    res = client.post(
        "/api/v1/auth/token",
        content="username=mw-expired&password=GoodPass123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = res.json()["access_token"]

    # A non-auth endpoint should be blocked.
    blocked = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "password_change_required"


def test_expired_password_allows_change_password(client, db):
    """Even with pwd_exp=true, /auth/change-password is whitelisted."""
    db.add(Setting(key="password_rotation_months", value="1"))
    user = User(
        username="mw-change",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("GoodPass123"),
        password_changed_at=datetime.now(timezone.utc) - timedelta(days=60),
    )
    db.add(user)
    db.commit()

    res = client.post(
        "/api/v1/auth/token",
        content="username=mw-change&password=GoodPass123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = res.json()["access_token"]

    # Use real auth (not the client fixture's fake get_current_user) so the
    # change-password endpoint can verify the actual password.
    app.dependency_overrides.pop(get_current_user, None)
    try:
        changed = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "GoodPass123", "new_password": "NewSecurePass456"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert changed.status_code == 200
    finally:
        # Restore the default override
        from app.core.dependencies import get_current_user as _gcu
        app.dependency_overrides[get_current_user] = lambda: User(
            username="test-admin", role="admin", is_admin=True, hashed_password="x"
        )


def test_change_password_clears_expiry_and_refresh_yields_clean_token(client, db):
    """After changing an expired password, a refresh produces a token without
    pwd_exp=true, and non-auth endpoints are accessible again."""
    db.add(Setting(key="password_rotation_months", value="1"))
    user = User(
        username="mw-recover",
        role="admin",
        is_admin=True,
        hashed_password=get_password_hash("GoodPass123"),
        password_changed_at=datetime.now(timezone.utc) - timedelta(days=60),
    )
    db.add(user)
    db.commit()

    res = client.post(
        "/api/v1/auth/token",
        content="username=mw-recover&password=GoodPass123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = res.json()["access_token"]
    assert res.json()["password_expired"] is True

    # Use real auth for change-password so the actual password is verified.
    app.dependency_overrides.pop(get_current_user, None)
    try:
        # Change the password (whitelisted even when expired)
        client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "GoodPass123", "new_password": "NewSecurePass456"},
            headers={"Authorization": f"Bearer {token}"},
        )

        # Refresh — the new token should not have pwd_exp
        refreshed = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert refreshed.status_code == 200
        new_token = refreshed.json()["access_token"]

        # Non-auth endpoint should now work
        ok = client.get("/api/v1/users", headers={"Authorization": f"Bearer {new_token}"})
        assert ok.status_code == 200
    finally:
        app.dependency_overrides[get_current_user] = lambda: User(
            username="test-admin", role="admin", is_admin=True, hashed_password="x"
        )


# ---------------------------------------------------------------------------
# Complexity validation on change-password
# ---------------------------------------------------------------------------

def test_change_password_rejects_missing_uppercase(client, db, real_user):
    db.add(Setting(key="password_require_uppercase", value="true"))
    db.commit()
    res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123", "new_password": "alllowercase1"},
    )
    assert res.status_code == 400
    assert "uppercase" in res.json()["detail"]


def test_change_password_accepts_compliant(client, db, real_user):
    db.add(Setting(key="password_require_uppercase", value="true"))
    db.add(Setting(key="password_require_digit", value="true"))
    db.commit()
    res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123", "new_password": "HasUpperAndDigit1"},
    )
    assert res.status_code == 200
