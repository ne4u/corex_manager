"""Restart-safety tests for the GeoIpDownloader."""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services import geoip
from app.services.geoip import GeoIpDownloader


def _set_last_run_at(db, dt):
    """Write the geoip_download_last_run_at setting directly."""
    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "geoip_download_last_run_at"
    ).first()
    if not row:
        row = Setting(key="geoip_download_last_run_at", value=dt.isoformat())
        db.add(row)
    else:
        row.value = dt.isoformat()
    db.commit()


def _patch_sessionlocal(db):
    """Patch geoip.SessionLocal so it yields the test db session."""
    mock = MagicMock()
    mock.return_value.__enter__.return_value = db
    mock.return_value.__exit__.return_value = False
    return patch("app.services.geoip.SessionLocal", mock)


def test_geoip_downloader_skips_download_when_recently_downloaded(db, tmp_path, monkeypatch):
    """A recent last_run_at + existing mmdb files => download skipped on startup."""
    # Point the DB paths at existing temp files so files_required check passes.
    country = tmp_path / "GeoLite2-Country.mmdb"
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    city = tmp_path / "GeoLite2-City.mmdb"
    country.write_text("fake")
    asn.write_text("fake")
    city.write_text("fake")
    monkeypatch.setattr(geoip.settings, "GEOIP_DB_PATH", str(country))
    monkeypatch.setattr(geoip.settings, "ASN_DB_PATH", str(asn))
    monkeypatch.setattr(geoip.settings, "GEOIP_CITY_DB_PATH", str(city))

    # Re-instantiate so files_required picks up the monkeypatched paths.
    downloader = GeoIpDownloader(interval_hours=24.0)

    recent = datetime.now(timezone.utc) - timedelta(seconds=60)
    _set_last_run_at(db, recent)

    mock_download = MagicMock(return_value={"ok": True, "results": []})
    mock_write_maps = MagicMock(return_value={"country": {"ok": False}, "asn": {"ok": False}})

    with _patch_sessionlocal(db):
        with patch("app.services.geoip.download_maxmind_dbs", mock_download):
            with patch("app.services.geoip.write_haproxy_maps", mock_write_maps):
                # Simulate the initial branch of _run
                if downloader._is_due():
                    downloader._run_tick()
                # Not due => _run_tick should not have been called

    mock_download.assert_not_called()


def test_geoip_downloader_downloads_when_files_missing(db, tmp_path, monkeypatch):
    """Recent last_run_at but missing .mmdb files => download runs."""
    # Point at non-existent paths
    monkeypatch.setattr(geoip.settings, "GEOIP_DB_PATH", str(tmp_path / "missing-country.mmdb"))
    monkeypatch.setattr(geoip.settings, "ASN_DB_PATH", str(tmp_path / "missing-asn.mmdb"))
    monkeypatch.setattr(geoip.settings, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing-city.mmdb"))

    downloader = GeoIpDownloader(interval_hours=24.0)

    recent = datetime.now(timezone.utc) - timedelta(seconds=60)
    _set_last_run_at(db, recent)

    mock_download = MagicMock(return_value={"ok": True, "results": []})
    mock_write_maps = MagicMock(return_value={"country": {"ok": False}, "asn": {"ok": False}})

    with _patch_sessionlocal(db):
        with patch("app.services.geoip.download_maxmind_dbs", mock_download):
            with patch("app.services.geoip.write_haproxy_maps", mock_write_maps):
                assert downloader._is_due() is True
                downloader._run_tick()

    mock_download.assert_called_once()


def test_geoip_downloader_downloads_when_never_run(db, tmp_path, monkeypatch):
    """No last_run_at setting => download runs immediately."""
    monkeypatch.setattr(geoip.settings, "GEOIP_DB_PATH", str(tmp_path / "missing-country.mmdb"))
    monkeypatch.setattr(geoip.settings, "ASN_DB_PATH", str(tmp_path / "missing-asn.mmdb"))
    monkeypatch.setattr(geoip.settings, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing-city.mmdb"))

    downloader = GeoIpDownloader(interval_hours=24.0)

    mock_download = MagicMock(return_value={"ok": True, "results": []})
    mock_write_maps = MagicMock(return_value={"country": {"ok": False}, "asn": {"ok": False}})

    with _patch_sessionlocal(db):
        with patch("app.services.geoip.download_maxmind_dbs", mock_download):
            with patch("app.services.geoip.write_haproxy_maps", mock_write_maps):
                assert downloader._is_due() is True
                downloader._run_tick()

    mock_download.assert_called_once()


def test_geoip_downloader_stamps_on_success(db, tmp_path, monkeypatch):
    """Successful download (result ok=True) stamps geoip_download_last_run_at."""
    country = tmp_path / "GeoLite2-Country.mmdb"
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    city = tmp_path / "GeoLite2-City.mmdb"
    country.write_text("fake")
    asn.write_text("fake")
    city.write_text("fake")
    monkeypatch.setattr(geoip.settings, "GEOIP_DB_PATH", str(country))
    monkeypatch.setattr(geoip.settings, "ASN_DB_PATH", str(asn))
    monkeypatch.setattr(geoip.settings, "GEOIP_CITY_DB_PATH", str(city))

    downloader = GeoIpDownloader(interval_hours=24.0)

    mock_download = MagicMock(return_value={"ok": True, "results": []})
    mock_write_maps = MagicMock(return_value={"country": {"ok": False}, "asn": {"ok": False}})

    with _patch_sessionlocal(db):
        with patch("app.services.geoip.download_maxmind_dbs", mock_download):
            with patch("app.services.geoip.write_haproxy_maps", mock_write_maps):
                downloader._run_tick()

    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "geoip_download_last_run_at"
    ).first()
    assert row is not None
    assert row.value is not None


def test_geoip_downloader_no_stamp_on_failure(db, tmp_path, monkeypatch):
    """Failed download (result ok=False) does not stamp last_run_at."""
    country = tmp_path / "GeoLite2-Country.mmdb"
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    city = tmp_path / "GeoLite2-City.mmdb"
    country.write_text("fake")
    asn.write_text("fake")
    city.write_text("fake")
    monkeypatch.setattr(geoip.settings, "GEOIP_DB_PATH", str(country))
    monkeypatch.setattr(geoip.settings, "ASN_DB_PATH", str(asn))
    monkeypatch.setattr(geoip.settings, "GEOIP_CITY_DB_PATH", str(city))

    downloader = GeoIpDownloader(interval_hours=24.0)

    mock_download = MagicMock(return_value={"ok": False, "results": [{"ok": False}]})
    mock_write_maps = MagicMock(return_value={"country": {"ok": False}, "asn": {"ok": False}})

    with _patch_sessionlocal(db):
        with patch("app.services.geoip.download_maxmind_dbs", mock_download):
            with patch("app.services.geoip.write_haproxy_maps", mock_write_maps):
                # _run_tick is void; _tick returns False so no stamp should occur
                downloader._run_tick()

    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "geoip_download_last_run_at"
    ).first()
    assert row is None


def test_editions_include_city_db():
    """EDITIONS should include GeoLite2-City alongside Country and ASN."""
    edition_ids = [e["edition_id"] for e in geoip.EDITIONS]
    assert "GeoLite2-Country" in edition_ids
    assert "GeoLite2-ASN" in edition_ids
    assert "GeoLite2-City" in edition_ids
