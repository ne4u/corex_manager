"""Security list and dynamic feed endpoints."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form, status, Response
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_admin, require_write, rate_limit
from ...core.config import get_settings
from ...models.models import *
from ...schemas.security_lists import *
from ...services.security_lists import (
    validate_network_value,
    validate_asn_value,
    validate_country_code,
    validate_ja4_value,
    validate_pattern_value,
    get_country_options,
    find_list_references,
    build_in_use_message,
)
from ...services.security_list_feeds import refresh_feed as refresh_dynamic_feed
from ...services.security_rules import (
    parse_expression,
    translate,
    validate_expression,
    reorder_rules,
)

settings = get_settings()
router = APIRouter()


def _network_list_response(lst) -> NetworkListResponse:
    return NetworkListResponse(
        id=lst.id,
        name=lst.name,
        description=lst.description,
        entry_count=len(lst.entries),
        created_at=lst.created_at,
        updated_at=lst.updated_at,
    )


def _asn_list_response(lst) -> AsnListResponse:
    return AsnListResponse(
        id=lst.id,
        name=lst.name,
        description=lst.description,
        entry_count=len(lst.entries),
        created_at=lst.created_at,
        updated_at=lst.updated_at,
    )


def _geo_list_response(lst) -> GeoListResponse:
    return GeoListResponse(
        id=lst.id,
        name=lst.name,
        description=lst.description,
        entry_count=len(lst.entries),
        created_at=lst.created_at,
        updated_at=lst.updated_at,
    )


def _ja4_list_response(lst) -> Ja4ListResponse:
    return Ja4ListResponse(
        id=lst.id,
        name=lst.name,
        description=lst.description,
        entry_count=len(lst.entries),
        created_at=lst.created_at,
        updated_at=lst.updated_at,
    )


def _pattern_list_response(lst) -> PatternListResponse:
    return PatternListResponse(
        id=lst.id,
        name=lst.name,
        description=lst.description,
        entry_count=len(lst.entries),
        created_at=lst.created_at,
        updated_at=lst.updated_at,
    )


def _touch_list(db: Session, model_cls, lid: int):
    """Bump a list's updated_at timestamp to now (used when entries change)."""
    lst = db.get(model_cls, lid)
    if lst:
        lst.updated_at = datetime.now(timezone.utc)


# --- Network lists ---
@router.get("/security-lists/network", response_model=List[NetworkListResponse])
def list_network_lists(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return [_network_list_response(l) for l in db.query(NetworkList).all()]


@router.post("/security-lists/network", response_model=NetworkListResponse)
def create_network_list(a: NetworkListCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = NetworkList(name=a.name, description=a.description)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _network_list_response(obj)


@router.put("/security-lists/network/{lid}", response_model=NetworkListResponse)
def update_network_list(lid: int, a_in: NetworkListUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(NetworkList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="Network list not found")
    for k, v in a_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return _network_list_response(obj)


@router.delete("/security-lists/network/{lid}")
def delete_network_list(lid: int, force: bool = False, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(NetworkList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="Network list not found")
    refs = find_list_references(db, "network", lid)
    # Hard block: rule/setting references cannot be force-overridden.
    in_use_msg = build_in_use_message(obj.name, refs)
    if in_use_msg:
        raise HTTPException(status_code=409, detail=in_use_msg)
    feed = refs["feed"]
    if feed and not force:
        raise HTTPException(status_code=409, detail=f"List is targeted by dynamic feed '{feed.name}'. Delete the feed first or pass force=true.")
    if feed:
        db.delete(feed)
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.get("/security-lists/network/{lid}/entries", response_model=List[NetworkListEntryResponse])
def list_network_entries(lid: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    if not db.get(NetworkList, lid):
        raise HTTPException(status_code=404, detail="Network list not found")
    return db.query(NetworkListEntry).filter(NetworkListEntry.list_id == lid).all()


@router.post("/security-lists/network/{lid}/entries", response_model=NetworkListEntryResponse)
def create_network_entry(lid: int, e: NetworkListEntryCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    if not db.get(NetworkList, lid):
        raise HTTPException(status_code=404, detail="Network list not found")
    try:
        value = validate_network_value(e.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    obj = NetworkListEntry(list_id=lid, value=value, note=e.note)
    db.add(obj)
    _touch_list(db, NetworkList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/security-lists/network/{lid}/entries/{eid}", response_model=NetworkListEntryResponse)
def update_network_entry(lid: int, eid: int, e_in: NetworkListEntryUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(NetworkListEntry).filter(NetworkListEntry.list_id == lid, NetworkListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    data = e_in.model_dump(exclude_unset=True)
    if "value" in data and data["value"] is not None:
        try:
            data["value"] = validate_network_value(data["value"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for k, v in data.items():
        setattr(obj, k, v)
    _touch_list(db, NetworkList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-lists/network/{lid}/entries/{eid}")
def delete_network_entry(lid: int, eid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(NetworkListEntry).filter(NetworkListEntry.list_id == lid, NetworkListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(obj)
    _touch_list(db, NetworkList, lid)
    db.commit()
    return {"status": "ok"}


# --- ASN lists ---
@router.get("/security-lists/asn", response_model=List[AsnListResponse])
def list_asn_lists(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return [_asn_list_response(l) for l in db.query(AsnList).all()]


@router.post("/security-lists/asn", response_model=AsnListResponse)
def create_asn_list(a: AsnListCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = AsnList(name=a.name, description=a.description)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _asn_list_response(obj)


@router.put("/security-lists/asn/{lid}", response_model=AsnListResponse)
def update_asn_list(lid: int, a_in: AsnListUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(AsnList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="ASN list not found")
    for k, v in a_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return _asn_list_response(obj)


@router.delete("/security-lists/asn/{lid}")
def delete_asn_list(lid: int, force: bool = False, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(AsnList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="ASN list not found")
    refs = find_list_references(db, "asn", lid)
    in_use_msg = build_in_use_message(obj.name, refs)
    if in_use_msg:
        raise HTTPException(status_code=409, detail=in_use_msg)
    feed = refs["feed"]
    if feed and not force:
        raise HTTPException(status_code=409, detail=f"List is targeted by dynamic feed '{feed.name}'. Delete the feed first or pass force=true.")
    if feed:
        db.delete(feed)
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.get("/security-lists/asn/{lid}/entries", response_model=List[AsnListEntryResponse])
def list_asn_entries(lid: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    if not db.get(AsnList, lid):
        raise HTTPException(status_code=404, detail="ASN list not found")
    return db.query(AsnListEntry).filter(AsnListEntry.list_id == lid).all()


@router.post("/security-lists/asn/{lid}/entries", response_model=AsnListEntryResponse)
def create_asn_entry(lid: int, e: AsnListEntryCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    if not db.get(AsnList, lid):
        raise HTTPException(status_code=404, detail="ASN list not found")
    try:
        value = validate_asn_value(e.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    obj = AsnListEntry(list_id=lid, value=value, note=e.note)
    db.add(obj)
    _touch_list(db, AsnList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/security-lists/asn/{lid}/entries/{eid}", response_model=AsnListEntryResponse)
def update_asn_entry(lid: int, eid: int, e_in: AsnListEntryUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(AsnListEntry).filter(AsnListEntry.list_id == lid, AsnListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    data = e_in.model_dump(exclude_unset=True)
    if "value" in data and data["value"] is not None:
        try:
            data["value"] = validate_asn_value(data["value"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for k, v in data.items():
        setattr(obj, k, v)
    _touch_list(db, AsnList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-lists/asn/{lid}/entries/{eid}")
def delete_asn_entry(lid: int, eid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(AsnListEntry).filter(AsnListEntry.list_id == lid, AsnListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(obj)
    _touch_list(db, AsnList, lid)
    db.commit()
    return {"status": "ok"}


# --- GeoIP lists ---
@router.get("/security-lists/geo", response_model=List[GeoListResponse])
def list_geo_lists(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return [_geo_list_response(l) for l in db.query(GeoList).all()]


@router.get("/security-lists/geo/countries", response_model=List[GeoCountryOption])
def list_geo_countries(user=Depends(get_current_user), _=Depends(rate_limit)):
    """Return a sorted list of country codes and their full English names.

    Names are read from the MaxMind Country DB if it is present; otherwise a
    static ISO 3166-1 alpha-2 fallback mapping is used.
    """
    return get_country_options()


@router.post("/security-lists/geo", response_model=GeoListResponse)
def create_geo_list(a: GeoListCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = GeoList(name=a.name, description=a.description)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _geo_list_response(obj)


@router.put("/security-lists/geo/{lid}", response_model=GeoListResponse)
def update_geo_list(lid: int, a_in: GeoListUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(GeoList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="GeoIP list not found")
    for k, v in a_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return _geo_list_response(obj)


@router.delete("/security-lists/geo/{lid}")
def delete_geo_list(lid: int, force: bool = False, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(GeoList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="GeoIP list not found")
    refs = find_list_references(db, "geo", lid)
    in_use_msg = build_in_use_message(obj.name, refs)
    if in_use_msg:
        raise HTTPException(status_code=409, detail=in_use_msg)
    feed = refs["feed"]
    if feed and not force:
        raise HTTPException(status_code=409, detail=f"List is targeted by dynamic feed '{feed.name}'. Delete the feed first or pass force=true.")
    if feed:
        db.delete(feed)
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.get("/security-lists/geo/{lid}/entries", response_model=List[GeoListEntryResponse])
def list_geo_entries(lid: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    if not db.get(GeoList, lid):
        raise HTTPException(status_code=404, detail="GeoIP list not found")
    return db.query(GeoListEntry).filter(GeoListEntry.list_id == lid).all()


@router.post("/security-lists/geo/{lid}/entries", response_model=GeoListEntryResponse)
def create_geo_entry(lid: int, e: GeoListEntryCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    if not db.get(GeoList, lid):
        raise HTTPException(status_code=404, detail="GeoIP list not found")
    try:
        value = validate_country_code(e.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    obj = GeoListEntry(list_id=lid, value=value, note=e.note)
    db.add(obj)
    _touch_list(db, GeoList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/security-lists/geo/{lid}/entries/{eid}", response_model=GeoListEntryResponse)
def update_geo_entry(lid: int, eid: int, e_in: GeoListEntryUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(GeoListEntry).filter(GeoListEntry.list_id == lid, GeoListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    data = e_in.model_dump(exclude_unset=True)
    if "value" in data and data["value"] is not None:
        try:
            data["value"] = validate_country_code(data["value"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for k, v in data.items():
        setattr(obj, k, v)
    _touch_list(db, GeoList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-lists/geo/{lid}/entries/{eid}")
def delete_geo_entry(lid: int, eid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(GeoListEntry).filter(GeoListEntry.list_id == lid, GeoListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(obj)
    _touch_list(db, GeoList, lid)
    db.commit()
    return {"status": "ok"}


# --- JA4 lists ---
@router.get("/security-lists/ja4", response_model=List[Ja4ListResponse])
def list_ja4_lists(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return [_ja4_list_response(l) for l in db.query(Ja4List).all()]


@router.post("/security-lists/ja4", response_model=Ja4ListResponse)
def create_ja4_list(a: Ja4ListCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = Ja4List(name=a.name, description=a.description)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _ja4_list_response(obj)


@router.put("/security-lists/ja4/{lid}", response_model=Ja4ListResponse)
def update_ja4_list(lid: int, a_in: Ja4ListUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(Ja4List, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="JA4 list not found")
    for k, v in a_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return _ja4_list_response(obj)


@router.delete("/security-lists/ja4/{lid}")
def delete_ja4_list(lid: int, force: bool = False, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(Ja4List, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="JA4 list not found")
    refs = find_list_references(db, "ja4", lid)
    in_use_msg = build_in_use_message(obj.name, refs)
    if in_use_msg:
        raise HTTPException(status_code=409, detail=in_use_msg)
    feed = refs["feed"]
    if feed and not force:
        raise HTTPException(status_code=409, detail=f"List is targeted by dynamic feed '{feed.name}'. Delete the feed first or pass force=true.")
    if feed:
        db.delete(feed)
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.get("/security-lists/ja4/{lid}/entries", response_model=List[Ja4ListEntryResponse])
def list_ja4_entries(lid: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    if not db.get(Ja4List, lid):
        raise HTTPException(status_code=404, detail="JA4 list not found")
    return db.query(Ja4ListEntry).filter(Ja4ListEntry.list_id == lid).all()


@router.post("/security-lists/ja4/{lid}/entries", response_model=Ja4ListEntryResponse)
def create_ja4_entry(lid: int, e: Ja4ListEntryCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    if not db.get(Ja4List, lid):
        raise HTTPException(status_code=404, detail="JA4 list not found")
    try:
        value = validate_ja4_value(e.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    obj = Ja4ListEntry(list_id=lid, value=value, note=e.note)
    db.add(obj)
    _touch_list(db, Ja4List, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/security-lists/ja4/{lid}/entries/{eid}", response_model=Ja4ListEntryResponse)
def update_ja4_entry(lid: int, eid: int, e_in: Ja4ListEntryUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(Ja4ListEntry).filter(Ja4ListEntry.list_id == lid, Ja4ListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    data = e_in.model_dump(exclude_unset=True)
    if "value" in data and data["value"] is not None:
        try:
            data["value"] = validate_ja4_value(data["value"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for k, v in data.items():
        setattr(obj, k, v)
    _touch_list(db, Ja4List, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-lists/ja4/{lid}/entries/{eid}")
def delete_ja4_entry(lid: int, eid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(Ja4ListEntry).filter(Ja4ListEntry.list_id == lid, Ja4ListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(obj)
    _touch_list(db, Ja4List, lid)
    db.commit()
    return {"status": "ok"}


# --- Pattern lists ---
@router.get("/security-lists/pattern", response_model=List[PatternListResponse])
def list_pattern_lists(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return [_pattern_list_response(l) for l in db.query(PatternList).all()]


@router.post("/security-lists/pattern", response_model=PatternListResponse)
def create_pattern_list(a: PatternListCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = PatternList(name=a.name, description=a.description)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _pattern_list_response(obj)


@router.put("/security-lists/pattern/{lid}", response_model=PatternListResponse)
def update_pattern_list(lid: int, a_in: PatternListUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(PatternList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="Pattern list not found")
    for k, v in a_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return _pattern_list_response(obj)


@router.delete("/security-lists/pattern/{lid}")
def delete_pattern_list(lid: int, force: bool = False, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(PatternList, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="Pattern list not found")
    refs = find_list_references(db, "pattern", lid)
    in_use_msg = build_in_use_message(obj.name, refs)
    if in_use_msg:
        raise HTTPException(status_code=409, detail=in_use_msg)
    feed = refs["feed"]
    if feed and not force:
        raise HTTPException(status_code=409, detail=f"List is targeted by dynamic feed '{feed.name}'. Delete the feed first or pass force=true.")
    if feed:
        db.delete(feed)
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.get("/security-lists/pattern/{lid}/entries", response_model=List[PatternListEntryResponse])
def list_pattern_entries(lid: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    if not db.get(PatternList, lid):
        raise HTTPException(status_code=404, detail="Pattern list not found")
    return db.query(PatternListEntry).filter(PatternListEntry.list_id == lid).all()


@router.post("/security-lists/pattern/{lid}/entries", response_model=PatternListEntryResponse)
def create_pattern_entry(lid: int, e: PatternListEntryCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    if not db.get(PatternList, lid):
        raise HTTPException(status_code=404, detail="Pattern list not found")
    try:
        value = validate_pattern_value(e.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    obj = PatternListEntry(list_id=lid, value=value, note=e.note)
    db.add(obj)
    _touch_list(db, PatternList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/security-lists/pattern/{lid}/entries/{eid}", response_model=PatternListEntryResponse)
def update_pattern_entry(lid: int, eid: int, e_in: PatternListEntryUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(PatternListEntry).filter(PatternListEntry.list_id == lid, PatternListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    data = e_in.model_dump(exclude_unset=True)
    if "value" in data and data["value"] is not None:
        try:
            data["value"] = validate_pattern_value(data["value"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for k, v in data.items():
        setattr(obj, k, v)
    _touch_list(db, PatternList, lid)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-lists/pattern/{lid}/entries/{eid}")
def delete_pattern_entry(lid: int, eid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.query(PatternListEntry).filter(PatternListEntry.list_id == lid, PatternListEntry.id == eid).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(obj)
    _touch_list(db, PatternList, lid)
    db.commit()
    return {"status": "ok"}


# --- Dynamic feeds ---
@router.get("/security-lists/feeds", response_model=List[DynamicFeedResponse])
def list_dynamic_feeds(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return db.query(DynamicFeed).all()


@router.post("/security-lists/feeds", response_model=DynamicFeedResponse)
def create_dynamic_feed(f: DynamicFeedCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    target_list_id = f.target_list_id
    if target_list_id is None:
        # Create a new empty list named after the feed.
        if f.list_type == "network":
            lst = NetworkList(name=f.name)
        elif f.list_type == "asn":
            lst = AsnList(name=f.name)
        elif f.list_type == "ja4":
            lst = Ja4List(name=f.name)
        else:
            raise HTTPException(status_code=400, detail="list_type must be 'network', 'asn', or 'ja4'")
        db.add(lst)
        db.flush()
        target_list_id = lst.id
    else:
        # Validate the target list exists and matches the feed's list_type.
        if f.list_type == "network":
            if not db.get(NetworkList, target_list_id):
                raise HTTPException(status_code=404, detail="Target network list not found")
        elif f.list_type == "asn":
            if not db.get(AsnList, target_list_id):
                raise HTTPException(status_code=404, detail="Target ASN list not found")
        elif f.list_type == "ja4":
            if not db.get(Ja4List, target_list_id):
                raise HTTPException(status_code=404, detail="Target JA4 list not found")
        else:
            raise HTTPException(status_code=400, detail="list_type must be 'network', 'asn', or 'ja4'")
    obj = DynamicFeed(
        name=f.name,
        list_type=f.list_type,
        url=f.url,
        update_interval_hours=f.update_interval_hours,
        description=f.description,
        enabled=f.enabled,
        target_list_id=target_list_id,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    # Trigger an immediate refresh.
    try:
        refresh_dynamic_feed(db, obj)
        db.refresh(obj)
    except Exception:
        pass
    return obj


@router.put("/security-lists/feeds/{fid}", response_model=DynamicFeedResponse)
def update_dynamic_feed(fid: int, f_in: DynamicFeedUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(DynamicFeed, fid)
    if not obj:
        raise HTTPException(status_code=404, detail="Dynamic feed not found")
    for k, v in f_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-lists/feeds/{fid}")
def delete_dynamic_feed(fid: int, delete_list: bool = False, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(DynamicFeed, fid)
    if not obj:
        raise HTTPException(status_code=404, detail="Dynamic feed not found")
    target_list_id = obj.target_list_id
    list_type = obj.list_type
    db.delete(obj)
    if delete_list:
        if list_type == "network":
            lst = db.get(NetworkList, target_list_id)
        elif list_type == "asn":
            lst = db.get(AsnList, target_list_id)
        else:
            lst = db.get(Ja4List, target_list_id)
        if lst:
            db.delete(lst)
    db.commit()
    return {"status": "ok"}


@router.post("/security-lists/feeds/{fid}/refresh")
def refresh_feed_now(fid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(DynamicFeed, fid)
    if not obj:
        raise HTTPException(status_code=404, detail="Dynamic feed not found")
    result = refresh_dynamic_feed(db, obj)
    db.refresh(obj)
    return result


