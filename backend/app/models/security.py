from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, Float, ForeignKey, JSON
import sqlalchemy as sa
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class NetworkList(Base):
    __tablename__ = "network_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    entries = relationship("NetworkListEntry", back_populates="list", cascade="all, delete-orphan")


class NetworkListEntry(Base):
    __tablename__ = "network_list_entries"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("network_lists.id"), nullable=False)
    value = Column(String, nullable=False)  # single IP or CIDR block (canonical form)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    list = relationship("NetworkList", back_populates="entries")


class AsnList(Base):
    __tablename__ = "asn_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    entries = relationship("AsnListEntry", back_populates="list", cascade="all, delete-orphan")


class AsnListEntry(Base):
    __tablename__ = "asn_list_entries"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("asn_lists.id"), nullable=False)
    value = Column(String, nullable=False)  # ASN in normalized AS<n> form
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    list = relationship("AsnList", back_populates="entries")


class GeoList(Base):
    __tablename__ = "geo_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    entries = relationship("GeoListEntry", back_populates="list", cascade="all, delete-orphan")


class GeoListEntry(Base):
    __tablename__ = "geo_list_entries"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("geo_lists.id"), nullable=False)
    value = Column(String, nullable=False)  # ISO 3166-1 alpha-2 country code (uppercased)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    list = relationship("GeoList", back_populates="entries")


class Ja4List(Base):
    __tablename__ = "ja4_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    entries = relationship("Ja4ListEntry", back_populates="list", cascade="all, delete-orphan")


class Ja4ListEntry(Base):
    __tablename__ = "ja4_list_entries"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("ja4_lists.id"), nullable=False)
    value = Column(String, nullable=False)  # JA4 fingerprint (normalized lowercase)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    list = relationship("Ja4List", back_populates="entries")


class PatternList(Base):
    __tablename__ = "pattern_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    entries = relationship("PatternListEntry", back_populates="list", cascade="all, delete-orphan")


class PatternListEntry(Base):
    __tablename__ = "pattern_list_entries"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("pattern_lists.id"), nullable=False)
    value = Column(String, nullable=False)  # regex pattern (stored as-is)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    list = relationship("PatternList", back_populates="entries")


class DynamicFeed(Base):
    __tablename__ = "dynamic_feeds"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    list_type = Column(String, nullable=False)  # network, asn, ja4
    url = Column(String, nullable=False)
    update_interval_hours = Column(Integer, default=24)
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    target_list_id = Column(Integer, nullable=False)  # FK to network_lists.id, asn_lists.id, or ja4_lists.id (polymorphic by list_type)
    last_updated_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    last_entry_count = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class SecurityRule(Base):
    __tablename__ = "security_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0, index=True, nullable=False)
    listener_ids = Column(JSON, default=list, nullable=True)  # [] = all listeners
    expression = Column(Text, nullable=False)  # source of truth (Cloudflare-style text)
    expression_ast = Column(JSON, nullable=True)  # parsed AST, re-derived on save
    action = Column(String, default="block")  # block|allow|redirect|custom_response|challenge|skip_rules|skip_rules_ratelimit|skip_rules_waf|skip_all
    log = Column(Boolean, default=True)  # record action in request log line
    no_log = Column(Boolean, default=False)  # suppress entire request log line for matching requests
    status_code = Column(Integer, nullable=True)  # block/custom_response status (default 403 at emit time)
    redirect_url = Column(String, nullable=True)  # URL for redirect action
    redirect_code = Column(Integer, nullable=True)  # HTTP status code for redirect (default 302)
    error_page_id = Column(Integer, nullable=True)  # FK to custom_error_pages for custom_response action
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class RiskRuleset(Base):
    __tablename__ = "risk_rulesets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # display name (not unique; slug is unique)
    slug = Column(String, unique=True, index=True, nullable=False)  # HAProxy var name
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0)  # tab ordering
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    rules = relationship("RiskRule", back_populates="ruleset", cascade="all, delete-orphan")


class RiskRule(Base):
    __tablename__ = "risk_rules"
    __table_args__ = (
        sa.UniqueConstraint('name', 'ruleset_id', name='uq_risk_rules_name_ruleset'),
    )

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)  # unique per (name, ruleset_id)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0, index=True, nullable=False)
    listener_ids = Column(JSON, default=list, nullable=True)  # [] = all listeners
    expression = Column(Text, nullable=False)  # source of truth (Cloudflare-style text)
    expression_ast = Column(JSON, nullable=True)  # parsed AST, re-derived on save
    points = Column(Integer, nullable=False)  # +/- integer points added on match
    category = Column(String, nullable=True)  # auto-derived from expression, user-overridable
    log = Column(Boolean, default=True)  # record matched rule name in txn.risk.rules_hit
    ruleset_id = Column(Integer, ForeignKey("risk_rulesets.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    ruleset = relationship("RiskRuleset", back_populates="rules")


__all__ = ['AsnList', 'AsnListEntry', 'DynamicFeed', 'GeoList', 'GeoListEntry', 'Ja4List', 'Ja4ListEntry', 'NetworkList', 'NetworkListEntry', 'PatternList', 'PatternListEntry', 'RiskRule', 'RiskRuleset', 'SecurityRule']
