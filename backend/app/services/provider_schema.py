"""Provider schema loader for the Terraform exporter.

Reads the JSON schema extracted from the Go provider binary
(`corex_provider_schema.json`, produced by `terraform providers schema -json`)
and derives per-resource field overrides so the exporter cannot drift from
the provider schema.

The schema is the single source of truth for:
  - Which attributes each resource supports (fields not in the schema are skipped)
  - Which attributes are computed (computed-only attributes are skipped on write)
  - Type information for type-overrides (list vs string vs map, etc.)

Manual overrides in PROVIDER_FIELD_OVERRIDES (in terraform_export.py) still
exist for cases where the DB column name differs from the provider attribute
name (renames) or where a DB field should be passed as a raw int FK rather
than resolved to a resource reference. The schema loader supplements these
by adding schema-derived skips on top of the manual overrides.
"""
import json
import os
from functools import lru_cache
from typing import Any, Dict, Set

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'corex_provider_schema.json')


@lru_cache(maxsize=1)
def _load_schema() -> Dict[str, Any]:
    """Load and cache the provider schema JSON."""
    with open(_SCHEMA_PATH) as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _resource_schemas() -> Dict[str, Dict[str, Any]]:
    """Return {resource_type: schema_block} for all corex_* resources.

    The keys are stripped of the 'corex_' prefix so callers can look up
    by resource_type (e.g. 'cache_config', 'mcp_server').
    """
    data = _load_schema()
    provider = data.get('provider_schemas', {})
    # There's exactly one provider (registry.terraform.io/ne4u/corex)
    for prov in provider.values():
        return {
            name.replace('corex_', '', 1): block
            for name, block in prov.get('resource_schemas', {}).items()
        }
    return {}


def get_resource_attributes(resource_type: str) -> Dict[str, Dict[str, Any]]:
    """Return {attribute_name: attribute_info} for a resource type.

    attribute_info has keys: computed, optional, required, type, sensitive.
    Returns {} if the resource type is not in the schema.
    """
    schemas = _resource_schemas()
    block = schemas.get(resource_type)
    if block is None:
        return {}
    return block.get('block', {}).get('attributes', {})


def get_computed_fields(resource_type: str) -> Set[str]:
    """Return the set of computed-only attribute names for a resource type.

    These are attributes the provider computes (server-side) and should
    NOT be written by the exporter. Includes 'id' by convention.
    """
    attrs = get_resource_attributes(resource_type)
    return {
        name for name, info in attrs.items()
        if info.get('computed') and not info.get('optional')
    }


def get_provider_field_names(resource_type: str) -> Set[str]:
    """Return the set of all attribute names the provider schema defines.

    Fields in the DB model but NOT in this set should be skipped (they're
    not supported by the provider).
    """
    return set(get_resource_attributes(resource_type).keys())


def get_attribute_type(resource_type: str, attr_name: str) -> Any:
    """Return the raw type descriptor for an attribute, or None."""
    attrs = get_resource_attributes(resource_type)
    info = attrs.get(attr_name)
    if info is None:
        return None
    return info.get('type')
