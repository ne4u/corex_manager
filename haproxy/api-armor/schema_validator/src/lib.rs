//! API Armor schema validator — JSON Schema validation for API request bodies.
//!
//! Validates parsed JSON request bodies against JSON Schema definitions derived
//! from OpenAPI specs or learned from traffic. The validator supports a subset
//! of JSON Schema Draft 2020-12 sufficient for API request validation:
//! - type (string, number, integer, boolean, object, array, null)
//! - properties (object)
//! - required (object)
//! - items (array)
//! - minLength, maxLength (string)
//! - minimum, maximum (number/integer)
//! - enum
//! - pattern (regex — basic glob-like matching)
//! - additionalProperties (bool or schema)

/// Validation result.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        ValidationResult {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn fail(msg: impl Into<String>) -> Self {
        ValidationResult {
            valid: false,
            errors: vec![msg.into()],
        }
    }

    pub fn add_error(&mut self, msg: impl Into<String>) {
        self.valid = false;
        self.errors.push(msg.into());
    }
}

/// Validate a JSON value against a JSON Schema.
/// The schema should be a serde_json::Value following JSON Schema conventions.
pub fn validate(value: &serde_json::Value, schema: &serde_json::Value) -> ValidationResult {
    let mut result = ValidationResult::ok();
    validate_value(value, schema, "", &mut result);
    result
}

fn validate_value(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
    result: &mut ValidationResult,
) {
    // Get the schema type
    let schema_obj = match schema.as_object() {
        Some(obj) => obj,
        None => return, // No schema object = no validation
    };

    // Check type
    if let Some(type_val) = schema_obj.get("type") {
        if !check_type(value, type_val) {
            result.add_error(format!(
                "{}: expected type {:?}, got {}",
                path_or_root(path),
                type_val,
                json_type_name(value)
            ));
            return;
        }
    }

    // Check enum
    if let Some(enum_arr) = schema_obj.get("enum") {
        if let Some(enum_vals) = enum_arr.as_array() {
            if !enum_vals.contains(value) {
                result.add_error(format!(
                    "{}: value not in enum {:?}",
                    path_or_root(path),
                    enum_arr
                ));
            }
        }
    }

    // String constraints
    if let Some(s) = value.as_str() {
        if let Some(min_len) = schema_obj.get("minLength").and_then(|v| v.as_u64()) {
            if (s.len() as u64) < min_len {
                result.add_error(format!(
                    "{}: string length {} < minLength {}",
                    path_or_root(path),
                    s.len(),
                    min_len
                ));
            }
        }
        if let Some(max_len) = schema_obj.get("maxLength").and_then(|v| v.as_u64()) {
            if (s.len() as u64) > max_len {
                result.add_error(format!(
                    "{}: string length {} > maxLength {}",
                    path_or_root(path),
                    s.len(),
                    max_len
                ));
            }
        }
        if let Some(pattern) = schema_obj.get("pattern").and_then(|v| v.as_str()) {
            if !match_pattern(s, pattern) {
                result.add_error(format!(
                    "{}: string does not match pattern {:?}",
                    path_or_root(path),
                    pattern
                ));
            }
        }
    }

    // Number constraints
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema_obj.get("minimum").and_then(|v| v.as_f64()) {
            if n < min {
                result.add_error(format!("{}: value {} < minimum {}", path_or_root(path), n, min));
            }
        }
        if let Some(max) = schema_obj.get("maximum").and_then(|v| v.as_f64()) {
            if n > max {
                result.add_error(format!("{}: value {} > maximum {}", path_or_root(path), n, max));
            }
        }
    }

    // Object validation
    if let Some(obj) = value.as_object() {
        // Check required fields
        if let Some(required) = schema_obj.get("required").and_then(|v| v.as_array()) {
            for req in required {
                if let Some(req_name) = req.as_str() {
                    if !obj.contains_key(req_name) {
                        result.add_error(format!("{}: missing required field {:?}", path_or_root(path), req_name));
                    }
                }
            }
        }

        // Validate properties
        if let Some(properties) = schema_obj.get("properties").and_then(|v| v.as_object()) {
            for (key, prop_schema) in properties {
                if let Some(val) = obj.get(key) {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    validate_value(val, prop_schema, &child_path, result);
                }
            }
        }

        // Check additionalProperties
        if let Some(addl) = schema_obj.get("additionalProperties") {
            if let Some(properties) = schema_obj.get("properties").and_then(|v| v.as_object()) {
                match addl {
                    serde_json::Value::Bool(false) => {
                        for key in obj.keys() {
                            if !properties.contains_key(key) {
                                result.add_error(format!(
                                    "{}: additional property {:?} not allowed",
                                    path_or_root(path),
                                    key
                                ));
                            }
                        }
                    }
                    serde_json::Value::Object(_) => {
                        for (key, val) in obj {
                            if !properties.contains_key(key) {
                                let child_path = if path.is_empty() {
                                    key.clone()
                                } else {
                                    format!("{}.{}", path, key)
                                };
                                validate_value(val, addl, &child_path, result);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Array validation
    if let Some(arr) = value.as_array() {
        if let Some(items_schema) = schema_obj.get("items") {
            for (i, item) in arr.iter().enumerate() {
                let child_path = format!("{}[{}]", path, i);
                validate_value(item, items_schema, &child_path, result);
            }
        }
        if let Some(min_items) = schema_obj.get("minItems").and_then(|v| v.as_u64()) {
            if (arr.len() as u64) < min_items {
                result.add_error(format!(
                    "{}: array length {} < minItems {}",
                    path_or_root(path),
                    arr.len(),
                    min_items
                ));
            }
        }
        if let Some(max_items) = schema_obj.get("maxItems").and_then(|v| v.as_u64()) {
            if (arr.len() as u64) > max_items {
                result.add_error(format!(
                    "{}: array length {} > maxItems {}",
                    path_or_root(path),
                    arr.len(),
                    max_items
                ));
            }
        }
    }
}

/// Check if a JSON value matches the expected type.
fn check_type(value: &serde_json::Value, type_val: &serde_json::Value) -> bool {
    let type_str = match type_val.as_str() {
        Some(s) => s,
        None => {
            // Could be an array of types
            if let Some(types) = type_val.as_array() {
                return types.iter().any(|t| check_type(value, t));
            }
            return true; // Unknown type format = no constraint
        }
    };

    match type_str {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64() || (value.is_f64() && value.as_f64().map_or(false, |f| f.fract() == 0.0)),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true, // Unknown type = no constraint
    }
}

/// Get a human-readable type name for a JSON value.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Format a path for error messages.
fn path_or_root(path: &str) -> String {
    if path.is_empty() {
        "root".to_string()
    } else {
        path.to_string()
    }
}

/// Basic pattern matching (supports prefix*, *suffix, *contains*, and exact match).
/// Full regex is not available in this no-std-friendly context.
fn match_pattern(s: &str, pattern: &str) -> bool {
    // Simple wildcard matching
    if pattern.starts_with('*') && pattern.ends_with('*') {
        s.contains(&pattern[1..pattern.len() - 1])
    } else if pattern.starts_with('*') {
        s.ends_with(&pattern[1..])
    } else if pattern.ends_with('*') {
        s.starts_with(&pattern[..pattern.len() - 1])
    } else {
        s == pattern
    }
}

/// Infer a JSON Schema from a JSON value.
/// This is used by the learned schema feature to build schemas from observed traffic.
pub fn infer_schema(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Null => serde_json::json!({"type": "null"}),
        serde_json::Value::Bool(_) => serde_json::json!({"type": "boolean"}),
        serde_json::Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                serde_json::json!({"type": "integer"})
            } else {
                serde_json::json!({"type": "number"})
            }
        }
        serde_json::Value::String(s) => {
            let mut schema = serde_json::json!({"type": "string"});
            if let Some(map) = schema.as_object_mut() {
                map.insert("minLength".to_string(), serde_json::json!(0));
                map.insert("maxLength".to_string(), serde_json::json!(s.len()));
            }
            schema
        }
        serde_json::Value::Array(arr) => {
            let items_schema = if arr.is_empty() {
                serde_json::json!({})
            } else {
                // Infer from first element
                infer_schema(&arr[0])
            };
            serde_json::json!({
                "type": "array",
                "items": items_schema,
                "minItems": 0,
                "maxItems": arr.len(),
            })
        }
        serde_json::Value::Object(obj) => {
            let mut properties = serde_json::Map::new();
            let mut required = Vec::new();
            for (key, val) in obj {
                properties.insert(key.clone(), infer_schema(val));
                required.push(serde_json::json!(key));
            }
            serde_json::json!({
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": true,
            })
        }
    }
}

/// Merge two schemas, broadening constraints to accommodate both observations.
/// Used by learned schema inference to merge schemas from multiple requests.
pub fn merge_schemas(s1: &serde_json::Value, s2: &serde_json::Value) -> serde_json::Value {
    // If types differ, return a permissive schema
    let t1 = s1.get("type").and_then(|v| v.as_str());
    let t2 = s2.get("type").and_then(|v| v.as_str());

    if t1 != t2 {
        // Different types — return union type
        if let (Some(t1), Some(t2)) = (t1, t2) {
            return serde_json::json!({"type": [t1, t2]});
        }
        return serde_json::json!({});
    }

    let mut merged = s1.clone();

    if t1 == Some("object") {
        // Merge properties
        let mut props = s1
            .get("properties")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        if let Some(s2_props) = s2.get("properties").and_then(|v| v.as_object()) {
            for (key, val2) in s2_props {
                if let Some(val1) = props.get(key) {
                    props.insert(key.clone(), merge_schemas(val1, val2));
                } else {
                    props.insert(key.clone(), val2.clone());
                }
            }
        }

        // Required = intersection (only fields required in both)
        let req1: Vec<String> = s1
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let req2: Vec<String> = s2
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let required: Vec<&String> = req1.iter().filter(|r| req2.contains(r)).collect();

        if let Some(map) = merged.as_object_mut() {
            map.insert("properties".to_string(), serde_json::Value::Object(props));
            map.insert(
                "required".to_string(),
                serde_json::Value::Array(
                    required.iter().map(|r| serde_json::json!(r)).collect(),
                ),
            );
        }
    } else if t1 == Some("string") {
        // Broaden maxLength, narrow minLength
        let max1 = s1.get("maxLength").and_then(|v| v.as_u64()).unwrap_or(0);
        let max2 = s2.get("maxLength").and_then(|v| v.as_u64()).unwrap_or(0);
        let min1 = s1.get("minLength").and_then(|v| v.as_u64()).unwrap_or(0);
        let min2 = s2.get("minLength").and_then(|v| v.as_u64()).unwrap_or(0);

        if let Some(map) = merged.as_object_mut() {
            map.insert("maxLength".to_string(), serde_json::json!(max1.max(max2)));
            map.insert("minLength".to_string(), serde_json::json!(min1.min(min2)));
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_simple_object() {
        let value = json!({"name": "test", "age": 30});
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name", "age"]
        });
        let result = validate(&value, &schema);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_missing_required() {
        let value = json!({"name": "test"});
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name", "age"]
        });
        let result = validate(&value, &schema);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("age")));
    }

    #[test]
    fn test_validate_wrong_type() {
        let value = json!({"name": 123, "age": 30});
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            }
        });
        let result = validate(&value, &schema);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("expected type")));
    }

    #[test]
    fn test_validate_string_constraints() {
        let value = json!("ab");
        let schema = json!({"type": "string", "minLength": 3, "maxLength": 10});
        let result = validate(&value, &schema);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("minLength")));
    }

    #[test]
    fn test_validate_number_constraints() {
        let value = json!(15);
        let schema = json!({"type": "integer", "minimum": 0, "maximum": 10});
        let result = validate(&value, &schema);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("maximum")));
    }

    #[test]
    fn test_validate_enum() {
        let value = json!("blue");
        let schema = json!({"type": "string", "enum": ["red", "green", "blue"]});
        let result = validate(&value, &schema);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_enum_fail() {
        let value = json!("yellow");
        let schema = json!({"type": "string", "enum": ["red", "green", "blue"]});
        let result = validate(&value, &schema);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_array() {
        let value = json!([1, 2, 3]);
        let schema = json!({
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 1,
            "maxItems": 5
        });
        let result = validate(&value, &schema);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_nested_object() {
        let value = json!({
            "user": {
                "name": "test",
                "address": {
                    "city": "NYC"
                }
            }
        });
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "address": {
                            "type": "object",
                            "properties": {
                                "city": {"type": "string"}
                            }
                        }
                    }
                }
            }
        });
        let result = validate(&value, &schema);
        assert!(result.valid);
    }

    #[test]
    fn test_infer_schema_simple() {
        let value = json!({"name": "test", "age": 30});
        let schema = infer_schema(&value);
        assert_eq!(schema.get("type").unwrap(), "object");
        assert!(schema.get("properties").is_some());
    }

    #[test]
    fn test_merge_schemas_same_type() {
        let s1 = json!({"type": "string", "maxLength": 10, "minLength": 2});
        let s2 = json!({"type": "string", "maxLength": 20, "minLength": 1});
        let merged = merge_schemas(&s1, &s2);
        assert_eq!(merged.get("maxLength").unwrap(), 20);
        assert_eq!(merged.get("minLength").unwrap(), 1);
    }

    #[test]
    fn test_merge_schemas_different_types() {
        let s1 = json!({"type": "string"});
        let s2 = json!({"type": "integer"});
        let merged = merge_schemas(&s1, &s2);
        let types = merged.get("type").unwrap().as_array().unwrap();
        assert_eq!(types.len(), 2);
    }
}
