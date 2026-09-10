//! Regex validation for custom DLP/guardrail patterns.
//!
//! Authoritative Rust-side check: compiles the pattern with the `regex` crate
//! (so unsupported features fail to compile) and applies the ReDoS heuristic.
//! The backend `/api/v1/mcp/validate-regex` endpoint mirrors this with a
//! Python heuristic; this module is used by the Rust gateway directly and by
//! tests to keep the two in sync.

use regex::{Regex, RegexBuilder};

/// Reason a regex was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexValidationError {
    /// Empty pattern.
    Empty,
    /// Invalid syntax / unsupported feature (Rust `regex` compile failure).
    Invalid(String),
    /// ReDoS-vulnerable pattern.
    Redos,
}

/// Validate a regex pattern. Returns `Ok(())` if it compiles and is not a
/// ReDoS risk, otherwise the rejection reason.
pub fn validate_regex(pattern: &str, case_insensitive: bool, multi_line: bool) -> Result<(), RegexValidationError> {
    if pattern.trim().is_empty() {
        return Err(RegexValidationError::Empty);
    }

    // ReDoS heuristic first (cheap, on the pattern string).
    if is_redos(pattern) {
        return Err(RegexValidationError::Redos);
    }

    // Compile with the Rust regex engine — unsupported features (backreferences,
    // lookaround, possessive quantifiers, atomic groups) fail here.
    let mut builder = RegexBuilder::new(pattern);
    if case_insensitive {
        builder.case_insensitive(true);
    }
    if multi_line {
        builder.multi_line(true);
    }
    match builder.build() {
        Ok(_) => Ok(()),
        Err(e) => Err(RegexValidationError::Invalid(e.to_string())),
    }
}

/// ReDoS heuristic: nested quantifiers or alternation-with-quantifier.
pub fn is_redos(pattern: &str) -> bool {
    let redos = [
        r"\([^)]*[+*][^)]*\)[+*]",
        r"\([^)]*\|[^)]*\)[+*]",
    ];
    redos.iter().any(|rp| Regex::new(rp).map(|re| re.is_match(pattern)).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pattern_ok() {
        assert!(validate_regex(r"\bsecret\b", true, false).is_ok());
        assert!(validate_regex(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", true, false).is_ok());
    }

    #[test]
    fn empty_rejected() {
        assert_eq!(validate_regex("", true, false), Err(RegexValidationError::Empty));
        assert_eq!(validate_regex("   ", true, false), Err(RegexValidationError::Empty));
    }

    #[test]
    fn redos_rejected() {
        assert_eq!(validate_regex(r"(a+)+b", true, false), Err(RegexValidationError::Redos));
        assert_eq!(validate_regex(r"(a|b)+", true, false), Err(RegexValidationError::Redos));
    }

    #[test]
    fn rust_unsupported_rejected() {
        // Backreference — Rust regex rejects.
        let r = validate_regex(r"(a)\1", true, false);
        assert!(matches!(r, Err(RegexValidationError::Invalid(_))));
        // Lookahead — Rust regex rejects.
        let r = validate_regex(r"foo(?=bar)", true, false);
        assert!(matches!(r, Err(RegexValidationError::Invalid(_))));
        // Lookbehind — Rust regex rejects.
        let r = validate_regex(r"(?<=foo)bar", true, false);
        assert!(matches!(r, Err(RegexValidationError::Invalid(_))));
    }

    #[test]
    fn flags_applied() {
        // Case-insensitive flag should let it compile and match — just checks no error.
        assert!(validate_regex(r"SECRET", true, false).is_ok());
        assert!(validate_regex(r"^foo$", false, true).is_ok());
    }
}
