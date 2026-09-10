//! Compiled-in DLP detector + guardrail pack patterns.
//!
//! These are *patterns only* — rules remain optional and bundle-configured.
//! A rule references a built-in by `detector`/`pack` id; the pattern is looked
//! up here so it is compiled once (Lazy) rather than per request.

use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};

/// A built-in DLP detector (single pattern).
pub struct DetectorPattern {
    pub id: &'static str,
    pub regex: &'static str,
}

/// A built-in guardrail pack (multiple patterns).
pub struct PackPatterns {
    pub id: &'static str,
    pub patterns: &'static [&'static str],
}

/// Built-in DLP detectors (ids + patterns match `shared/dlp_core.py`).
pub static DETECTORS: &[DetectorPattern] = &[
    DetectorPattern { id: "email", regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" },
    DetectorPattern { id: "phone", regex: r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b" },
    DetectorPattern { id: "ssn", regex: r"\b\d{3}-\d{2}-\d{4}\b" },
    DetectorPattern { id: "credit_card", regex: r"\b(?:\d[ -]*?){13,19}\b" },
    DetectorPattern { id: "ip", regex: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" },
    DetectorPattern { id: "aws_key", regex: r"\bAKIA[0-9A-Z]{16}\b" },
    DetectorPattern { id: "private_key", regex: r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----" },
    DetectorPattern { id: "github_token", regex: r"\bgh[pousr]_[A-Za-z0-9]{36}\b" },
    DetectorPattern { id: "slack_token", regex: r"\bxox[baprs]-[A-Za-z0-9-]+\b" },
];

/// Built-in guardrail packs (ids + patterns match `shared/guardrails_core.py`).
pub static PACKS: &[PackPatterns] = &[
    PackPatterns {
        id: "builtin:jailbreak_v1",
        patterns: &[
            r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b",
            r"\bDAN\b.*\bdo\s+anything\s+now\b",
            r"\byou\s+are\s+(?:now|a)\s+(?:DAN|freed|unrestricted)\b",
            r"\bjailbreak\b",
            r"\bdeveloper\s+mode\b",
            r"\bact\s+as\s+(?:if\s+you\s+(?:are|have)\s+no\s+(?:rules|restrictions))\b",
            r"\bpretend\s+(?:that\s+)?you\s+(?:have\s+no|don'?t\s+have\s+(?:any\s+)?(?:rules|restrictions|guidelines))\b",
            r"\bSTAN\b.*\bstrive\s+to\s+avoid\s+norms\b",
            r"\bevil\s+mode\b",
            r"\bgod\s+mode\b",
            r"\bun(?:censored|filtered|restricted)\s+mode\b",
            r"\bAIM\b.*\balways\s+intelligent\s+and\s+machiavellian\b",
        ],
    },
    PackPatterns {
        id: "builtin:instruction_override",
        patterns: &[
            r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?|directives?)\b",
            r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b",
            r"\bforget\s+(?:everything|all\s+(?:previous|prior)\s+(?:instructions?|rules?))\b",
            r"\byou\s+are\s+now\s+(?:in\s+)?(?:a\s+)?(?:different|new)\s+mode\b",
            r"\bfrom\s+now\s+on[,\s]+you\s+(?:are|will|must|should)\b",
            r"\boverride\s+(?:your|the)\s+(?:system|safety|content)\s+(?:prompt|instructions?|rules?)\b",
            r"\bnew\s+instructions?\s*:\s*\b",
            r"\bsystem\s+prompt\s*:\s*\b",
            r"\breveal\s+(?:your|the)\s+(?:system|initial)\s+prompt\b",
            r"\bshow\s+me\s+your\s+(?:system|initial)\s+(?:prompt|instructions?)\b",
        ],
    },
    PackPatterns {
        id: "builtin:obfuscation",
        patterns: &[
            r"[A-Za-z0-9+/]{40,}={0,2}",
            r"\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}",
            r"\brot13\b",
            r"\bbase64\s*(?:decode|encoded)\b",
            r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
        ],
    },
];

/// Look up a built-in DLP detector pattern string by id.
pub fn detector_pattern(id: &str) -> Option<&'static str> {
    DETECTORS.iter().find(|d| d.id == id).map(|d| d.regex)
}

/// Look up a built-in guardrail pack's pattern strings by id.
pub fn pack_patterns(id: &str) -> Option<&'static [&'static str]> {
    PACKS.iter().find(|p| p.id == id).map(|p| p.patterns)
}

/// Lazily-compiled DLP detector regexes (case-insensitive).
static COMPILED_DETECTORS: Lazy<std::collections::HashMap<&'static str, Regex>> = Lazy::new(|| {
    let mut m = std::collections::HashMap::new();
    for d in DETECTORS {
        if let Ok(re) = RegexBuilder::new(d.regex).case_insensitive(true).build() {
            m.insert(d.id, re);
        }
    }
    m
});

/// Look up a compiled DLP detector regex by id.
pub fn detector_regex(id: &str) -> Option<&'static Regex> {
    COMPILED_DETECTORS.get(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_detectors() {
        assert!(detector_pattern("credit_card").is_some());
        assert!(detector_pattern("nonexistent").is_none());
        assert!(pack_patterns("builtin:jailbreak_v1").is_some());
        assert_eq!(pack_patterns("builtin:jailbreak_v1").unwrap().len(), 12);
    }

    #[test]
    fn credit_card_matches() {
        let re = detector_regex("credit_card").unwrap();
        assert!(re.is_match("4111 1111 1111 1111"));
        assert!(!re.is_match("short"));
    }
}
