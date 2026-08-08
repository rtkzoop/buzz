//! Provider-local redaction for untrusted Box API and command output.
//!
//! Box command output can contain arbitrary process output, including values
//! copied from the launch environment. This module intentionally stays local
//! to the provider so every provider error path can add ambient credentials
//! without relying on a desktop-side cleanup pass.

use std::fmt;
use url::Url;

const TOKEN_PREFIXES: [&str; 8] = [
    "github_pat_",
    "sprt_tok_",
    "nsec1",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
];

/// Bounded exact and token-pattern redactor.
#[derive(Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Redactor")
            .field("secret_count", &self.secrets.len())
            .finish()
    }
}

impl Redactor {
    /// Build a redactor from all non-empty values that may appear in output.
    /// Exact values are replaced longest-first so short values cannot partially
    /// expose a longer credential.
    pub fn from_values(values: impl IntoIterator<Item = String>) -> Self {
        let mut redactor = Self::default();
        for value in values {
            redactor = redactor.with_value(value);
        }
        redactor
    }

    /// Add one value and any URL userinfo component to the redaction set.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        let value = value.into();
        if value.is_empty() {
            return self;
        }
        self.secrets.push(value.clone());
        if let Ok(url) = Url::parse(&value) {
            let username = url.username();
            let password = url.password();
            if !username.is_empty() {
                self.secrets.push(username.to_string());
            }
            if let Some(password) = password.filter(|password| !password.is_empty()) {
                self.secrets.push(password.to_string());
            }
            if !username.is_empty() {
                if let Some(password) = password.filter(|password| !password.is_empty()) {
                    self.secrets.push(format!("{}:{password}", username));
                }
            }
        }
        self.normalize();
        self
    }

    /// Replace exact secret values, token-shaped credentials, and control
    /// characters in untrusted provider output.
    pub fn redact(&self, input: &str) -> String {
        let mut output = input.to_string();
        for secret in &self.secrets {
            output = output.replace(secret, "[redacted]");
        }
        for prefix in TOKEN_PREFIXES {
            output = redact_token_prefix(&output, prefix);
        }
        output
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
            .take(512)
            .collect()
    }

    fn normalize(&mut self) {
        self.secrets.retain(|value| !value.is_empty());
        self.secrets
            .sort_by_key(|value| std::cmp::Reverse(value.len()));
        self.secrets.dedup();
    }
}

fn redact_token_prefix(input: &str, prefix: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(index) = remaining.find(prefix) {
        output.push_str(&remaining[..index]);
        let token = &remaining[index..];
        let end = token.find(char::is_whitespace).unwrap_or(token.len());
        output.push_str("[redacted]");
        remaining = &token[end..];
    }
    output.push_str(remaining);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_overlapping_values_longest_first() {
        let redactor = Redactor::from_values(["secret".to_string(), "secret-value".to_string()]);
        assert_eq!(redactor.redact("secret-value"), "[redacted]");
    }

    #[test]
    fn redacts_url_userinfo_and_token_patterns() {
        let redactor =
            Redactor::from_values(["https://alice:password@example.invalid".to_string()]);
        let output = redactor.redact("alice:password nsec1abc github_pat_xyz");
        assert!(!output.contains("alice:password"));
        assert!(!output.contains("nsec1abc"));
        assert!(!output.contains("github_pat_xyz"));
    }
}
