//! Native Mattermost incoming webhook alert dispatcher.
//!
//! Formats [`TTLReport`] findings into Mattermost-compatible incoming webhook
//! payloads using Slack-compatible attachments with severity color borders,
//! optional `channel` and `username` overrides, and a Markdown alert card in
//! Mattermost's `props.card` parameter.

use std::fmt;
use std::time::Duration;

use reqwest::{Client, Url};
use sentinel_core::{AlertMinLevel, RiskLevel, StorageEntryReport, TTLReport};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Yellow attachment border color for `WARN` alerts.
pub const COLOR_WARN: &str = "#FFCC00";

/// Red attachment border color for `CRITICAL` and `ARCHIVED` alerts.
pub const COLOR_CRITICAL: &str = "#D0021B";

/// Default maximum number of retry attempts after an initial transient failure.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default base delay for exponential backoff between retry attempts.
pub const DEFAULT_BASE_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Default HTTP request timeout for webhook delivery.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum `Retry-After` header duration honored per retry attempt.
const MAX_RETRY_AFTER_SECS: u64 = 5;

/// Maximum number of decaying key rows included in the alert card table.
const MAX_TABLE_ENTRIES: usize = 50;

/// Errors returned by [`MattermostAlertDispatcher`].
#[derive(Debug, Error)]
pub enum MattermostError {
    /// The configured webhook URL is malformed or uses a disallowed scheme.
    #[error("invalid Mattermost webhook URL: {0}")]
    InvalidWebhookUrl(String),

    /// The underlying HTTP client could not be constructed.
    #[error("failed to initialize Mattermost HTTP client: {0}")]
    ClientInit(String),

    /// Mattermost returned a non-retryable HTTP error status.
    #[error("Mattermost webhook rejected request with HTTP {status}: {message}")]
    HttpStatus { status: u16, message: String },

    /// A non-retryable network or transport failure occurred.
    #[error("Mattermost webhook transport error: {0}")]
    Transport(String),

    /// All retry attempts were exhausted for transient HTTP or transport errors.
    #[error("Mattermost webhook delivery failed after {attempts} attempts: {last_error}")]
    RetriesExhausted { attempts: u32, last_error: String },
}

/// Top-level JSON payload posted to a Mattermost incoming webhook endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MattermostPayload {
    /// Optional channel override (slug or `@username`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Optional display username override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Primary Markdown summary message.
    pub text: String,
    /// Slack-compatible attachment cards with color borders and structured fields.
    pub attachments: Vec<MattermostAttachment>,
    /// Mattermost-specific `props` metadata, including the Markdown side-panel card.
    pub props: MattermostProps,
}

/// Mattermost/Slack-compatible message attachment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MattermostAttachment {
    /// Plain-text fallback for notifications and clients that do not render attachments.
    pub fallback: String,
    /// Hex color border (`#FFCC00` for Warn, `#D0021B` for Critical/Archived).
    pub color: String,
    /// Attachment heading.
    pub title: String,
    /// Markdown body containing the table of decaying keys.
    pub text: String,
    /// Key-value summary fields displayed in the attachment.
    pub fields: Vec<MattermostField>,
    /// Attribution footer text.
    pub footer: String,
}

/// Structured key-value field within a [`MattermostAttachment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MattermostField {
    /// Whether this field can render side-by-side with adjacent short fields.
    pub short: bool,
    /// Field heading.
    pub title: String,
    /// Field value (supports Mattermost Markdown).
    pub value: String,
}

/// Mattermost-specific `props` object attached to an incoming webhook post.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MattermostProps {
    /// Formatted Markdown alert card rendered in Mattermost's post info panel.
    pub card: String,
}

/// Native Mattermost incoming webhook dispatcher with retry and formatting support.
pub struct MattermostAlertDispatcher {
    webhook_url: Url,
    channel: Option<String>,
    username: Option<String>,
    min_level: AlertMinLevel,
    max_retries: u32,
    base_retry_delay: Duration,
    client: Client,
}

impl fmt::Debug for MattermostAlertDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MattermostAlertDispatcher")
            .field("webhook_url", &"<redacted>")
            .field("channel", &self.channel)
            .field("username", &self.username)
            .field("min_level", &self.min_level)
            .field("max_retries", &self.max_retries)
            .field("base_retry_delay", &self.base_retry_delay)
            .finish_non_exhaustive()
    }
}

impl MattermostAlertDispatcher {
    /// Creates a new [`MattermostAlertDispatcher`] targeting the given incoming webhook URL.
    ///
    /// Requires `https://` unless pointing at a loopback host (`localhost`, `127.0.0.1`, `::1`)
    /// for local development or automated tests.
    pub fn new(webhook_url: impl AsRef<str>) -> Result<Self, MattermostError> {
        let parsed = validate_webhook_url(webhook_url.as_ref())?;
        let client = build_http_client(DEFAULT_TIMEOUT)?;

        Ok(Self {
            webhook_url: parsed,
            channel: None,
            username: None,
            min_level: AlertMinLevel::Warn,
            max_retries: DEFAULT_MAX_RETRIES,
            base_retry_delay: DEFAULT_BASE_RETRY_DELAY,
            client,
        })
    }

    /// Sets an optional Mattermost channel override (e.g. `"soroban-ops"`).
    ///
    /// Empty or whitespace-only values are ignored.
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        let trimmed = channel.into().trim().to_string();
        if !trimmed.is_empty() {
            self.channel = Some(trimmed);
        }
        self
    }

    /// Sets an optional Mattermost display username override (e.g. `"Soroban Sentinel"`).
    ///
    /// Empty or whitespace-only values are ignored.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        let trimmed = username.into().trim().to_string();
        if !trimmed.is_empty() {
            self.username = Some(trimmed);
        }
        self
    }

    /// Sets the minimum [`AlertMinLevel`] required to emit an alert.
    pub fn with_min_level(mut self, min_level: AlertMinLevel) -> Self {
        self.min_level = min_level;
        self
    }

    /// Sets the maximum number of retry attempts for transient failures (`429`, `5xx`, connect/timeout).
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the base backoff delay between retry attempts.
    pub fn with_base_retry_delay(mut self, delay: Duration) -> Self {
        self.base_retry_delay = delay;
        self
    }

    /// Configures a custom HTTP request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, MattermostError> {
        self.client = build_http_client(timeout)?;
        Ok(self)
    }

    /// Formats a [`TTLReport`] into a [`MattermostPayload`] when the report meets
    /// the configured [`AlertMinLevel`]. Returns `None` when no alert should be sent.
    pub fn build_payload(&self, report: &TTLReport) -> Option<MattermostPayload> {
        if !self.min_level.includes(report.overall_status) {
            return None;
        }

        let color = attachment_color(report.overall_status).to_string();
        let decaying: Vec<&StorageEntryReport> = report
            .entries
            .iter()
            .filter(|entry| entry.status != RiskLevel::Ok)
            .collect();

        let earliest_live_until = decaying
            .iter()
            .map(|entry| entry.live_until_ledger)
            .min()
            .map(|ledger| ledger.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        let decaying_table = render_decaying_keys_table(&decaying);

        let text = format!(
            "**Soroban Sentinel {} Alert** — Contract `{}` ({})",
            report.overall_status, report.contract_id, report.network
        );

        let fallback = format!(
            "Soroban Sentinel {} alert for contract {} ({}): current ledger {}, earliest live-until ledger {}, {} decaying key(s)",
            report.overall_status,
            report.contract_id,
            report.network,
            report.latest_ledger,
            earliest_live_until,
            decaying.len()
        );

        let fields = vec![
            MattermostField {
                short: false,
                title: "Contract ID".to_string(),
                value: format!("`{}`", report.contract_id),
            },
            MattermostField {
                short: true,
                title: "Network".to_string(),
                value: report.network.clone(),
            },
            MattermostField {
                short: true,
                title: "Status".to_string(),
                value: report.overall_status.to_string(),
            },
            MattermostField {
                short: true,
                title: "Current Ledger".to_string(),
                value: report.latest_ledger.to_string(),
            },
            MattermostField {
                short: true,
                title: "Live-Until Ledger".to_string(),
                value: earliest_live_until.clone(),
            },
        ];

        let card = format!(
            "### Soroban Sentinel {} Alert\n\n\
            - **Contract ID:** `{}`\n\
            - **Network:** `{}`\n\
            - **Current Ledger:** {}\n\
            - **Live-Until Ledger:** {}\n\
            - **Overall Status:** **{}**\n\n\
            #### Decaying Keys\n\n\
            {}",
            report.overall_status,
            report.contract_id,
            report.network,
            report.latest_ledger,
            earliest_live_until,
            report.overall_status,
            decaying_table
        );

        let attachment = MattermostAttachment {
            fallback,
            color,
            title: format!(
                "TTL Expiry Risk: {} ({})",
                report.overall_status, report.network
            ),
            text: decaying_table,
            fields,
            footer: "Soroban Sentinel".to_string(),
        };

        Some(MattermostPayload {
            channel: self.channel.clone(),
            username: self.username.clone(),
            text,
            attachments: vec![attachment],
            props: MattermostProps { card },
        })
    }

    /// Dispatches a Mattermost alert for the given [`TTLReport`].
    ///
    /// Returns `Ok(true)` if an alert was posted, `Ok(false)` if the report status
    /// was below the configured minimum alert level, or an error if delivery failed.
    pub async fn dispatch(&self, report: &TTLReport) -> Result<bool, MattermostError> {
        let Some(payload) = self.build_payload(report) else {
            return Ok(false);
        };

        let total_attempts = self.max_retries.saturating_add(1);
        let mut last_error = String::new();

        for attempt in 0..total_attempts {
            let response = self
                .client
                .post(self.webhook_url.clone())
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => return Ok(true),
                Ok(resp) => {
                    let status = resp.status();
                    let retry_after = parse_retry_after(&resp);
                    let body = resp.text().await.unwrap_or_default();
                    let detail = if body.trim().is_empty() {
                        status
                            .canonical_reason()
                            .unwrap_or("request failed")
                            .to_string()
                    } else {
                        body.trim().to_string()
                    };

                    let retryable = status.is_server_error() || status.as_u16() == 429;
                    if !retryable {
                        return Err(MattermostError::HttpStatus {
                            status: status.as_u16(),
                            message: detail,
                        });
                    }

                    last_error = format!("HTTP {}: {}", status.as_u16(), detail);
                    if attempt + 1 < total_attempts {
                        let delay = retry_after
                            .unwrap_or_else(|| backoff_delay(self.base_retry_delay, attempt));
                        tokio::time::sleep(delay).await;
                    }
                }
                Err(err) => {
                    let retryable = err.is_timeout() || err.is_connect();
                    if !retryable {
                        return Err(MattermostError::Transport(err.to_string()));
                    }

                    last_error = err.to_string();
                    if attempt + 1 < total_attempts {
                        let delay = backoff_delay(self.base_retry_delay, attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(MattermostError::RetriesExhausted {
            attempts: total_attempts,
            last_error,
        })
    }
}

fn validate_webhook_url(raw: &str) -> Result<Url, MattermostError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(MattermostError::InvalidWebhookUrl(
            "webhook URL must not be empty".to_string(),
        ));
    }

    let parsed =
        Url::parse(trimmed).map_err(|err| MattermostError::InvalidWebhookUrl(err.to_string()))?;

    let is_loopback = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
    });

    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_loopback) {
        return Err(MattermostError::InvalidWebhookUrl(
            "webhook URL must use https:// (or http:// for loopback endpoints)".to_string(),
        ));
    }

    if parsed.host_str().is_none() {
        return Err(MattermostError::InvalidWebhookUrl(
            "webhook URL must contain a valid host".to_string(),
        ));
    }

    Ok(parsed)
}

fn build_http_client(timeout: Duration) -> Result<Client, MattermostError> {
    Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| MattermostError::ClientInit(err.to_string()))
}

fn attachment_color(status: RiskLevel) -> &'static str {
    match status {
        RiskLevel::Critical | RiskLevel::Archived => COLOR_CRITICAL,
        RiskLevel::Warn | RiskLevel::Ok => COLOR_WARN,
    }
}

fn render_decaying_keys_table(entries: &[&StorageEntryReport]) -> String {
    if entries.is_empty() {
        return "_No decaying keys reported._".to_string();
    }

    let mut out = String::from(
        "| Key | Durability | Live-Until Ledger | Remaining Ledgers | Est. Days | Status |\n\
         | --- | --- | ---: | ---: | ---: | --- |\n",
    );

    for entry in entries.iter().take(MAX_TABLE_ENTRIES) {
        let escaped_key = entry.key_identifier.replace('|', "\\|");
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {:.2} | {} |\n",
            escaped_key,
            entry.durability,
            entry.live_until_ledger,
            entry.remaining_ledgers,
            entry.remaining_days,
            entry.status
        ));
    }

    if entries.len() > MAX_TABLE_ENTRIES {
        let omitted = entries.len() - MAX_TABLE_ENTRIES;
        out.push_str(&format!(
            "\n_...and {omitted} additional decaying key(s) omitted._"
        ));
    }

    out.trim_end().to_string()
}

fn parse_retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECS)))
}

fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let factor = 1u32.checked_shl(attempt.min(10)).unwrap_or(1024);
    base.saturating_mul(factor)
}
