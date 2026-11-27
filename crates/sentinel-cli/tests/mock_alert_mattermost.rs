use std::time::Duration;

use clap::Parser;
use sentinel_cli::adapters::alert_mattermost::{
    MattermostAlertDispatcher, MattermostError, COLOR_CRITICAL, COLOR_WARN,
};
use sentinel_cli::commands::watch::build_mattermost_dispatcher;
use sentinel_cli::{Cli, Commands};
use sentinel_core::{
    AlertMinLevel, Durability, EntryType, RiskLevel, StorageEntryReport, TTLReport,
};
use serde_json::Value;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

fn sample_report(overall_status: RiskLevel, entries: Vec<StorageEntryReport>) -> TTLReport {
    TTLReport {
        contract_id: CONTRACT_ID.to_string(),
        network: "mainnet".to_string(),
        latest_ledger: 500_000,
        ledger_velocity_seconds: 5.0,
        burn_rate: Default::default(),
        entries,
        overall_status,
        archival_recommendations: Vec::new(),
        sac_asset_info: None,
        contract_code_hash: None,
        contract_bytecode_size: None,
        contract_upgrade: None,
    }
}

fn warn_report() -> TTLReport {
    sample_report(
        RiskLevel::Warn,
        vec![
            StorageEntryReport::new(
                "code_wasm",
                EntryType::ContractCode,
                Durability::Code,
                8192,
                900_000,
                400_000,
                2_000_000.0,
                23.15,
                RiskLevel::Ok,
            ),
            StorageEntryReport::new(
                "instance",
                EntryType::ContractInstance,
                Durability::Instance,
                512,
                580_000,
                80_000,
                400_000.0,
                4.63,
                RiskLevel::Warn,
            ),
            StorageEntryReport::new(
                "persistent:ADMIN",
                EntryType::PersistentData,
                Durability::Persistent,
                128,
                540_000,
                40_000,
                200_000.0,
                2.31,
                RiskLevel::Warn,
            ),
        ],
    )
}

fn critical_report(status: RiskLevel) -> TTLReport {
    sample_report(
        status,
        vec![StorageEntryReport::new(
            "persistent:TREASURY",
            EntryType::PersistentData,
            Durability::Persistent,
            256,
            505_000,
            5_000,
            25_000.0,
            0.29,
            status,
        )],
    )
}

#[tokio::test]
async fn warn_alert_posts_yellow_attachment_with_contract_ledgers_and_decaying_table() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/test-token"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let dispatcher = MattermostAlertDispatcher::new(format!("{}/hooks/test-token", server.uri()))
        .unwrap()
        .with_channel("soroban-ops")
        .with_username("Soroban Sentinel");

    let sent = dispatcher.dispatch(&warn_report()).await.unwrap();
    assert!(sent);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);

    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["channel"], "soroban-ops");
    assert_eq!(body["username"], "Soroban Sentinel");
    assert!(body["text"].as_str().unwrap().contains(CONTRACT_ID));
    assert!(body["text"].as_str().unwrap().contains("WARN"));

    let attachment = &body["attachments"][0];
    assert_eq!(attachment["color"], COLOR_WARN);
    assert_eq!(attachment["footer"], "Soroban Sentinel");

    let fields = attachment["fields"].as_array().unwrap();
    let find_field = |title: &str| {
        fields
            .iter()
            .find(|f| f["title"] == title)
            .and_then(|f| f["value"].as_str())
            .expect("expected field")
    };
    assert!(find_field("Contract ID").contains(CONTRACT_ID));
    assert_eq!(find_field("Current Ledger"), "500000");
    assert_eq!(find_field("Live-Until Ledger"), "540000");
    assert_eq!(find_field("Status"), "WARN");

    let table = attachment["text"].as_str().unwrap();
    assert!(table.contains("| Key | Durability | Live-Until Ledger |"));
    assert!(table.contains("`instance`"));
    assert!(table.contains("580000"));
    assert!(table.contains("`persistent:ADMIN`"));
    assert!(table.contains("540000"));
    assert!(
        !table.contains("code_wasm"),
        "healthy OK entries should not be listed in decaying keys table"
    );

    let card = body["props"]["card"].as_str().unwrap();
    assert!(card.contains(CONTRACT_ID));
    assert!(card.contains("500000"));
    assert!(card.contains("540000"));
    assert!(card.contains("`persistent:ADMIN`"));
}

#[tokio::test]
async fn critical_and_archived_alerts_use_red_attachment_border_and_omit_unset_overrides() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/critical"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;

    let dispatcher =
        MattermostAlertDispatcher::new(format!("{}/hooks/critical", server.uri())).unwrap();

    assert!(dispatcher
        .dispatch(&critical_report(RiskLevel::Critical))
        .await
        .unwrap());
    assert!(dispatcher
        .dispatch(&critical_report(RiskLevel::Archived))
        .await
        .unwrap());

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);

    for req in requests {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        assert!(body.get("channel").is_none());
        assert!(body.get("username").is_none());
        assert_eq!(body["attachments"][0]["color"], COLOR_CRITICAL);
        assert!(body["attachments"][0]["text"]
            .as_str()
            .unwrap()
            .contains("persistent:TREASURY"));
    }
}

#[tokio::test]
async fn ok_report_and_below_min_level_do_not_send_http_post() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/quiet"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let warn_dispatcher =
        MattermostAlertDispatcher::new(format!("{}/hooks/quiet", server.uri())).unwrap();
    let ok_report = sample_report(
        RiskLevel::Ok,
        vec![StorageEntryReport::new(
            "instance",
            EntryType::ContractInstance,
            Durability::Instance,
            256,
            900_000,
            400_000,
            2_000_000.0,
            23.15,
            RiskLevel::Ok,
        )],
    );
    assert!(!warn_dispatcher.dispatch(&ok_report).await.unwrap());

    let critical_dispatcher =
        MattermostAlertDispatcher::new(format!("{}/hooks/quiet", server.uri()))
            .unwrap()
            .with_min_level(AlertMinLevel::Critical);
    assert!(!critical_dispatcher.dispatch(&warn_report()).await.unwrap());
}

#[tokio::test]
async fn retries_transient_503_and_429_before_succeeding() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hooks/retry"))
        .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/hooks/retry"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("rate limited"),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/hooks/retry"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let dispatcher = MattermostAlertDispatcher::new(format!("{}/hooks/retry", server.uri()))
        .unwrap()
        .with_max_retries(3)
        .with_base_retry_delay(Duration::from_millis(5));

    let sent = dispatcher.dispatch(&warn_report()).await.unwrap();
    assert!(sent);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn exhausted_retries_on_persistent_500_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/fail"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .expect(3)
        .mount(&server)
        .await;

    let dispatcher = MattermostAlertDispatcher::new(format!("{}/hooks/fail", server.uri()))
        .unwrap()
        .with_max_retries(2)
        .with_base_retry_delay(Duration::from_millis(5));

    let err = dispatcher
        .dispatch(&critical_report(RiskLevel::Critical))
        .await
        .unwrap_err();

    match err {
        MattermostError::RetriesExhausted {
            attempts,
            last_error,
        } => {
            assert_eq!(attempts, 3);
            assert!(last_error.contains("500"));
        }
        other => panic!("expected RetriesExhausted, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn non_retryable_400_fails_immediately_without_retries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/bad-request"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid payload"))
        .expect(1)
        .mount(&server)
        .await;

    let dispatcher = MattermostAlertDispatcher::new(format!("{}/hooks/bad-request", server.uri()))
        .unwrap()
        .with_max_retries(3)
        .with_base_retry_delay(Duration::from_millis(5));

    let err = dispatcher.dispatch(&warn_report()).await.unwrap_err();
    match err {
        MattermostError::HttpStatus { status, message } => {
            assert_eq!(status, 400);
            assert!(message.contains("invalid payload"));
        }
        other => panic!("expected HttpStatus(400), got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn validates_webhook_urls_and_redacts_secret_in_debug() {
    assert!(matches!(
        MattermostAlertDispatcher::new(""),
        Err(MattermostError::InvalidWebhookUrl(_))
    ));
    assert!(matches!(
        MattermostAlertDispatcher::new("not-a-url"),
        Err(MattermostError::InvalidWebhookUrl(_))
    ));
    assert!(matches!(
        MattermostAlertDispatcher::new("http://mattermost.example.com/hooks/secret"),
        Err(MattermostError::InvalidWebhookUrl(_))
    ));
    assert!(matches!(
        MattermostAlertDispatcher::new("ftp://mattermost.example.com/hooks/secret"),
        Err(MattermostError::InvalidWebhookUrl(_))
    ));

    let dispatcher =
        MattermostAlertDispatcher::new("https://mattermost.example.com/hooks/super-secret-token")
            .unwrap()
            .with_channel("ops")
            .with_username("sentinel");
    let debug = format!("{dispatcher:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(debug.contains("<redacted>"));
}

#[tokio::test]
async fn watch_cli_parses_alert_mattermost_and_builds_working_dispatcher() {
    let server = MockServer::start().await;
    let webhook_url = format!("{}/hooks/watch-secret-token", server.uri());

    Mock::given(method("POST"))
        .and(path("/hooks/watch-secret-token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cli = Cli::try_parse_from([
        "sentinel",
        "watch",
        CONTRACT_ID,
        "--alert-mattermost",
        &webhook_url,
        "--alert-mattermost-channel",
        "sec-ops",
        "--alert-mattermost-username",
        "sentinel-watch",
        "--alert-min-level",
        "critical",
    ])
    .unwrap();

    let debug = format!("{cli:?}");
    assert!(
        !debug.contains("watch-secret-token"),
        "WatchArgs Debug output must not expose webhook URL"
    );

    let Commands::Watch(watch_args) = cli.command else {
        panic!("expected Watch command");
    };
    assert_eq!(
        watch_args.alert_mattermost.as_deref(),
        Some(webhook_url.as_str())
    );
    assert_eq!(
        watch_args.alert_mattermost_channel.as_deref(),
        Some("sec-ops")
    );
    assert_eq!(
        watch_args.alert_mattermost_username.as_deref(),
        Some("sentinel-watch")
    );

    let dispatcher = build_mattermost_dispatcher(&watch_args)
        .unwrap()
        .expect("dispatcher should be built");

    // Warn is skipped because --alert-min-level critical was configured
    assert!(!dispatcher.dispatch(&warn_report()).await.unwrap());

    // Critical is dispatched with channel & username overrides
    assert!(dispatcher
        .dispatch(&critical_report(RiskLevel::Critical))
        .await
        .unwrap());

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["channel"], "sec-ops");
    assert_eq!(body["username"], "sentinel-watch");
    assert_eq!(body["attachments"][0]["color"], COLOR_CRITICAL);

    // Omitting --alert-mattermost yields Ok(None)
    let cli_none = Cli::try_parse_from(["sentinel", "watch", CONTRACT_ID]).unwrap();
    let Commands::Watch(watch_none) = cli_none.command else {
        panic!("expected Watch command");
    };
    assert!(build_mattermost_dispatcher(&watch_none).unwrap().is_none());
}
