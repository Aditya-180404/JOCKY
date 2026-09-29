use chrono::Utc;
use jocky_runtime_correlation::{
    entities::NormalizedEntities,
    ioc::{Indicator, IndicatorType, IocEngine, MatchType},
    rules::{JockyRule, RuleCondition, RuleEngine, RuleSeverity},
};
use jocky_runtime_timeline::TimelineEvent;
use serde_json::json;

#[test]
fn test_normalized_entities_extraction() {
    let records = vec![
        json!({
            "source": "system",
            "hostname": "fin-srv-01",
            "os": "Linux 6.8",
            "arch": "x86_64"
        }),
        json!({
            "source": "process",
            "event_type": "process_observed",
            "pid": 1337,
            "ppid": 100,
            "name": "nc.exe",
            "command_line": "nc.exe -lvp 4444 -e cmd.exe",
            "executable": "/tmp/nc.exe",
            "user": "SYSTEM",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }),
        json!({
            "source": "network",
            "local_address": "192.168.1.50:4444",
            "remote_address": "10.0.0.99:51234",
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "pid": 1337,
            "process_name": "nc.exe"
        }),
        json!({
            "source": "filesystem",
            "path": "/tmp/nc.exe",
            "size": 59392,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }),
    ];

    let entities = NormalizedEntities::from_records(&records, "fin-srv-01");
    assert_eq!(entities.hosts.len(), 1);
    assert_eq!(entities.hosts[0].hostname, "fin-srv-01");
    assert_eq!(entities.processes.len(), 1);
    assert_eq!(entities.processes[0].name, "nc.exe");
    assert_eq!(entities.processes[0].pid, 1337);
    assert_eq!(entities.network_connections.len(), 1);
    assert_eq!(entities.network_connections[0].remote_port, 51234);
    assert_eq!(entities.files.len(), 1);
    assert_eq!(entities.files[0].path, "/tmp/nc.exe");
}

#[test]
fn test_ioc_matching_engine_all_operators() {
    let mut engine = IocEngine::new();

    // 1. Exact match on SHA256
    engine.add_indicator(Indicator::new(
        "ioc-sha-01",
        IndicatorType::Sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        MatchType::Exact,
        "critical",
    ));

    // 2. Contains match on process name
    engine.add_indicator(Indicator::new(
        "ioc-proc-01",
        IndicatorType::ProcessName,
        "nc",
        MatchType::Contains,
        "high",
    ));

    // 3. Prefix match on IP
    engine.add_indicator(Indicator::new(
        "ioc-ip-01",
        IndicatorType::Ip,
        "10.0.0.",
        MatchType::Prefix,
        "high",
    ));

    // 4. Regex match on executable path
    engine.add_indicator(Indicator::new(
        "ioc-path-01",
        IndicatorType::Path,
        r"^/tmp/.*\.exe$",
        MatchType::Regex,
        "critical",
    ));

    let records = vec![
        json!({
            "source": "process",
            "pid": 1337,
            "name": "nc.exe",
            "executable": "/tmp/nc.exe",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }),
        json!({
            "source": "network",
            "local_address": "192.168.1.50:4444",
            "remote_address": "10.0.0.99:51234",
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "pid": 1337
        }),
    ];

    let entities = NormalizedEntities::from_records(&records, "fin-srv-01");
    let matches = engine.scan_entities(&entities, "fin-srv-01");

    assert!(!matches.is_empty(), "Expected multiple IOC matches");
    let matched_ids: Vec<&str> = matches.iter().map(|m| m.indicator_id.as_str()).collect();
    assert!(
        matched_ids.contains(&"ioc-sha-01"),
        "SHA256 exact match failed"
    );
    assert!(
        matched_ids.contains(&"ioc-proc-01"),
        "Process contains match failed"
    );
    assert!(matched_ids.contains(&"ioc-ip-01"), "IP prefix match failed");
    assert!(
        matched_ids.contains(&"ioc-path-01"),
        "Path regex match failed"
    );
}

#[test]
fn test_jocky_native_rule_engine() {
    let mut engine = RuleEngine::new();

    // Custom behavioral rule with nested boolean logic
    engine.add_rule(
        JockyRule::new(
            "reverse_shell_netcat",
            "Netcat Reverse Shell Observed",
            "Process named nc or ncat spawned with -e argument indicative of reverse shell",
            RuleCondition::And(vec![
                RuleCondition::Or(vec![
                    RuleCondition::Contains {
                        field: "process.name".to_string(),
                        value: "nc".to_string(),
                    },
                    RuleCondition::Contains {
                        field: "process.name".to_string(),
                        value: "ncat".to_string(),
                    },
                ]),
                RuleCondition::Contains {
                    field: "process.command_line".to_string(),
                    value: "-e".to_string(),
                },
            ]),
            RuleSeverity::Critical,
        )
        .with_mitre("T1059")
        .with_recommendation("Terminate process tree and review network egress destinations."),
    );

    let records = vec![json!({
        "source": "process",
        "pid": 2048,
        "name": "nc.exe",
        "command_line": "nc.exe -lvp 4444 -e /bin/sh",
        "user": "root"
    })];

    let entities = NormalizedEntities::from_records(&records, "dmz-bastion");
    let findings = engine.evaluate_entities(&entities);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.rule_name, "reverse_shell_netcat");
    assert_eq!(finding.severity, RuleSeverity::Critical);
    assert_eq!(finding.mitre_attack_id.as_deref(), Some("T1059"));
    assert_eq!(finding.evidence_ref.as_deref(), Some("pid:2048"));
}

#[test]
fn test_rule_evaluation_on_timeline_events() {
    let engine = RuleEngine::new(); // Includes builtin rules

    let mut event = TimelineEvent::new(Utc::now(), "win-client-04", "process", "process_observed");
    event.process_name = Some("powershell.exe".to_string());
    event.process_id = Some(5012);
    event.evidence_ref = Some("pid:5012".to_string());

    // Matches the builtin rule recon_system_info_discovery when process.name is whoami
    let mut event_recon =
        TimelineEvent::new(Utc::now(), "win-client-04", "process", "process_observed");
    event_recon.process_name = Some("whoami".to_string());
    event_recon.process_id = Some(5013);
    event_recon.evidence_ref = Some("pid:5013".to_string());

    let findings = engine.evaluate_timeline(&[event, event_recon]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_name, "recon_system_info_discovery");
    assert_eq!(findings[0].mitre_attack_id.as_deref(), Some("T1082"));
}
