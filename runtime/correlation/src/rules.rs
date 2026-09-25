//! JOCKEY-Native Rule Engine (Section 14)
//!
//! Evaluates declarative behavioral rules against forensic artifacts and timeline events.
//! Supports operators: ==, !=, contains, starts_with, ends_with, regex, >, <, exists, and, or, not.
//! Generates evidence-backed security findings with MITRE ATT&CK taxonomy mappings.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::entities::NormalizedEntities;
use jockey_runtime_timeline::TimelineEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RuleSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RuleCondition {
    Equals { field: String, value: String },
    NotEquals { field: String, value: String },
    Contains { field: String, value: String },
    StartsWith { field: String, value: String },
    EndsWith { field: String, value: String },
    RegexMatch { field: String, pattern: String },
    GreaterThan { field: String, value: f64 },
    LessThan { field: String, value: f64 },
    Exists { field: String },
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
}

impl RuleCondition {
    /// Evaluate condition against a property resolver function
    pub fn evaluate<'a, F>(&self, resolver: &F) -> bool
    where
        F: Fn(&str) -> Option<&'a str>,
    {
        match self {
            RuleCondition::Equals { field, value } => {
                resolver(field).map_or(false, |v| v.eq_ignore_ascii_case(value))
            }
            RuleCondition::NotEquals { field, value } => {
                resolver(field).map_or(true, |v| !v.eq_ignore_ascii_case(value))
            }
            RuleCondition::Contains { field, value } => {
                resolver(field).map_or(false, |v| v.to_ascii_lowercase().contains(&value.to_ascii_lowercase()))
            }
            RuleCondition::StartsWith { field, value } => {
                resolver(field).map_or(false, |v| v.to_ascii_lowercase().starts_with(&value.to_ascii_lowercase()))
            }
            RuleCondition::EndsWith { field, value } => {
                resolver(field).map_or(false, |v| v.to_ascii_lowercase().ends_with(&value.to_ascii_lowercase()))
            }
            RuleCondition::RegexMatch { field, pattern } => {
                if let (Some(val), Ok(re)) = (resolver(field), Regex::new(pattern)) {
                    re.is_match(val)
                } else {
                    false
                }
            }
            RuleCondition::GreaterThan { field, value } => {
                resolver(field).and_then(|v| v.parse::<f64>().ok()).map_or(false, |n| n > *value)
            }
            RuleCondition::LessThan { field, value } => {
                resolver(field).and_then(|v| v.parse::<f64>().ok()).map_or(false, |n| n < *value)
            }
            RuleCondition::Exists { field } => resolver(field).is_some(),
            RuleCondition::And(conditions) => conditions.iter().all(|c| c.evaluate(resolver)),
            RuleCondition::Or(conditions) => conditions.iter().any(|c| c.evaluate(resolver)),
            RuleCondition::Not(condition) => !condition.evaluate(resolver),
        }
    }
}

/// Strongly-typed JOCKEY Forensic Rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JockeyRule {
    pub name: String,
    pub title: String,
    pub description: String,
    pub condition: RuleCondition,
    pub severity: RuleSeverity,
    pub mitre_attack_id: Option<String>,
    pub recommendation: Option<String>,
}

impl JockeyRule {
    pub fn new(
        name: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        condition: RuleCondition,
        severity: RuleSeverity,
    ) -> Self {
        Self {
            name: name.into(),
            title: title.into(),
            description: description.into(),
            condition,
            severity,
            mitre_attack_id: None,
            recommendation: None,
        }
    }

    pub fn with_mitre(mut self, attack_id: impl Into<String>) -> Self {
        self.mitre_attack_id = Some(attack_id.into());
        self
    }

    pub fn with_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = Some(rec.into());
        self
    }
}

/// An actionable finding triggered by a rule evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleFinding {
    pub id: String,
    pub rule_name: String,
    pub title: String,
    pub description: String,
    pub severity: RuleSeverity,
    pub mitre_attack_id: Option<String>,
    pub evidence_ref: Option<String>,
    pub matched_entity: String,
    pub timestamp: DateTime<Utc>,
    pub recommendation: Option<String>,
}

/// Rule Evaluation Engine
#[derive(Debug, Default, Clone)]
pub struct RuleEngine {
    pub rules: Vec<JockeyRule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut engine = Self::default();
        engine.load_builtin_rules();
        engine
    }

    pub fn add_rule(&mut self, rule: JockeyRule) {
        self.rules.push(rule);
    }

    /// Load standard forensic detection rules
    pub fn load_builtin_rules(&mut self) {
        // Suspicious encoded powershell
        self.add_rule(
            JockeyRule::new(
                "suspicious_powershell_enc",
                "Encoded PowerShell Execution",
                "Detected powershell execution containing base64 encoded command arguments (-enc / -encodedcommand)",
                RuleCondition::And(vec![
                    RuleCondition::Contains { field: "process.name".to_string(), value: "powershell".to_string() },
                    RuleCondition::Or(vec![
                        RuleCondition::Contains { field: "process.command_line".to_string(), value: "-enc".to_string() },
                        RuleCondition::Contains { field: "process.command_line".to_string(), value: "-encodedcommand".to_string() },
                    ]),
                ]),
                RuleSeverity::High,
            )
            .with_mitre("T1059.001")
            .with_recommendation("Decode the base64 command line payload to identify script execution intent."),
        );

        // Discovery commands
        self.add_rule(
            JockeyRule::new(
                "recon_system_info_discovery",
                "System Reconnaissance / Host Discovery",
                "Execution of system discovery utilities (whoami, hostname, systeminfo, ifconfig, ip a)",
                RuleCondition::Or(vec![
                    RuleCondition::Equals { field: "process.name".to_string(), value: "whoami".to_string() },
                    RuleCondition::Equals { field: "process.name".to_string(), value: "ipconfig".to_string() },
                    RuleCondition::Equals { field: "process.name".to_string(), value: "systeminfo".to_string() },
                ]),
                RuleSeverity::Low,
            )
            .with_mitre("T1082")
            .with_recommendation("Verify if the discovery commands correlate with administrative or legitimate automation."),
        );

        // Word / Office spawning command shells
        self.add_rule(
            JockeyRule::new(
                "office_spawning_cmd",
                "Office Application Spawning Command Interpreter",
                "Microsoft Office or document viewer spawned a command shell or scripting interpreter",
                RuleCondition::And(vec![
                    RuleCondition::Or(vec![
                        RuleCondition::Equals { field: "process.name".to_string(), value: "cmd.exe".to_string() },
                        RuleCondition::Equals { field: "process.name".to_string(), value: "powershell.exe".to_string() },
                        RuleCondition::Equals { field: "process.name".to_string(), value: "sh".to_string() },
                        RuleCondition::Equals { field: "process.name".to_string(), value: "bash".to_string() },
                    ]),
                    RuleCondition::Or(vec![
                        RuleCondition::Contains { field: "process.parent".to_string(), value: "winword.exe".to_string() },
                        RuleCondition::Contains { field: "process.parent".to_string(), value: "excel.exe".to_string() },
                    ]),
                ]),
                RuleSeverity::Critical,
            )
            .with_mitre("T1204.002")
            .with_recommendation("Isolate host immediately and perform memory analysis to extract malicious macro artifacts."),
        );
    }

    /// Evaluate rules against normalized forensic entities
    pub fn evaluate_entities(&self, entities: &NormalizedEntities) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        let now = Utc::now();

        for proc in &entities.processes {
            let pid_str = proc.pid.to_string();
            let ppid_str = proc.ppid.map(|p| p.to_string()).unwrap_or_default();
            let cmdline = proc.command_line.as_deref().unwrap_or("");
            let exe = proc.executable.as_deref().unwrap_or("");
            let user = proc.user.as_deref().unwrap_or("");

            let resolver = |field: &str| -> Option<&str> {
                match field {
                    "process.name" => Some(&proc.name),
                    "process.pid" => Some(&pid_str),
                    "process.ppid" => Some(&ppid_str),
                    "process.command_line" => Some(cmdline),
                    "process.executable" => Some(exe),
                    "process.user" => Some(user),
                    _ => None,
                }
            };

            for rule in &self.rules {
                if rule.condition.evaluate(&resolver) {
                    findings.push(RuleFinding {
                        id: format!("find-{}-{}", rule.name, proc.pid),
                        rule_name: rule.name.clone(),
                        title: rule.title.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity,
                        mitre_attack_id: rule.mitre_attack_id.clone(),
                        evidence_ref: Some(format!("pid:{}", proc.pid)),
                        matched_entity: format!("process:{}({})", proc.name, proc.pid),
                        timestamp: proc.start_time.unwrap_or(now),
                        recommendation: rule.recommendation.clone(),
                    });
                }
            }
        }

        findings
    }

    /// Evaluate rules against timeline events
    pub fn evaluate_timeline(&self, events: &[TimelineEvent]) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for event in events {
            let pid_str = event.process_id.map(|p| p.to_string()).unwrap_or_default();
            let proc_name = event.process_name.as_deref().unwrap_or("");
            let path = event.path.as_deref().unwrap_or("");
            let endpoint = event.network_endpoint.as_deref().unwrap_or("");
            let actor = event.actor.as_deref().unwrap_or("");

            let resolver = |field: &str| -> Option<&str> {
                match field {
                    "process.name" => Some(proc_name),
                    "process.pid" => Some(&pid_str),
                    "file.path" | "path" => Some(path),
                    "network.endpoint" => Some(endpoint),
                    "actor" => Some(actor),
                    "event_type" => Some(&event.event_type),
                    "source" => Some(&event.source),
                    _ => None,
                }
            };

            for rule in &self.rules {
                if rule.condition.evaluate(&resolver) {
                    findings.push(RuleFinding {
                        id: format!("find-{}-{}", rule.name, event.timestamp.timestamp_millis()),
                        rule_name: rule.name.clone(),
                        title: rule.title.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity,
                        mitre_attack_id: rule.mitre_attack_id.clone(),
                        evidence_ref: event.evidence_ref.clone(),
                        matched_entity: format!("{}:{}", event.source, event.event_type),
                        timestamp: event.timestamp,
                        recommendation: rule.recommendation.clone(),
                    });
                }
            }
        }

        findings
    }
}
