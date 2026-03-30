use soroban_sdk::{contracttype, Address, BytesN, Env, Map, String, Symbol, Vec};

use crate::error::Error;

/// Risk score categories for fraud assessment
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    /// No risk detected - normal operation
    None = 0,
    /// Low risk - minor anomalies, monitor
    Low = 1,
    /// Medium risk - suspicious patterns, review recommended
    Medium = 2,
    /// High risk - likely fraud, immediate attention required
    High = 3,
    /// Critical risk - confirmed fraud, block transactions
    Critical = 4,
}

/// Risk score with detailed breakdown
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskScore {
    /// Overall risk level
    pub level: RiskLevel,
    /// Numeric score (0-100, higher = more risky)
    pub score: u32,
    /// Contributing risk factors
    pub factors: Vec<RiskFactor>,
    /// Timestamp of assessment
    pub assessed_at: u64,
    /// Assessor address
    pub assessor: Address,
}

/// Individual risk factor contributing to overall score
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFactor {
    /// Factor type identifier
    pub factor_type: Symbol,
    /// Human-readable description
    pub description: String,
    /// Weight of this factor (0-100)
    pub weight: u32,
    /// Severity of this specific factor
    pub severity: RiskLevel,
}

/// Anomaly pattern detected in supply chain data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnomalyPattern {
    /// Pattern identifier
    pub pattern_id: Symbol,
    /// Pattern type/category
    pub pattern_type: AnomalyType,
    /// Product ID affected
    pub product_id: String,
    /// Actor address involved (if applicable)
    pub actor: Address,
    /// Detection timestamp
    pub detected_at: u64,
    /// Severity of the anomaly
    pub severity: RiskLevel,
    /// Pattern confidence (0-100)
    pub confidence: u32,
    /// Related event IDs
    pub related_events: Vec<u64>,
    /// Additional context data
    pub context: Map<Symbol, String>,
}

/// Types of anomalies that can be detected
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnomalyType {
    /// Unusual frequency of events
    FrequencyAnomaly,
    /// Impossible location jumps (teleportation)
    LocationJump,
    /// Event sequence violations
    SequenceViolation,
    /// Unauthorized actor attempting actions
    UnauthorizedActor,
    /// Duplicate event submissions
    DuplicateEvent,
    /// Tampered timestamp (future or past dates)
    TimestampTampering,
    /// Unusual ownership transfer patterns
    SuspiciousTransfer,
    /// Batch operation anomalies
    BatchAnomaly,
    /// Quality metric outliers
    QualityOutlier,
    /// Custom anomaly type
    Custom(Symbol),
}

/// Fraud detection rule
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FraudRule {
    /// Rule identifier
    pub rule_id: Symbol,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Rule type
    pub rule_type: RuleType,
    /// Trigger conditions
    pub conditions: Vec<RuleCondition>,
    /// Risk level if triggered
    pub risk_level: RiskLevel,
    /// Is rule active
    pub active: bool,
    /// Created at timestamp
    pub created_at: u64,
}

/// Type of fraud detection rule
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleType {
    /// Threshold-based rule
    Threshold,
    /// Pattern matching rule
    Pattern,
    /// Statistical outlier rule
    Statistical,
    /// Velocity check rule
    Velocity,
    /// Geographical rule
    Geographical,
    /// Temporal rule
    Temporal,
}

/// Condition for triggering a fraud rule
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleCondition {
    /// Field to check
    pub field: Symbol,
    /// Comparison operator
    pub operator: ComparisonOp,
    /// Threshold value
    pub value: u64,
    /// Additional context
    pub context: String,
}

/// Comparison operators for rules
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    InRange,
    NotInRange,
}

/// Fraud alert issued by the system
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FraudAlert {
    /// Alert identifier
    pub alert_id: u64,
    /// Product ID involved
    pub product_id: String,
    /// Alert type
    pub alert_type: AnomalyType,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Alert message
    pub message: String,
    /// Triggered rule IDs
    pub triggered_rules: Vec<Symbol>,
    /// Timestamp
    pub timestamp: u64,
    /// Is alert acknowledged
    pub acknowledged: bool,
    /// Acknowledged by (if applicable)
    pub acknowledged_by: Option<Address>,
}

/// Fraud detection statistics
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FraudStats {
    /// Total events analyzed
    pub total_events_analyzed: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Alerts generated
    pub alerts_generated: u64,
    /// High risk events
    pub high_risk_count: u64,
    /// Critical risk events
    pub critical_risk_count: u64,
    /// False positives (reported)
    pub false_positives: u64,
    /// Last analysis timestamp
    pub last_analysis_at: u64,
}

/// Velocity check data for rate limiting analysis
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VelocityData {
    /// Actor address
    pub actor: Address,
    /// Event count in window
    pub event_count: u32,
    /// Window start timestamp
    pub window_start: u64,
    /// Window duration in seconds
    pub window_duration: u64,
    /// Last event timestamp
    pub last_event_at: u64,
}

/// Behavior profile for an actor
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehaviorProfile {
    /// Actor address
    pub actor: Address,
    /// Normal operation patterns
    pub normal_patterns: Vec<Symbol>,
    /// Typical event frequency (events per hour)
    pub typical_frequency: u32,
    /// Usual geographic regions
    pub usual_regions: Vec<String>,
    /// Established timestamp
    pub established_at: u64,
    /// Last updated
    pub last_updated: u64,
    /// Risk history
    pub risk_history: Vec<RiskScore>,
}

/// Convert risk level to numeric score threshold
pub fn risk_level_threshold(level: &RiskLevel) -> u32 {
    match level {
        RiskLevel::None => 0,
        RiskLevel::Low => 25,
        RiskLevel::Medium => 50,
        RiskLevel::High => 75,
        RiskLevel::Critical => 90,
    }
}

/// Validate a risk score is within bounds
pub fn validate_risk_score(score: u32) -> Result<(), Error> {
    if score > 100 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Determine risk level from numeric score
pub fn score_to_risk_level(score: u32) -> Result<RiskLevel, Error> {
    validate_risk_score(score)?;
    
    let level = if score >= 90 {
        RiskLevel::Critical
    } else if score >= 75 {
        RiskLevel::High
    } else if score >= 50 {
        RiskLevel::Medium
    } else if score >= 25 {
        RiskLevel::Low
    } else {
        RiskLevel::None
    };
    
    Ok(level)
}

/// Check if an anomaly type requires immediate action
pub fn requires_immediate_action(anomaly_type: &AnomalyType) -> bool {
    matches!(
        anomaly_type,
        AnomalyType::UnauthorizedActor
            | AnomalyType::TimestampTampering
            | AnomalyType::SuspiciousTransfer
    )
}

/// Convert AnomalyType to u32 for event emission
pub fn anomaly_type_to_u32(anomaly_type: &AnomalyType) -> u32 {
    match anomaly_type {
        AnomalyType::FrequencyAnomaly => 0,
        AnomalyType::LocationJump => 1,
        AnomalyType::SequenceViolation => 2,
        AnomalyType::UnauthorizedActor => 3,
        AnomalyType::DuplicateEvent => 4,
        AnomalyType::TimestampTampering => 5,
        AnomalyType::SuspiciousTransfer => 6,
        AnomalyType::BatchAnomaly => 7,
        AnomalyType::QualityOutlier => 8,
        AnomalyType::Custom(_) => 9,
    }
}

/// Default fraud detection rules
pub fn default_fraud_rules(env: &Env) -> Vec<FraudRule> {
    let mut rules = Vec::new(env);
    
    // Rule 1: High frequency events
    rules.push_back(FraudRule {
        rule_id: Symbol::new(env, "FREQ_THRESHOLD"),
        name: String::from_str(env, "High Frequency Events"),
        description: String::from_str(env, "Detects unusually high event submission rates"),
        rule_type: RuleType::Velocity,
        conditions: Vec::from_array(
            env,
            [RuleCondition {
                field: Symbol::new(env, "events_per_hour"),
                operator: ComparisonOp::GreaterThan,
                value: 100,
                context: String::from_str(env, "More than 100 events per hour"),
            }],
        ),
        risk_level: RiskLevel::Medium,
        active: true,
        created_at: env.ledger().timestamp(),
    });
    
    // Rule 2: Location jump anomaly
    rules.push_back(FraudRule {
        rule_id: Symbol::new(env, "LOC_JUMP"),
        name: String::from_str(env, "Impossible Location Jump"),
        description: String::from_str(env, "Detects location changes faster than physically possible"),
        rule_type: RuleType::Geographical,
        conditions: Vec::new(env),
        risk_level: RiskLevel::High,
        active: true,
        created_at: env.ledger().timestamp(),
    });
    
    // Rule 3: Duplicate events
    rules.push_back(FraudRule {
        rule_id: Symbol::new(env, "DUP_EVENT"),
        name: String::from_str(env, "Duplicate Event"),
        description: String::from_str(env, "Detects identical events submitted multiple times"),
        rule_type: RuleType::Pattern,
        conditions: Vec::new(env),
        risk_level: RiskLevel::Low,
        active: true,
        created_at: env.ledger().timestamp(),
    });
    
    rules
}
