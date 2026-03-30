use soroban_sdk::{contract, contractimpl, Address, Env, Map, String, Symbol, Vec};

use crate::error::Error;
use crate::fraud_detection::{
    AnomalyPattern, AnomalyType, BehaviorProfile, ComparisonOp, FraudAlert, FraudRule,
    FraudStats, RiskFactor, RiskLevel, RiskScore, RuleCondition, RuleType, VelocityData,
    anomaly_type_to_u32, default_fraud_rules, requires_immediate_action, risk_level_threshold,
    score_to_risk_level, validate_risk_score,
};

/// Contract for fraud detection and risk scoring
/// Implements anomaly detection, behavioral analysis, and risk assessment
#[contract]
pub struct FraudDetectionContract;

#[contractimpl]
impl FraudDetectionContract {
    // ─── Constants ───────────────────────────────────────────────────────────
    
    const MAX_RULES: u32 = 100;
    const MAX_FACTORS: u32 = 10;
    const VELOCITY_WINDOW_SECS: u64 = 3600; // 1 hour
    const MAX_EVENTS_PER_WINDOW: u32 = 100;

    // ─── Rule Management ─────────────────────────────────────────────────────

    /// Add a new fraud detection rule
    pub fn add_fraud_rule(
        env: Env,
        caller: Address,
        rule: FraudRule,
    ) -> Result<(), Error> {
        caller.require_auth();

        // Check max rules limit
        let current_rules: Vec<FraudRule> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "FRAUD_RULES"))
            .unwrap_or_else(|| Vec::new(&env));

        if current_rules.len() >= Self::MAX_RULES {
            return Err(Error::InvalidInput);
        }

        // Validate rule
        if rule.name.len() < 1 {
            return Err(Error::InvalidInput);
        }

        // Store rule
        let mut rules = current_rules;
        rules.push_back(rule);

        env.storage().persistent().set(
            &Symbol::new(&env, "FRAUD_RULES"),
            &rules,
        );

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "fraud_rule_added"), caller),
            rules.len(),
        );

        Ok(())
    }

    /// Get all active fraud rules
    pub fn get_fraud_rules(env: Env) -> Vec<FraudRule> {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "FRAUD_RULES"))
            .unwrap_or_else(|| default_fraud_rules(&env))
    }

    /// Activate/deactivate a rule
    pub fn set_rule_status(
        env: Env,
        caller: Address,
        rule_id: Symbol,
        active: bool,
    ) -> Result<(), Error> {
        caller.require_auth();

        let rules: Vec<FraudRule> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "FRAUD_RULES"))
            .unwrap_or_else(|| Vec::new(&env));

        let mut found = false;
        let mut updated_rules = Vec::new(&env);

        for i in 0..rules.len() {
            let mut rule = rules.get_unchecked(i);
            if rule.rule_id == rule_id {
                rule.active = active;
                found = true;
            }
            updated_rules.push_back(rule);
        }

        if !found {
            return Err(Error::EventNotFound);
        }

        env.storage().persistent().set(
            &Symbol::new(&env, "FRAUD_RULES"),
            &updated_rules,
        );

        Ok(())
    }

    // ─── Risk Assessment ─────────────────────────────────────────────────────

    /// Calculate risk score for a product/actor
    pub fn assess_risk(
        env: Env,
        caller: Address,
        product_id: String,
        factors: Vec<RiskFactor>,
    ) -> Result<RiskScore, Error> {
        caller.require_auth();

        // Validate factor count
        if factors.len() > Self::MAX_FACTORS {
            return Err(Error::InvalidInput);
        }

        // Calculate weighted score
        let mut total_score: u32 = 0;
        let mut total_weight: u32 = 0;

        for i in 0..factors.len() {
            let factor = factors.get_unchecked(i);
            total_score += factor.weight * risk_level_threshold(&factor.severity) / 100;
            total_weight += factor.weight;
        }

        // Normalize score
        let final_score = if total_weight > 0 {
            total_score * 100 / total_weight
        } else {
            0
        };

        validate_risk_score(final_score)?;
        let level = score_to_risk_level(final_score)?;
        let level_value = level.clone() as u32;

        let score = RiskScore {
            level: level.clone(),
            score: final_score,
            factors,
            assessed_at: env.ledger().timestamp(),
            assessor: caller.clone(),
        };

        // Store risk score
        let scores_key = (Symbol::new(&env, "RISK_SCORES"), product_id.clone());
        let mut scores: Vec<RiskScore> = env
            .storage()
            .persistent()
            .get(&scores_key)
            .unwrap_or_else(|| Vec::new(&env));
        scores.push_back(score.clone());
        env.storage().persistent().set(&scores_key, &scores);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "risk_assessed"), product_id, caller),
            (final_score, level_value),
        );

        Ok(score)
    }

    /// Get risk history for a product
    pub fn get_risk_history(env: Env, product_id: String) -> Vec<RiskScore> {
        let scores_key = (Symbol::new(&env, "RISK_SCORES"), product_id);
        env.storage()
            .persistent()
            .get(&scores_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ─── Anomaly Detection ─────────────────────────────────────────────────────

    /// Report an anomaly pattern
    pub fn report_anomaly(
        env: Env,
        caller: Address,
        pattern: AnomalyPattern,
    ) -> Result<u64, Error> {
        caller.require_auth();

        // Get next anomaly ID
        let anomaly_id = env
            .storage()
            .persistent()
            .get::<_, u64>(&Symbol::new(&env, "ANOMALY_SEQ"))
            .unwrap_or(0)
            + 1;

        // Check if immediate action required
        let immediate_action = requires_immediate_action(&pattern.pattern_type);

        // Store anomaly
        env.storage().persistent().set(
            &(Symbol::new(&env, "ANOMALY"), anomaly_id),
            &pattern,
        );

        // Update sequence
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "ANOMALY_SEQ"), &anomaly_id);

        // Create alert for high/critical anomalies
        if pattern.severity == RiskLevel::High || pattern.severity == RiskLevel::Critical {
            let alert = FraudAlert {
                alert_id: anomaly_id,
                product_id: pattern.product_id.clone(),
                alert_type: pattern.pattern_type.clone(),
                risk_level: pattern.severity.clone(),
                message: String::from_str(&env, "Anomaly detected - review required"),
                triggered_rules: Vec::new(&env),
                timestamp: env.ledger().timestamp(),
                acknowledged: false,
                acknowledged_by: None,
            };

            env.storage().persistent().set(
                &(Symbol::new(&env, "FRAUD_ALERT"), anomaly_id),
                &alert,
            );

            // Emit alert event
            let severity_value = pattern.severity.clone() as u32;
            env.events().publish(
                (
                    Symbol::new(&env, "fraud_alert"),
                    pattern.product_id.clone(),
                    severity_value,
                ),
                anomaly_id,
            );
        }

        // Emit anomaly event
        let pattern_type_value = anomaly_type_to_u32(&pattern.pattern_type);
        env.events().publish(
            (
                Symbol::new(&env, "anomaly_detected"),
                pattern.product_id,
                pattern_type_value,
            ),
            (anomaly_id, immediate_action),
        );

        Ok(anomaly_id)
    }

    /// Get anomaly by ID
    pub fn get_anomaly(env: Env, anomaly_id: u64) -> Result<AnomalyPattern, Error> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "ANOMALY"), anomaly_id))
            .ok_or(Error::EventNotFound)
    }

    // ─── Velocity Tracking ───────────────────────────────────────────────────

    /// Record event velocity for an actor
    pub fn record_velocity(
        env: Env,
        caller: Address,
        actor: Address,
    ) -> Result<VelocityData, Error> {
        caller.require_auth();

        let velocity_key = (Symbol::new(&env, "VELOCITY"), actor.clone());
        let now = env.ledger().timestamp();

        let mut velocity: VelocityData = env
            .storage()
            .temporary()
            .get(&velocity_key)
            .unwrap_or(VelocityData {
                actor: actor.clone(),
                event_count: 0,
                window_start: now,
                window_duration: Self::VELOCITY_WINDOW_SECS,
                last_event_at: 0,
            });

        // Check if window has expired
        if now - velocity.window_start > Self::VELOCITY_WINDOW_SECS {
            // Reset window
            velocity.window_start = now;
            velocity.event_count = 0;
        }

        // Increment count
        velocity.event_count += 1;
        velocity.last_event_at = now;

        // Store updated velocity
        env.storage().temporary().set(&velocity_key, &velocity);

        // Check threshold
        if velocity.event_count > Self::MAX_EVENTS_PER_WINDOW {
            // Emit threshold exceeded event
            env.events().publish(
                (Symbol::new(&env, "velocity_threshold_exceeded"), actor),
                velocity.event_count,
            );
        }

        Ok(velocity)
    }

    /// Get velocity data for an actor
    pub fn get_velocity(env: Env, actor: Address) -> VelocityData {
        let velocity_key = (Symbol::new(&env, "VELOCITY"), actor.clone());
        env.storage()
            .temporary()
            .get(&velocity_key)
            .unwrap_or(VelocityData {
                actor,
                event_count: 0,
                window_start: 0,
                window_duration: Self::VELOCITY_WINDOW_SECS,
                last_event_at: 0,
            })
    }

    // ─── Fraud Alerts ─────────────────────────────────────────────────────────

    /// Acknowledge a fraud alert
    pub fn acknowledge_alert(
        env: Env,
        caller: Address,
        alert_id: u64,
    ) -> Result<(), Error> {
        caller.require_auth();

        let alert_key = (Symbol::new(&env, "FRAUD_ALERT"), alert_id);
        let mut alert: FraudAlert = env
            .storage()
            .persistent()
            .get(&alert_key)
            .ok_or(Error::EventNotFound)?;

        alert.acknowledged = true;
        alert.acknowledged_by = Some(caller.clone());

        env.storage().persistent().set(&alert_key, &alert);

        env.events().publish(
            (Symbol::new(&env, "alert_acknowledged"), alert_id),
            caller,
        );

        Ok(())
    }

    /// Get fraud alert by ID
    pub fn get_fraud_alert(env: Env, alert_id: u64) -> Result<FraudAlert, Error> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "FRAUD_ALERT"), alert_id))
            .ok_or(Error::EventNotFound)
    }

    // ─── Statistics ─────────────────────────────────────────────────────────

    /// Get fraud detection statistics
    pub fn get_fraud_stats(env: Env) -> FraudStats {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "FRAUD_STATS"))
            .unwrap_or(FraudStats {
                total_events_analyzed: 0,
                anomalies_detected: 0,
                alerts_generated: 0,
                high_risk_count: 0,
                critical_risk_count: 0,
                false_positives: 0,
                last_analysis_at: 0,
            })
    }

    /// Update fraud statistics
    pub fn update_fraud_stats(
        env: Env,
        caller: Address,
        stats: FraudStats,
    ) -> Result<(), Error> {
        caller.require_auth();

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "FRAUD_STATS"), &stats);

        Ok(())
    }

    // ─── Helper Functions ────────────────────────────────────────────────────

    /// Check if a condition is met (simplified evaluation)
    pub fn evaluate_condition(
        _env: Env,
        condition: &RuleCondition,
        value: u64,
    ) -> bool {
        match condition.operator {
            ComparisonOp::Equal => value == condition.value,
            ComparisonOp::NotEqual => value != condition.value,
            ComparisonOp::GreaterThan => value > condition.value,
            ComparisonOp::LessThan => value < condition.value,
            ComparisonOp::GreaterThanOrEqual => value >= condition.value,
            ComparisonOp::LessThanOrEqual => value <= condition.value,
            ComparisonOp::InRange => {
                // Simplified range check - actual implementation would parse context
                value >= condition.value && value <= condition.value + 100
            }
            ComparisonOp::NotInRange => {
                value < condition.value || value > condition.value + 100
            }
        }
    }
}
