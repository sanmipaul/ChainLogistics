use soroban_sdk::{contracttype, Address, BytesN, Env, Map, String, Symbol, Vec};

use crate::error::Error;

/// Quality status for a product
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualityStatus {
    /// Not yet inspected
    Pending = 0,
    /// Passed quality inspection
    Passed = 1,
    /// Failed quality inspection
    Failed = 2,
    /// Conditionally passed with minor issues
    Conditional = 3,
    /// Requires re-inspection
    ReinspectRequired = 4,
    /// Quarantined pending investigation
    Quarantined = 5,
}

/// Quality inspection event
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityEvent {
    /// Event ID
    pub event_id: u64,
    /// Product ID inspected
    pub product_id: String,
    /// Inspector address
    pub inspector: Address,
    /// Inspection timestamp
    pub inspected_at: u64,
    /// Quality status result
    pub status: QualityStatus,
    /// Inspection type
    pub inspection_type: InspectionType,
    /// Quality score (0-100)
    pub quality_score: u32,
    /// Measured parameters
    pub measurements: Map<Symbol, u64>,
    /// Notes/comments
    pub notes: String,
    /// Certification ID reference (empty if none)
    pub certification_id: String,
    /// Has certification attached
    pub has_certification: bool,
}

/// Type of quality inspection
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectionType {
    /// Visual inspection
    Visual,
    /// Physical measurement
    Physical,
    /// Chemical analysis
    Chemical,
    /// Microbiological testing
    Microbiological,
    /// Sensor/IoT automated check
    Automated,
    /// Third-party verification
    ThirdParty,
    /// Regulatory compliance check
    Regulatory,
    /// Custom inspection type
    Custom(Symbol),
}

/// Quality standard/specification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityStandard {
    /// Standard ID
    pub standard_id: Symbol,
    /// Standard name
    pub name: String,
    /// Standard description
    pub description: String,
    /// Category (e.g., "organic", "fair_trade", "ISO9001")
    pub category: String,
    /// Required parameters and their acceptable ranges
    pub parameters: Map<Symbol, ParameterSpec>,
    /// Minimum quality score required
    pub min_quality_score: u32,
    /// Is this standard active
    pub active: bool,
    /// Created at
    pub created_at: u64,
}

/// Parameter specification for quality standards
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterSpec {
    /// Parameter name
    pub name: Symbol,
    /// Unit of measurement
    pub unit: String,
    /// Minimum acceptable value
    pub min_value: u64,
    /// Maximum acceptable value
    pub max_value: u64,
    /// Target/optimal value
    pub target_value: u64,
    /// Is this parameter required
    pub required: bool,
}

/// Certification reference
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationRef {
    /// Certification ID
    pub cert_id: String,
    /// Issuing authority
    pub issuer: String,
    /// Certification type
    pub cert_type: String,
    /// Issue date
    pub issued_at: u64,
    /// Expiration date (0 = no expiration)
    pub expires_at: u64,
    /// Certificate hash/document reference
    pub document_hash: BytesN<32>,
}

/// IoT device registration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoTDevice {
    /// Device ID
    pub device_id: String,
    /// Device type (sensor type)
    pub device_type: Symbol,
    /// Device name/description
    pub name: String,
    /// Owner/operator address
    pub owner: Address,
    /// Associated product ID
    pub product_id: String,
    /// Device status
    pub status: DeviceStatus,
    /// Calibration timestamp
    pub last_calibrated_at: u64,
    /// Data collection frequency (seconds)
    pub sampling_interval: u64,
    /// Registered at
    pub registered_at: u64,
}

/// IoT device status
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceStatus {
    /// Active and collecting data
    Active = 0,
    /// Inactive/offline
    Inactive = 1,
    /// Needs calibration
    NeedsCalibration = 2,
    /// Maintenance required
    MaintenanceRequired = 3,
    /// Decommissioned
    Decommissioned = 4,
}

/// IoT sensor reading
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorReading {
    /// Reading ID
    pub reading_id: u64,
    /// Device that took the reading
    pub device_id: String,
    /// Product being monitored
    pub product_id: String,
    /// Timestamp of reading
    pub timestamp: u64,
    /// Sensor type
    pub sensor_type: Symbol,
    /// Reading value
    pub value: u64,
    /// Unit of measurement
    pub unit: String,
    /// Quality flag (is reading valid)
    pub is_valid: bool,
}

/// Quality metrics summary for a product
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityMetrics {
    /// Product ID
    pub product_id: String,
    /// Current quality status
    pub current_status: QualityStatus,
    /// Overall quality score (0-100)
    pub overall_score: u32,
    /// Number of inspections completed
    pub inspection_count: u32,
    /// Number of passed inspections
    pub passed_count: u32,
    /// Number of failed inspections
    pub failed_count: u32,
    /// Last inspection timestamp
    pub last_inspection_at: u64,
    /// Certifications held
    pub certifications: Vec<CertificationRef>,
    /// Compliance with standards
    pub standard_compliance: Map<Symbol, bool>,
}

/// Quality control configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityConfig {
    /// Configuration ID
    pub config_id: Symbol,
    /// Product category this applies to
    pub category: String,
    /// Required inspection types
    pub required_inspections: Vec<InspectionType>,
    /// Applicable quality standards
    pub standards: Vec<Symbol>,
    /// Minimum inspections required
    pub min_inspections: u32,
    /// IoT monitoring enabled
    pub iot_enabled: bool,
    /// Auto-approve if IoT readings pass
    pub auto_approve_iot: bool,
    /// Requires human verification
    pub requires_human_verification: bool,
}

/// Convert quality status to string representation
pub fn quality_status_to_u32(status: &QualityStatus) -> u32 {
    match status {
        QualityStatus::Pending => 0,
        QualityStatus::Passed => 1,
        QualityStatus::Failed => 2,
        QualityStatus::Conditional => 3,
        QualityStatus::ReinspectRequired => 4,
        QualityStatus::Quarantined => 5,
    }
}

/// Convert inspection type to numeric value
pub fn inspection_type_to_u32(inspection: &InspectionType) -> u32 {
    match inspection {
        InspectionType::Visual => 0,
        InspectionType::Physical => 1,
        InspectionType::Chemical => 2,
        InspectionType::Microbiological => 3,
        InspectionType::Automated => 4,
        InspectionType::ThirdParty => 5,
        InspectionType::Regulatory => 6,
        InspectionType::Custom(_) => 7,
    }
}

/// Convert device status to numeric value
pub fn device_status_to_u32(status: &DeviceStatus) -> u32 {
    match status {
        DeviceStatus::Active => 0,
        DeviceStatus::Inactive => 1,
        DeviceStatus::NeedsCalibration => 2,
        DeviceStatus::MaintenanceRequired => 3,
        DeviceStatus::Decommissioned => 4,
    }
}

/// Check if a quality score meets the standard
pub fn meets_quality_standard(score: u32, required: u32) -> bool {
    score >= required
}

/// Validate quality score is within bounds
pub fn validate_quality_score(score: u32) -> Result<(), Error> {
    if score > 100 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Check if measurement is within specification
pub fn measurement_in_spec(value: u64, spec: &ParameterSpec) -> bool {
    value >= spec.min_value && value <= spec.max_value
}

/// Calculate quality score based on measurements vs specs
pub fn calculate_quality_score(
    measurements: &Map<Symbol, u64>,
    specs: &Map<Symbol, ParameterSpec>,
) -> u32 {
    if specs.len() == 0 {
        return 100; // Perfect score if no specs
    }

    let mut total_score: u32 = 0;
    let spec_keys = specs.keys();

    for i in 0..spec_keys.len() {
        let key = spec_keys.get_unchecked(i);
        if let Some(spec) = specs.get(key.clone()) {
            if let Some(value) = measurements.get(key) {
                if measurement_in_spec(value, &spec) {
                    total_score += 100 / spec_keys.len();
                }
            } else if spec.required {
                // Required parameter missing - significant penalty
                // Score stays lower
            }
        }
    }

    total_score.min(100)
}

/// Default quality standards
pub fn default_quality_standards(env: &Env) -> Vec<QualityStandard> {
    let mut standards = Vec::new(env);

    // Organic certification standard
    let mut organic_params = Map::new(env);
    organic_params.set(
        Symbol::new(env, "pesticide_residue"),
        ParameterSpec {
            name: Symbol::new(env, "pesticide_residue"),
            unit: String::from_str(env, "ppm"),
            min_value: 0,
            max_value: 10,
            target_value: 0,
            required: true,
        },
    );

    standards.push_back(QualityStandard {
        standard_id: Symbol::new(env, "ORGANIC"),
        name: String::from_str(env, "Organic Certification"),
        description: String::from_str(env, "Certified organic production standard"),
        category: String::from_str(env, "organic"),
        parameters: organic_params,
        min_quality_score: 95,
        active: true,
        created_at: env.ledger().timestamp(),
    });

    // Fair trade standard
    let mut fairtrade_params = Map::new(env);
    fairtrade_params.set(
        Symbol::new(env, "worker_wages"),
        ParameterSpec {
            name: Symbol::new(env, "worker_wages"),
            unit: String::from_str(env, "local_currency"),
            min_value: 100,
            max_value: 10000,
            target_value: 200,
            required: true,
        },
    );

    standards.push_back(QualityStandard {
        standard_id: Symbol::new(env, "FAIR_TRADE"),
        name: String::from_str(env, "Fair Trade Certification"),
        description: String::from_str(env, "Fair trade labor and pricing standards"),
        category: String::from_str(env, "fair_trade"),
        parameters: fairtrade_params,
        min_quality_score: 90,
        active: true,
        created_at: env.ledger().timestamp(),
    });

    standards
}
