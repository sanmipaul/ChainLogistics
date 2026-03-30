use soroban_sdk::{contract, contractimpl, Address, Env, Map, String, Symbol, Vec};

use crate::error::Error;
use crate::quality_control::{
    calculate_quality_score, CertificationRef, DeviceStatus, InspectionType, IoTDevice,
    ParameterSpec, QualityConfig, QualityEvent, QualityMetrics, QualityStandard,
    QualityStatus, SensorReading, default_quality_standards, inspection_type_to_u32,
    quality_status_to_u32, validate_quality_score,
};

/// Contract for quality control management
/// Handles quality inspections, IoT integrations, and certifications
#[contract]
pub struct QualityControlContract;

#[contractimpl]
impl QualityControlContract {
    // ─── Constants ───────────────────────────────────────────────────────────
    
    const MAX_STANDARDS: u32 = 50;
    const MAX_CERTIFICATIONS: u32 = 20;
    const MAX_DEVICES_PER_PRODUCT: u32 = 10;

    // ─── Quality Standards Management ─────────────────────────────────────────

    /// Add a new quality standard
    pub fn add_quality_standard(
        env: Env,
        caller: Address,
        standard: QualityStandard,
    ) -> Result<(), Error> {
        caller.require_auth();

        // Check max standards
        let standards: Vec<QualityStandard> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "QUALITY_STANDARDS"))
            .unwrap_or_else(|| Vec::new(&env));

        if standards.len() >= Self::MAX_STANDARDS {
            return Err(Error::InvalidInput);
        }

        // Validate standard
        if standard.name.len() < 1 {
            return Err(Error::InvalidInput);
        }

        // Store standard
        let mut updated = standards;
        updated.push_back(standard);

        env.storage().persistent().set(
            &Symbol::new(&env, "QUALITY_STANDARDS"),
            &updated,
        );

        Ok(())
    }

    /// Get all quality standards
    pub fn get_quality_standards(env: Env) -> Vec<QualityStandard> {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "QUALITY_STANDARDS"))
            .unwrap_or_else(|| default_quality_standards(&env))
    }

    /// Get standard by ID
    pub fn get_standard_by_id(
        env: Env,
        standard_id: Symbol,
    ) -> Result<QualityStandard, Error> {
        let standards = Self::get_quality_standards(env);

        for i in 0..standards.len() {
            let std = standards.get_unchecked(i);
            if std.standard_id == standard_id {
                return Ok(std);
            }
        }

        Err(Error::EventNotFound)
    }

    // ─── Quality Inspections ──────────────────────────────────────────────────

    /// Record a quality inspection event
    pub fn record_inspection(
        env: Env,
        caller: Address,
        product_id: String,
        inspection_type: InspectionType,
        status: QualityStatus,
        quality_score: u32,
        measurements: Map<Symbol, u64>,
        notes: String,
        certification_id: String,
        has_certification: bool,
    ) -> Result<u64, Error> {
        caller.require_auth();

        // Validate score
        validate_quality_score(quality_score)?;

        // Get next event ID
        let event_id = env
            .storage()
            .persistent()
            .get::<_, u64>(&Symbol::new(&env, "QC_EVENT_SEQ"))
            .unwrap_or(0)
            + 1;

        let event = QualityEvent {
            event_id,
            product_id: product_id.clone(),
            inspector: caller.clone(),
            inspected_at: env.ledger().timestamp(),
            status: status.clone(),
            inspection_type: inspection_type.clone(),
            quality_score,
            measurements,
            notes,
            certification_id: certification_id.clone(),
            has_certification,
        };

        // Store event
        env.storage().persistent().set(
            &(Symbol::new(&env, "QC_EVENT"), event_id),
            &event,
        );

        // Update sequence
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "QC_EVENT_SEQ"), &event_id);

        // Update quality metrics for product
        let cert_ref = if has_certification {
            // Get certification from storage by ID
            env.storage()
                .persistent()
                .get::<_, CertificationRef>(&(Symbol::new(&env, "CERTIFICATION"), certification_id.clone()))
        } else {
            None
        };
        
        Self::update_product_metrics(
            &env,
            product_id.clone(),
            status.clone(),
            quality_score,
            cert_ref,
        );

        // Emit event
        let status_value = quality_status_to_u32(&status);
        let type_value = inspection_type_to_u32(&inspection_type);
        env.events().publish(
            (
                Symbol::new(&env, "quality_inspection"),
                product_id,
                status_value,
                type_value,
            ),
            (event_id, quality_score),
        );

        Ok(event_id)
    }

    /// Get quality event by ID
    pub fn get_quality_event(env: Env, event_id: u64) -> Result<QualityEvent, Error> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "QC_EVENT"), event_id))
            .ok_or(Error::EventNotFound)
    }

    // ─── Quality Metrics ───────────────────────────────────────────────────────

    /// Get quality metrics for a product
    pub fn get_quality_metrics(env: Env, product_id: String) -> QualityMetrics {
        let metrics_key = (Symbol::new(&env, "QC_METRICS"), product_id.clone());
        env.storage()
            .persistent()
            .get(&metrics_key)
            .unwrap_or(QualityMetrics {
                product_id,
                current_status: QualityStatus::Pending,
                overall_score: 0,
                inspection_count: 0,
                passed_count: 0,
                failed_count: 0,
                last_inspection_at: 0,
                certifications: Vec::new(&env),
                standard_compliance: Map::new(&env),
            })
    }

    /// Update product quality metrics (internal)
    fn update_product_metrics(
        env: &Env,
        product_id: String,
        status: QualityStatus,
        score: u32,
        certification: Option<CertificationRef>,
    ) {
        let metrics_key = (Symbol::new(env, "QC_METRICS"), product_id.clone());

        let mut metrics: QualityMetrics = env
            .storage()
            .persistent()
            .get(&metrics_key)
            .unwrap_or(QualityMetrics {
                product_id: product_id.clone(),
                current_status: QualityStatus::Pending,
                overall_score: 0,
                inspection_count: 0,
                passed_count: 0,
                failed_count: 0,
                last_inspection_at: 0,
                certifications: Vec::new(env),
                standard_compliance: Map::new(env),
            });

        metrics.inspection_count += 1;
        metrics.current_status = status.clone();
        metrics.overall_score = ((metrics.overall_score * (metrics.inspection_count - 1) as u32 + score) 
            / metrics.inspection_count as u32);
        metrics.last_inspection_at = env.ledger().timestamp();

        if status == QualityStatus::Passed {
            metrics.passed_count += 1;
        } else if status == QualityStatus::Failed {
            metrics.failed_count += 1;
        }

        // Add certification if provided
        if let Some(cert) = certification {
            if metrics.certifications.len() < Self::MAX_CERTIFICATIONS {
                metrics.certifications.push_back(cert);
            }
        }

        env.storage().persistent().set(&metrics_key, &metrics);
    }

    // ─── IoT Device Management ──────────────────────────────────────────────

    /// Register an IoT device for monitoring
    pub fn register_iot_device(
        env: Env,
        caller: Address,
        device_id: String,
        device_type: Symbol,
        name: String,
        product_id: String,
        sampling_interval: u64,
    ) -> Result<IoTDevice, Error> {
        caller.require_auth();

        // Check existing devices for this product
        let devices = Self::get_product_devices(&env, product_id.clone());
        if devices.len() >= Self::MAX_DEVICES_PER_PRODUCT {
            return Err(Error::InvalidInput);
        }

        let device = IoTDevice {
            device_id: device_id.clone(),
            device_type,
            name,
            owner: caller.clone(),
            product_id: product_id.clone(),
            status: DeviceStatus::Active,
            last_calibrated_at: env.ledger().timestamp(),
            sampling_interval,
            registered_at: env.ledger().timestamp(),
        };

        // Store device
        env.storage().persistent().set(
            &(Symbol::new(&env, "IOT_DEVICE"), device_id.clone()),
            &device,
        );

        // Add to product's device list
        let mut updated_devices = devices;
        updated_devices.push_back(device_id.clone());
        env.storage().persistent().set(
            &(Symbol::new(&env, "PRODUCT_DEVICES"), product_id),
            &updated_devices,
        );

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "iot_device_registered"), device_id),
            caller,
        );

        Ok(device)
    }

    /// Get IoT device details
    pub fn get_iot_device(env: Env, device_id: String) -> Result<IoTDevice, Error> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "IOT_DEVICE"), device_id))
            .ok_or(Error::EventNotFound)
    }

    /// Get devices for a product
    fn get_product_devices(env: &Env, product_id: String) -> Vec<String> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(env, "PRODUCT_DEVICES"), product_id))
            .unwrap_or_else(|| Vec::new(env))
    }

    /// Update device status
    pub fn update_device_status(
        env: Env,
        caller: Address,
        device_id: String,
        new_status: DeviceStatus,
    ) -> Result<(), Error> {
        caller.require_auth();

        let mut device = Self::get_iot_device(env.clone(), device_id.clone())?;

        // Verify caller is device owner
        if device.owner != caller {
            return Err(Error::Unauthorized);
        }

        device.status = new_status.clone();

        // Update calibration timestamp if calibrating
        if matches!(new_status, DeviceStatus::Active) {
            device.last_calibrated_at = env.ledger().timestamp();
        }

        env.storage().persistent().set(
            &(Symbol::new(&env, "IOT_DEVICE"), device_id.clone()),
            &device,
        );

        env.events().publish(
            (Symbol::new(&env, "device_status_updated"), device_id),
            new_status as u32,
        );

        Ok(())
    }

    // ─── Sensor Data ───────────────────────────────────────────────────────────

    /// Record sensor reading from IoT device
    pub fn record_sensor_reading(
        env: Env,
        caller: Address,
        device_id: String,
        sensor_type: Symbol,
        value: u64,
        unit: String,
    ) -> Result<u64, Error> {
        caller.require_auth();

        // Verify device exists and is active
        let device = Self::get_iot_device(env.clone(), device_id.clone())?;
        
        if device.owner != caller {
            return Err(Error::Unauthorized);
        }

        // Get next reading ID
        let reading_id = env
            .storage()
            .persistent()
            .get::<_, u64>(&Symbol::new(&env, "SENSOR_READING_SEQ"))
            .unwrap_or(0)
            + 1;

        let reading = SensorReading {
            reading_id,
            device_id: device_id.clone(),
            product_id: device.product_id.clone(),
            timestamp: env.ledger().timestamp(),
            sensor_type: sensor_type.clone(),
            value,
            unit: unit.clone(),
            is_valid: !matches!(device.status, DeviceStatus::NeedsCalibration | DeviceStatus::Decommissioned),
        };

        // Store reading
        env.storage().persistent().set(
            &(Symbol::new(&env, "SENSOR_READING"), reading_id),
            &reading,
        );

        // Update sequence
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "SENSOR_READING_SEQ"), &reading_id);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "sensor_reading"),
                device.product_id,
                sensor_type,
            ),
            (reading_id, value),
        );

        Ok(reading_id)
    }

    /// Get sensor reading by ID
    pub fn get_sensor_reading(env: Env, reading_id: u64) -> Result<SensorReading, Error> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "SENSOR_READING"), reading_id))
            .ok_or(Error::EventNotFound)
    }

    // ─── Quality Configuration ───────────────────────────────────────────────

    /// Set quality configuration for a product category
    pub fn set_quality_config(
        env: Env,
        caller: Address,
        config: QualityConfig,
    ) -> Result<(), Error> {
        caller.require_auth();

        if config.category.len() < 1 {
            return Err(Error::InvalidInput);
        }

        env.storage().persistent().set(
            &(Symbol::new(&env, "QC_CONFIG"), config.category.clone()),
            &config,
        );

        Ok(())
    }

    /// Get quality configuration for a category
    pub fn get_quality_config(env: Env, category: String) -> Result<QualityConfig, Error> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "QC_CONFIG"), category))
            .ok_or(Error::NotInitialized)
    }

    // ─── Compliance Checking ─────────────────────────────────────────────────

    /// Check if product meets a quality standard
    pub fn check_standard_compliance(
        env: Env,
        product_id: String,
        standard_id: Symbol,
    ) -> Result<bool, Error> {
        let standard = Self::get_standard_by_id(env.clone(), standard_id)?;
        let metrics = Self::get_quality_metrics(env, product_id);

        // Check if quality score meets minimum
        let score_ok = metrics.overall_score >= standard.min_quality_score;

        // For a full check, we'd compare measurements against parameter specs
        // This is a simplified check

        Ok(score_ok && metrics.current_status == QualityStatus::Passed)
    }
}
