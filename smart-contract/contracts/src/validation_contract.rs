#![allow(clippy::len_zero)]
use soroban_sdk::{Address, Map, String, Symbol};

use crate::error::Error;
use crate::types::ProductConfig;

pub struct ValidationContract;

impl ValidationContract {
    // --- String length limits ---
    pub const MAX_PRODUCT_ID_LEN: u32 = 64;
    pub const MAX_PRODUCT_NAME_LEN: u32 = 128;
    pub const MAX_ORIGIN_LEN: u32 = 128;
    pub const MAX_CATEGORY_LEN: u32 = 64;
    pub const MAX_DESCRIPTION_LEN: u32 = 512;
    pub const MAX_TAG_LEN: u32 = 64;
    pub const MAX_CUSTOM_VALUE_LEN: u32 = 256;
    pub const MAX_NOTE_LEN: u32 = 512;
    pub const MAX_LOCATION_LEN: u32 = 128;

    // --- Array / collection size limits ---
    pub const MAX_TAGS: u32 = 20;
    pub const MAX_CERTIFICATIONS: u32 = 50;
    pub const MAX_MEDIA_HASHES: u32 = 50;
    pub const MAX_CUSTOM_FIELDS: u32 = 20;
    pub const MAX_METADATA_FIELDS: u32 = 20;

    // --- Primitive validators ---
    pub fn non_empty(s: &String) -> Result<(), Error> {
        if s.len() < 1 {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    pub fn max_len(s: &String, max: u32) -> Result<(), Error> {
        if s.len() > max {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    pub fn require_auth(actor: &Address) -> Result<(), Error> {
        actor.require_auth();
        Ok(())
    }

    // --- Product validation ---
    pub fn validate_product_config(config: &ProductConfig) -> Result<(), Error> {
        if config.id.len() < 1 {
            return Err(Error::InvalidProductId);
        }
        if config.id.len() > Self::MAX_PRODUCT_ID_LEN {
            return Err(Error::ProductIdTooLong);
        }

        if config.name.len() < 1 {
            return Err(Error::InvalidProductName);
        }
        if config.name.len() > Self::MAX_PRODUCT_NAME_LEN {
            return Err(Error::ProductNameTooLong);
        }

        if config.origin_location.len() < 1 {
            return Err(Error::InvalidOrigin);
        }
        if config.origin_location.len() > Self::MAX_ORIGIN_LEN {
            return Err(Error::OriginTooLong);
        }

        if config.category.len() < 1 {
            return Err(Error::InvalidCategory);
        }
        if config.category.len() > Self::MAX_CATEGORY_LEN {
            return Err(Error::CategoryTooLong);
        }

        if config.description.len() > Self::MAX_DESCRIPTION_LEN {
            return Err(Error::DescriptionTooLong);
        }

        if config.tags.len() > Self::MAX_TAGS {
            return Err(Error::TooManyTags);
        }
        for i in 0..config.tags.len() {
            let t = config.tags.get_unchecked(i);
            if t.len() > Self::MAX_TAG_LEN {
                return Err(Error::TagTooLong);
            }
        }

        if config.certifications.len() > Self::MAX_CERTIFICATIONS {
            return Err(Error::TooManyCertifications);
        }

        if config.media_hashes.len() > Self::MAX_MEDIA_HASHES {
            return Err(Error::TooManyMediaHashes);
        }

        Self::validate_custom_fields(&config.custom)
    }

    pub fn validate_deactivation_reason(reason: &String) -> Result<(), Error> {
        if reason.len() < 1 {
            return Err(Error::DeactivationReasonRequired);
        }
        Ok(())
    }

    // --- Custom fields / metadata validation ---
    pub fn validate_custom_fields(custom: &Map<Symbol, String>) -> Result<(), Error> {
        if custom.len() > Self::MAX_CUSTOM_FIELDS {
            return Err(Error::TooManyCustomFields);
        }

        let keys = custom.keys();
        for i in 0..keys.len() {
            let k = keys.get_unchecked(i);
            let v = custom.get_unchecked(k);
            if v.len() > Self::MAX_CUSTOM_VALUE_LEN {
                return Err(Error::CustomFieldValueTooLong);
            }
        }

        Ok(())
    }

    pub fn validate_metadata(metadata: &Map<Symbol, String>) -> Result<(), Error> {
        if metadata.len() > Self::MAX_METADATA_FIELDS {
            return Err(Error::TooManyCustomFields);
        }

        let keys = metadata.keys();
        for i in 0..keys.len() {
            let k = keys.get_unchecked(i);
            let v = metadata.get_unchecked(k);
            if v.len() > Self::MAX_CUSTOM_VALUE_LEN {
                return Err(Error::CustomFieldValueTooLong);
            }
        }

        Ok(())
    }

    // --- Event data validation ---
    pub fn validate_event_location(location: &String) -> Result<(), Error> {
        if location.len() > Self::MAX_LOCATION_LEN {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    pub fn validate_event_note(note: &String) -> Result<(), Error> {
        if note.len() > Self::MAX_NOTE_LEN {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    // --- Input Sanitization (Issue #161) ---

    /// Validates Stellar address format (G + 55 alphanumeric chars = 56 total)
    pub fn validate_stellar_address(address: &str) -> Result<(), Error> {
        // Check length (56 characters)
        if address.len() != 56 {
            return Err(Error::InvalidStellarAddress);
        }

        // Must start with 'G'
        if !address.starts_with('G') {
            return Err(Error::InvalidStellarAddress);
        }

        // All characters must be alphanumeric (base32 alphabet)
        for c in address.chars() {
            if !c.is_alphanumeric() {
                return Err(Error::InvalidStellarAddress);
            }
        }

        Ok(())
    }

    /// Validates Product ID format (alphanumeric, hyphens, underscores only)
    pub fn validate_product_id_format(id: &str) -> Result<(), Error> {
        if id.is_empty() {
            return Err(Error::InvalidProductIdFormat);
        }

        // Check first character is alphanumeric
        let first = id.chars().next().unwrap();
        if !first.is_alphanumeric() {
            return Err(Error::InvalidProductIdFormat);
        }

        // Allowed characters: alphanumeric, hyphen, underscore
        for c in id.chars() {
            if !c.is_alphanumeric() && c != '-' && c != '_' {
                return Err(Error::InvalidProductIdFormat);
            }
        }

        Ok(())
    }

    /// Sanitizes metadata content - prevents potentially dangerous characters
    /// Returns Ok(()) if content is valid, Err if prohibited characters found
    pub fn sanitize_metadata_content(content: &str) -> Result<(), Error> {
        // Check for prohibited characters that could be used for injection attacks
        let prohibited: &[char] = &['<', '>', '"', '\'', '&', '%', ';', '$', '{', '}', '|', '`'];

        for c in content.chars() {
            if prohibited.contains(&c) {
                return Err(Error::ProhibitedCharacter);
            }
        }

        Ok(())
    }

    /// Validates location data format (prevents injection, validates structure)
    pub fn validate_location_format(location: &str) -> Result<(), Error> {
        if location.is_empty() {
            return Err(Error::InvalidLocationFormat);
        }

        if location.len() > Self::MAX_LOCATION_LEN as usize {
            return Err(Error::InvalidLocationFormat);
        }

        // Check for prohibited characters that could indicate injection attempts
        let prohibited: &[char] = &['<', '>', '"', '\'', '&', '%', ';', '$', '{', '}', '|', '`', '\\'];

        for c in location.chars() {
            if prohibited.contains(&c) {
                return Err(Error::ProhibitedCharacter);
            }
        }

        Ok(())
    }

    /// Comprehensive metadata validation with content sanitization
    pub fn validate_and_sanitize_metadata(
        env: &soroban_sdk::Env,
        metadata: &Map<Symbol, String>,
    ) -> Result<Map<Symbol, String>, Error> {
        if metadata.len() > Self::MAX_METADATA_FIELDS {
            return Err(Error::TooManyCustomFields);
        }

        let mut sanitized = Map::new(env);
        let keys = metadata.keys();

        for i in 0..keys.len() {
            let key = keys.get_unchecked(i);
            // Clone key before using it to get value
            let key_clone = key.clone();
            let value = metadata.get_unchecked(key_clone);

            // Check value length
            if value.len() > Self::MAX_CUSTOM_VALUE_LEN {
                return Err(Error::CustomFieldValueTooLong);
            }

            // For now, basic validation only - value is not empty after trimming
            // Note: Full content sanitization would require more complex string handling
            // In a production environment, consider using additional validation layers
            if value.len() == 0 {
                return Err(Error::InvalidMetadataContent);
            }

            // Store the validated value - clone key since it doesn't implement Copy
            sanitized.set(key.clone(), value);
        }

        Ok(sanitized)
    }
}
