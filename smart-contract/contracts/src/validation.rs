#![allow(dead_code)]
use soroban_sdk::String;

use crate::validation_contract::ValidationContract;

pub fn non_empty(s: &String) -> bool {
    ValidationContract::non_empty(s).is_ok()
}

pub fn max_len(s: &String, max: u32) -> bool {
    ValidationContract::max_len(s, max).is_ok()
}

// --- Input Sanitization Helpers (Issue #161) ---

pub fn valid_stellar_address(address: &str) -> bool {
    ValidationContract::validate_stellar_address(address).is_ok()
}

pub fn valid_product_id(id: &str) -> bool {
    ValidationContract::validate_product_id_format(id).is_ok()
}

pub fn valid_location(location: &str) -> bool {
    ValidationContract::validate_location_format(location).is_ok()
}
