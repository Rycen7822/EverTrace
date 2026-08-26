use std::{fs, path::PathBuf};

pub fn detector_cases() -> Vec<(String, Vec<u8>, bool)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/capture/s04/detector_cases.json");
    let text = fs::read_to_string(path).expect("S04 detector fixture must be readable");
    let values: serde_json::Value =
        serde_json::from_str(&text).expect("S04 detector fixture must be valid JSON");
    values
        .as_array()
        .expect("S04 detector fixture must be an array")
        .iter()
        .map(|value| {
            let object = value.as_object().expect("fixture case must be an object");
            (
                object["name"].as_str().unwrap().to_owned(),
                object["input"].as_str().unwrap().as_bytes().to_vec(),
                object["redacted"].as_bool().unwrap(),
            )
        })
        .collect()
}
