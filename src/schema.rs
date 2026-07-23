use jsonschema::JSONSchema;
use std::sync::LazyLock;

// serde_yaml is archived by dtolnay. Pinned to 0.9 — stable, no updates expected.
static SCHEMA: LazyLock<JSONSchema> = LazyLock::new(|| {
    let json: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schema.json"
    )))
    .expect("embedded schema must be valid JSON");
    JSONSchema::compile(&json).expect("embedded schema must compile")
});

pub fn validate(value: &serde_json::Value) -> Result<(), Vec<String>> {
    let errors: Vec<String> = SCHEMA
        .validate(value)
        .err()
        .map(|iter| {
            iter.map(|e| format!("{} at {}", e, e.instance_path))
                .collect()
        })
        .unwrap_or_default();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
