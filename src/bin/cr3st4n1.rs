use base64::Engine;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "cr3st4n1",
    version,
    about = "Sign and verify .cr3st4n1 credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Key management
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Credential operations
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Print content hash (SHA-256 of canonical form)
    Hash {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Generate a new Ed25519 signing key
    Generate {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Extract public key from a signing key
    Public {
        #[arg(long)]
        key: PathBuf,
    },
}

#[derive(Subcommand)]
enum CredentialAction {
    /// Validate a credential against the embedded schema
    Validate {
        #[arg(long)]
        input: PathBuf,
    },
    /// Sign a credential with an Ed25519 key
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a credential's signature
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Inspect a credential: show identity, trust, signature status, content hash
    Inspect {
        #[arg(long)]
        input: PathBuf,
        /// Optional: verify signature inline
        #[arg(long)]
        key: Option<PathBuf>,
        /// Output as JSON (credential + _inspect metadata)
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Key { action } => match action {
            KeyAction::Generate { output } => {
                use ed25519_dalek::SigningKey;
                use rand::rngs::OsRng;

                let key = SigningKey::generate(&mut OsRng);
                let path = output.unwrap_or_else(|| PathBuf::from("key.json"));
                let key_data = serde_json::json!({
                    "secret": base64::engine::general_purpose::STANDARD.encode(key.to_bytes()),
                    "public": base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()),
                });
                std::fs::write(&path, serde_json::to_string_pretty(&key_data)?)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
                println!("Key written to {}", path.display());
                Ok(())
            }
            KeyAction::Public { key } => {
                let key_data: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&key)?)?;
                let public = key_data["public"]
                    .as_str()
                    .ok_or("missing 'public' field in key file")?;
                let pub_data = serde_json::json!({ "public": public });
                println!("{}", serde_json::to_string_pretty(&pub_data)?);
                Ok(())
            }
        },
        Command::Credential { action } => match action {
            CredentialAction::Validate { input } => {
                let content = std::fs::read_to_string(&input)?;
                let value: serde_json::Value = serde_yaml::from_str(&content)?;
                match cr3st4n1::validate(&value) {
                    Ok(()) => {
                        println!("Valid.");
                        Ok(())
                    }
                    Err(errors) => {
                        for e in &errors {
                            eprintln!("  {e}");
                        }
                        process::exit(1);
                    }
                }
            }
            CredentialAction::Sign { input, key, output } => {
                let content = std::fs::read_to_string(&input)?;
                let mut cred: cr3st4n1::Cr3st4n1Credential = serde_yaml::from_str(&content)?;
                let signing_key = load_signing_key(&key)?;
                cr3st4n1::sign(&mut cred, &signing_key)?;
                let yaml = serde_yaml::to_string(&cred)?;
                let out_path = output.unwrap_or(input);
                std::fs::write(&out_path, &yaml)?;
                println!("Signed: {}", out_path.display());
                Ok(())
            }
            CredentialAction::Verify { input, key } => {
                let content = std::fs::read_to_string(&input)?;
                let cred: cr3st4n1::Cr3st4n1Credential = serde_yaml::from_str(&content)?;
                let verifying_key = load_verifying_key(&key)?;
                match cr3st4n1::verify(&cred, &verifying_key) {
                    Ok(()) => {
                        println!("Signature valid.");
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Verification failed: {e}");
                        process::exit(2);
                    }
                }
            }
            CredentialAction::Inspect { input, key, json } => {
                let content = std::fs::read_to_string(&input)?;
                let cred: cr3st4n1::Cr3st4n1Credential = serde_yaml::from_str(&content)?;

                // Schema validation
                let value: serde_json::Value = serde_json::to_value(&cred)?;
                if let Err(errors) = cr3st4n1::validate(&value) {
                    for e in &errors {
                        eprintln!("  {e}");
                    }
                    process::exit(1);
                }

                let hash = cr3st4n1::content_hash(&cred)?;

                // Determine signature status
                let sig_empty = cred.signature.signature.is_empty();
                let (sig_status, sig_reason, exit_code) = if let Some(ref key_path) = key {
                    let vk = load_verifying_key(key_path)?;
                    match cr3st4n1::verify(&cred, &vk) {
                        Ok(()) => ("valid".to_string(), None, 0),
                        Err(e) => ("INVALID".to_string(), Some(e.to_string()), 2),
                    }
                } else if sig_empty {
                    ("absent".to_string(), None, 0)
                } else {
                    ("present".to_string(), None, 0)
                };

                if json {
                    let mut out = serde_json::to_value(&cred)?;
                    let mut inspect = serde_json::json!({
                        "content_hash": hash,
                        "signature_status": sig_status,
                        "schema_valid": true,
                    });
                    if let Some(ref reason) = sig_reason {
                        inspect["signature_reason"] = serde_json::Value::String(reason.clone());
                    }
                    out["_inspect"] = inspect;
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    print_inspect_human(&cred, &hash, &sig_status, sig_reason.as_deref());
                }

                if exit_code != 0 {
                    process::exit(exit_code);
                }
                Ok(())
            }
        },
        Command::Hash { input } => {
            let content = std::fs::read_to_string(&input)?;
            let cred: cr3st4n1::Cr3st4n1Credential = serde_yaml::from_str(&content)?;
            let hash = cr3st4n1::content_hash(&cred)?;
            println!("{hash}");
            Ok(())
        }
    }
}

fn trust_level_name(level: u8) -> &'static str {
    match level {
        0 => "anonymous",
        1 => "email_verified",
        2 => "single_gate",
        3 => "dual_gate",
        4 => "gov_id",
        5 => "fully_attested",
        _ => "unknown",
    }
}

fn print_inspect_human(
    cred: &cr3st4n1::Cr3st4n1Credential,
    hash: &str,
    sig_status: &str,
    sig_reason: Option<&str>,
) {
    use cr3st4n1::types::IdentityType;

    let id = &cred.identity;
    let type_str = match id.identity_type {
        IdentityType::Human => "human",
        IdentityType::AiAgent => "ai_agent",
        IdentityType::Organization => "organization",
    };

    // Identity section
    println!("Identity: {} ({})", id.display_name, type_str);
    println!("  email:     {}", id.email);
    if let Some(ref org) = id.organization {
        println!("  org:       {org}");
    }
    if let Some(ref meta) = id.ai_agent_metadata {
        println!("  operator:  {}", meta.operator_ref);
        if let Some(ref model) = meta.model {
            println!("  model:     {model}");
        }
    }

    // Trust section
    let level = cred.trust.level;
    println!();
    println!("Trust: Level {} ({})", level, trust_level_name(level));
    println!("  providers: {}", id.verification.providers.len());
    let binding = serde_yaml::to_value(&cred.device.binding_level)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", cred.device.binding_level));
    println!("  device:    {binding}");
    if let Some(ref hw) = cred.device.hardware_fingerprint {
        println!("  hw:        {hw}");
    }
    println!("  chain:");
    for entry in &cred.trust.credential_chain {
        println!(
            "    -> {} ({}, {})",
            entry.issuer,
            entry.method,
            entry
                .issued_at
                .split('T')
                .next()
                .unwrap_or(&entry.issued_at)
        );
    }

    // Signature section
    println!();
    println!("Signature:");
    println!(
        "  signer:    {} ({})",
        cred.signature.signer, cred.signature.algorithm
    );
    println!("  signed at: {}", cred.signature.signed_at);
    println!("  hash:      {hash}");
    match (sig_status, sig_reason) {
        ("valid", _) => println!("  status:    valid"),
        ("INVALID", Some(reason)) => println!("  status:    INVALID ({reason})"),
        ("INVALID", None) => println!("  status:    INVALID"),
        ("absent", _) => println!("  status:    absent"),
        _ => println!("  status:    present (use --key to verify)"),
    }
}

fn load_signing_key(
    path: &PathBuf,
) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error>> {
    use base64::Engine;
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let secret_b64 = data["secret"]
        .as_str()
        .ok_or("missing 'secret' field in key file")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(secret_b64)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "signing key must be 32 bytes")?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
}

fn load_verifying_key(
    path: &PathBuf,
) -> Result<ed25519_dalek::VerifyingKey, Box<dyn std::error::Error>> {
    use base64::Engine;
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let public_b64 = data["public"]
        .as_str()
        .ok_or("missing 'public' field in key file")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(public_b64)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)?)
}
