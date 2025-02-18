use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message};
use sequoia_openpgp as openpgp;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use structopt::StructOpt;
use walkdir::WalkDir;

// Exit codes
const EXIT_SUCCESS: i32 = 0;
const EXIT_INVALID_INPUT: i32 = 1;
const EXIT_KEY_ERROR: i32 = 2;
const EXIT_ENCRYPTION_ERROR: i32 = 3;
const EXIT_IO_ERROR: i32 = 4;

#[derive(StructOpt, Debug)]
#[structopt(name = "pgp-encrypt", about = "Encrypt files using PGP")]
struct Opt {
    /// Input folder containing files to encrypt
    #[structopt(short, long, parse(from_os_str))]
    folder: PathBuf,

    /// Public key file path
    #[structopt(short, long, parse(from_os_str))]
    key: PathBuf,
}

fn run() -> Result<(), (i32, String)> {
    let opt = Opt::from_args();

    // Validate input folder
    if !opt.folder.exists() {
        return Err((
            EXIT_INVALID_INPUT,
            format!("Input folder '{}' does not exist", opt.folder.display()),
        ));
    }

    // Validate public key file
    if !opt.key.exists() {
        return Err((
            EXIT_INVALID_INPUT,
            format!("Public key file '{}' does not exist", opt.key.display()),
        ));
    }

    // Create policy
    let policy = StandardPolicy::new();

    // Read and parse public key
    let key_data = fs::read(&opt.key)
        .map_err(|e| (EXIT_IO_ERROR, format!("Failed to read public key: {}", e)))?;
    let cert = openpgp::Cert::from_bytes(&key_data)
        .map_err(|e| (EXIT_KEY_ERROR, format!("Invalid public key: {}", e)))?;

    // Get encryption-capable key
    let recipients = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(|k| k.key().clone())
        .collect::<Vec<_>>();

    if recipients.is_empty() {
        return Err((
            EXIT_KEY_ERROR,
            "No valid encryption key found in the certificate".to_string(),
        ));
    }

    // Process all files
    for entry in WalkDir::new(&opt.folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path().to_owned();

        // Skip if file is already encrypted
        if file_path.extension().map_or(false, |ext| ext == "pgp") {
            continue;
        }

        // Read input file
        let input_data = fs::read(&file_path).map_err(|e| {
            (
                EXIT_IO_ERROR,
                format!("Failed to read {}: {}", file_path.display(), e),
            )
        })?;

        // Create encrypted data
        let mut encrypted_data = Vec::new();
        {
            let message = Message::new(&mut encrypted_data);

            // Create encryptor using Encryptor2
            let encryptor = Encryptor2::for_recipients(message, recipients.iter())
                .build()
                .map_err(|e| {
                    (
                        EXIT_ENCRYPTION_ERROR,
                        format!("Failed to create encryptor: {}", e),
                    )
                })?;

            // Create literal writer
            let mut literal_writer = LiteralWriter::new(encryptor).build().map_err(|e| {
                (
                    EXIT_ENCRYPTION_ERROR,
                    format!("Failed to create writer: {}", e),
                )
            })?;

            // Write data
            literal_writer.write_all(&input_data).map_err(|e| {
                (
                    EXIT_ENCRYPTION_ERROR,
                    format!("Failed to write data: {}", e),
                )
            })?;

            // Finalize
            literal_writer.finalize().map_err(|e| {
                (
                    EXIT_ENCRYPTION_ERROR,
                    format!("Failed to finalize encryption: {}", e),
                )
            })?;
        }

        // Create temporary file for atomic replacement
        let temp_path = file_path.with_extension("pgp.tmp");
        fs::write(&temp_path, &encrypted_data).map_err(|e| {
            (
                EXIT_IO_ERROR,
                format!(
                    "Failed to write temporary file {}: {}",
                    temp_path.display(),
                    e
                ),
            )
        })?;

        // Atomically replace original file with encrypted version
        fs::rename(&temp_path, &file_path).map_err(|e| {
            // Try to clean up temp file if rename fails
            let _ = fs::remove_file(&temp_path);
            (
                EXIT_IO_ERROR,
                format!(
                    "Failed to replace original file {}: {}",
                    file_path.display(),
                    e
                ),
            )
        })?;
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(_) => process::exit(EXIT_SUCCESS),
        Err((code, message)) => {
            eprintln!("Error: {}", message);
            process::exit(code);
        }
    }
}

