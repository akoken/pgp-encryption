use clap::Parser;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message};
use sequoia_openpgp as openpgp;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use walkdir::WalkDir;

// Exit codes
const EXIT_SUCCESS: i32 = 0;
const EXIT_INVALID_INPUT: i32 = 1;
const EXIT_KEY_ERROR: i32 = 2;
const EXIT_ENCRYPTION_ERROR: i32 = 3;
const EXIT_IO_ERROR: i32 = 4;

#[derive(Parser, Debug)]
#[command(name = "pgp-encrypt", about = "Encrypt files using PGP")]
struct Opt {
    /// Input folder containing files to encrypt
    #[arg(short, long, value_name = "INPUT_DIR")]
    folder: PathBuf,

    /// Output folder for encrypted files
    #[arg(short, long, value_name = "OUTPUT_DIR")]
    output: PathBuf,

    /// Public key file path
    #[arg(short, long, value_name = "KEY_FILE")]
    key: PathBuf,
}

fn run() -> Result<(), (i32, String)> {
    let args: Vec<String> = std::env::args().collect();
    run_with_args(&args.iter().map(String::as_str).collect::<Vec<&str>>())
}

fn run_with_args(args: &[&str]) -> Result<(), (i32, String)> {
    let opt = Opt::parse_from(args);

    // Validate input folder
    if !opt.folder.exists() || !opt.folder.is_dir() {
        return Err((
            EXIT_INVALID_INPUT,
            format!(
                "Input folder '{}' does not exist or is not a directory",
                opt.folder.display()
            ),
        ));
    }

    // Validate or create output folder
    if !opt.output.exists() {
        fs::create_dir_all(&opt.output).map_err(|e| {
            (
                EXIT_IO_ERROR,
                format!("Failed to create output directory: {}", e),
            )
        })?;
    } else if !opt.output.is_dir() {
        return Err((
            EXIT_INVALID_INPUT,
            format!("Output path '{}' is not a directory", opt.output.display()),
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

    // Process all files in the input folder
    for entry in WalkDir::new(&opt.folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();

        // Skip if file is already encrypted
        if file_path.extension().is_some_and(|ext| ext == "pgp") {
            continue;
        }

        // Read input file
        let input_data = fs::read(file_path).map_err(|e| {
            (
                EXIT_IO_ERROR,
                format!("Failed to read {}: {}", file_path.display(), e),
            )
        })?;

        // Create encrypted data
        let mut encrypted_data = Vec::new();
        {
            let message = Message::new(&mut encrypted_data);
            let encryptor = Encryptor2::for_recipients(message, recipients.iter())
                .build()
                .map_err(|e| {
                    (
                        EXIT_ENCRYPTION_ERROR,
                        format!("Failed to create encryptor: {}", e),
                    )
                })?;
            let mut literal_writer = LiteralWriter::new(encryptor).build().map_err(|e| {
                (
                    EXIT_ENCRYPTION_ERROR,
                    format!("Failed to create writer: {}", e),
                )
            })?;
            literal_writer.write_all(&input_data).map_err(|e| {
                (
                    EXIT_ENCRYPTION_ERROR,
                    format!("Failed to write data: {}", e),
                )
            })?;
            literal_writer.finalize().map_err(|e| {
                (
                    EXIT_ENCRYPTION_ERROR,
                    format!("Failed to finalize encryption: {}", e),
                )
            })?;
        }

        // Determine output file path
        let relative_path = file_path.strip_prefix(&opt.folder).unwrap_or(file_path);
        let output_path = opt.output.join(relative_path).with_extension("pgp");

        // Ensure output directories exist
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                (
                    EXIT_IO_ERROR,
                    format!("Failed to create output directories: {}", e),
                )
            })?;
        }

        // Write encrypted file to output folder
        fs::write(&output_path, &encrypted_data).map_err(|e| {
            (
                EXIT_IO_ERROR,
                format!(
                    "Failed to write encrypted file {}: {}",
                    output_path.display(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::Marshal;
    use std::fs::{self, File};
    use std::path::Path;
    use tempfile::{tempdir, TempDir};

    // Helper function to create a test environment
    fn setup_test_environment() -> (TempDir, TempDir, PathBuf) {
        let input_dir = tempdir().unwrap();
        let output_dir = tempdir().unwrap();

        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.com")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();

        let key_path = input_dir.path().join("test_key.pgp");
        let mut key_file = File::create(&key_path).unwrap();
        cert.armored().serialize(&mut key_file).unwrap();

        (input_dir, output_dir, key_path)
    }

    // Helper function to run tests with args
    fn run_test_with_args(folder: &Path, output: &Path, key: &Path) -> Result<(), (i32, String)> {
        let args = vec![
            "pgp-encrypt",
            "--folder",
            folder.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ];
        run_with_args(&args)
    }

    #[test]
    fn test_successful_encryption() {
        let (input_dir, output_dir, key_path) = setup_test_environment();
        assert!(run_test_with_args(input_dir.path(), output_dir.path(), &key_path).is_ok());
    }

    #[test]
    fn test_invalid_input_directory() {
        let (_, output_dir, key_path) = setup_test_environment();
        let invalid_folder = PathBuf::from("/nonexistent/directory");
        let result = run_test_with_args(&invalid_folder, output_dir.path(), &key_path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, EXIT_INVALID_INPUT);
    }

    #[test]
    fn test_invalid_key_file() {
        let (input_dir, output_dir, _) = setup_test_environment();
        let invalid_key = PathBuf::from("/nonexistent/key.pgp");
        let result = run_test_with_args(input_dir.path(), output_dir.path(), &invalid_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, EXIT_INVALID_INPUT);
    }

    #[test]
    fn test_empty_input_directory() {
        let (input_dir, output_dir, key_path) = setup_test_environment();
        assert!(run_test_with_args(input_dir.path(), output_dir.path(), &key_path).is_ok());
        assert!(fs::read_dir(output_dir.path()).unwrap().count() == 0);
    }
}
