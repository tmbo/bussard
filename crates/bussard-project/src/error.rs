//! The error type for `.knxproj` import.

use std::path::PathBuf;

/// An error importing a `.knxproj` file.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// An I/O error opening or reading a file.
    #[error("reading {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// The outer `.knxproj` ZIP could not be opened.
    #[error("opening .knxproj archive {path}: {source}")]
    Zip {
        /// The archive path.
        path: PathBuf,
        /// The underlying zip error.
        source: zip::result::ZipError,
    },

    /// An expected entry was missing from the archive.
    #[error("{path}: expected archive entry `{entry}` was not found")]
    MissingEntry {
        /// The archive being read.
        path: PathBuf,
        /// The entry that was expected.
        entry: String,
    },

    /// The project is password-protected but no password was supplied.
    #[error(
        "project is password-protected; supply a password (--password, BUSSARD_PROJECT_PASSWORD, or prompt)"
    )]
    PasswordRequired,

    /// The supplied password did not decrypt the inner project archive.
    #[error("could not decrypt the inner project archive (wrong password?)")]
    WrongPassword,

    /// A referenced manufacturer application-program file was missing.
    #[error(
        "application program `{application}` referenced by device {device} was not found in the archive"
    )]
    MissingApplication {
        /// The application program id.
        application: String,
        /// The device that referenced it.
        device: String,
    },

    /// An XML parse error, annotated with which file/element was being parsed.
    #[error("parsing {context}: {source}")]
    Xml {
        /// Human description of what was being parsed.
        context: String,
        /// The underlying XML error.
        source: quick_xml::Error,
    },

    /// An XML attribute error.
    #[error("parsing {context}: bad attribute: {source}")]
    XmlAttr {
        /// Human description of what was being parsed.
        context: String,
        /// The underlying attribute error.
        source: quick_xml::events::attributes::AttrError,
    },

    /// A structural problem in the project XML (something referenced but not
    /// resolvable, malformed data, …).
    #[error("in {context}: {message}")]
    Malformed {
        /// Human description of what was being parsed.
        context: String,
        /// The problem.
        message: String,
    },

    /// Failed to build the model from parsed data.
    #[error("building model: {0}")]
    Model(String),

    /// Reading the `--from-json` oracle dump failed.
    #[error("reading JSON dump {path}: {source}")]
    Json {
        /// The dump path.
        path: PathBuf,
        /// The underlying JSON error.
        source: serde_json::Error,
    },
}

/// Convenience result alias for the import path.
pub type Result<T> = std::result::Result<T, ImportError>;
