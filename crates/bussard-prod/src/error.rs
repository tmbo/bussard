//! The error type for `.knxprod` product-data reading.

use std::path::PathBuf;

/// An error reading a `.knxprod` product-data file.
#[derive(Debug, thiserror::Error)]
pub enum ProdError {
    /// An I/O error opening or reading a file.
    #[error("reading {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// The outer `.knxprod` ZIP could not be opened.
    #[error("opening .knxprod archive {path}: {source}")]
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

    /// A parameter's default (or override) could not be laid into its segment
    /// memory image: the value did not parse for its type, exceeded the field's
    /// declared width, or the memory location was incomplete.
    #[error("parameter `{parameter}`: {reason}")]
    ParameterImage {
        /// The offending parameter's name (or id if it has no name).
        parameter: String,
        /// What went wrong.
        reason: String,
    },

    /// The product-data pointer index could not be parsed.
    #[error("product index: {reason}")]
    Index {
        /// What went wrong parsing the index.
        reason: String,
    },

    /// A vendor download failed, was oversize, or did not match the index's
    /// declared size or checksum.
    #[error("fetching product data: {reason}")]
    Fetch {
        /// What went wrong (includes remediation guidance).
        reason: String,
    },

    /// An error from the shared ETS-XML primitive layer: XML parsing of an
    /// application program or `Hardware.xml`, and capped zip reads.
    #[error(transparent)]
    Ets(#[from] bussard_ets::EtsError),
}

/// Convenience result alias for the product-data reader.
pub type Result<T> = std::result::Result<T, ProdError>;
