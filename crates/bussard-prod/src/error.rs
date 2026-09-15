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
}

/// Convenience result alias for the product-data reader.
pub type Result<T> = std::result::Result<T, ProdError>;
