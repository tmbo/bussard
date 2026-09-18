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

    /// A ZIP-served wrapper held more than one inner `.knxprod`, so it is
    /// ambiguous which product to import. The caller should pick one (e.g. via
    /// `import-product --inner <name>`).
    #[error(
        "{path} is a ZIP wrapping multiple .knxprod files; pick one with \
         --inner <name>. Candidates: {}",
        entries.join(", ")
    )]
    AmbiguousWrapper {
        /// The wrapper archive being read.
        path: PathBuf,
        /// The inner `.knxprod` entry names, sorted.
        entries: Vec<String>,
    },

    /// A ZIP-served wrapper's inner `.knxprod` decompressed past the size cap
    /// (a zip-bomb guard); it is rejected rather than buffered.
    #[error(
        "{path}: inner .knxprod `{entry}` exceeds the {cap}-byte decompression \
         cap; refusing to buffer it"
    )]
    InnerTooLarge {
        /// The wrapper archive being read.
        path: PathBuf,
        /// The inner `.knxprod` entry that was too large.
        entry: String,
        /// The cap in bytes.
        cap: u64,
    },

    /// A ZIP-served wrapper's inner `.knxprod` was itself a wrapper. Unwrapping
    /// recurses at most one level, so a doubly wrapped archive is rejected.
    #[error(
        "{path}: inner .knxprod `{outer}` is itself a wrapper (contains \
         `{inner}`); nested wrappers are not supported"
    )]
    NestedWrapper {
        /// The outer wrapper archive being read.
        path: PathBuf,
        /// The inner `.knxprod` entry that turned out to be a wrapper.
        outer: String,
        /// The `.knxprod` found nested inside it.
        inner: String,
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
