//! The shared error type for the ETS-XML primitive layer.
//!
//! Both `.knxproj` import (`bussard-project`) and `.knxprod` reading
//! (`bussard-prod`) wrap this in their own crate-level error enums; the shared
//! layer only distinguishes the failure kinds it can actually produce (XML
//! parse/attribute errors and oversized zip entries).

/// An error from the shared ETS-XML layer.
#[derive(Debug, thiserror::Error)]
pub enum EtsError {
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

    /// A zip entry could not be opened.
    #[error("opening archive entry {entry}: {source}")]
    Zip {
        /// The entry name.
        entry: String,
        /// The underlying zip error.
        source: zip::result::ZipError,
    },

    /// An I/O error reading a zip entry.
    #[error("reading archive entry {entry}: {source}")]
    Io {
        /// The entry name.
        entry: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A zip entry's decompressed size exceeded the safety cap (a zip bomb
    /// guard): reading was aborted before the process could OOM.
    #[error("archive entry {entry} exceeds the {cap}-byte decompression cap (possible zip bomb)")]
    EntryTooLarge {
        /// The offending entry name.
        entry: String,
        /// The cap, in bytes.
        cap: u64,
    },
}

/// Convenience result alias for the shared ETS-XML layer.
pub type Result<T> = std::result::Result<T, EtsError>;
