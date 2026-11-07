//! The one error type of the product crate: ETS-XML parsing, `.knxprod`
//! reading, the parameter image and `.knxproj` import.

use std::path::PathBuf;

/// An error reading ETS product or project data.
#[derive(Debug, thiserror::Error)]
pub enum ProductError {
    /// An I/O error opening or reading a file.
    #[error("reading {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// An outer or inner archive could not be opened.
    #[error("opening {kind} archive {path}: {source}")]
    Zip {
        /// What the archive is: `.knxprod` or `.knxproj`.
        kind: &'static str,
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
    /// A zip entry could not be opened.
    #[error("opening archive entry {entry}: {source}")]
    EntryZip {
        /// The entry name.
        entry: String,
        /// The underlying zip error.
        source: zip::result::ZipError,
    },
    /// An I/O error reading a zip entry.
    #[error("reading archive entry {entry}: {source}")]
    EntryIo {
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
    /// A code segment's inline binary image (`<Data>` or `<Mask>`) is not valid
    /// base64. The segment binary is the firmware/config bytes bussard would
    /// download to the device, so a corrupt payload is a hard failure naming the
    /// exact segment rather than a vague file-level error.
    #[error(
        "parsing {context}: code segment `{segment}` has an invalid base64 {field} payload: {source}"
    )]
    SegmentDecode {
        /// Human description of what was being parsed.
        context: String,
        /// The offending segment id (e.g. `RS-4-1-0`).
        segment: String,
        /// Which child carried the bad payload: `"Data"` or `"Mask"`.
        field: &'static str,
        /// The underlying base64 decode error.
        source: base64::DecodeError,
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
    /// The project is password-protected but no password was supplied.
    #[error(
        "project is password-protected; supply a password (--password, BUSSARD_PROJECT_PASSWORD, or prompt)"
    )]
    PasswordRequired,
    /// The supplied password did not decrypt the inner project archive.
    #[error("could not decrypt the inner project archive (wrong password?)")]
    WrongPassword,
    /// The inner project archive was decrypted but the entry could not be read
    /// to the end.
    ///
    /// Kept apart from [`ProductError::WrongPassword`] so a zip-bomb cap
    /// ([`ProductError::EntryTooLarge`]) or a real I/O failure is not reported
    /// as a bad password. A wrong *traditional ZipCrypto* password does land
    /// here — that cipher only checks one byte, so garbage streams out and
    /// fails the CRC — which is why the message mentions it.
    #[error(
        "reading `{entry}` from the decrypted inner project archive failed: {source} \
         (with an ETS 4/5 export this is also what a wrong password looks like: traditional \
         ZipCrypto has no authentication tag, so a wrong key decrypts to garbage)"
    )]
    DecryptedEntry {
        /// The inner entry that could not be read.
        entry: String,
        /// The underlying read error.
        source: Box<ProductError>,
    },
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
    /// The project uses a group-address style bussard cannot import. bussard's
    /// address model is fixed to the 3-level `main/middle/sub` layout; a
    /// 2-level or free-style project would have its raw addresses mis-split, so
    /// import is refused rather than silently corrupting the data.
    #[error(
        "project uses GroupAddressStyle `{style}`, but bussard only imports ThreeLevel projects; \
         re-export the project from ETS with a 3-level group-address style"
    )]
    UnsupportedGroupAddressStyle {
        /// The actual style declared in `project.xml`.
        style: String,
    },
    /// The project declares an ETS schema version bussard does not recognise —
    /// either below the earliest known (ETS 4.1, schema 11) or an unparseable
    /// namespace. The message names what was found so the user can identify the
    /// ETS release.
    #[error(
        "unsupported ETS schema version `{version}`; bussard imports ETS 4, 5 and 6 exports \
         (project namespace http://knx.org/xml/project/{{11..}})"
    )]
    UnsupportedSchemaVersion {
        /// The version integer (or the raw namespace) that was found.
        version: String,
    },
}

/// Convenience result alias for the product crate.
pub type Result<T> = std::result::Result<T, ProductError>;
