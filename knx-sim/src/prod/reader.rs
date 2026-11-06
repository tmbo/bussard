//! ZIP + XML reader that turns a `.knxprod` into [`ProductData`].

use std::io::Read;
use std::path::Path;

use base64::Engine;
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::prod::branch::{Candidates, ChooseStack, Defaults};
use crate::prod::model::{
    LSM_ADDRESS_TABLE, LSM_ASSOCIATION_TABLE, LSM_COMOBJECT_TABLE, LdCtrl, LoadProcedure,
    LoadableObject, ProductData, RelativeSegment,
};

/// Errors from reading a `.knxprod`.
#[derive(Debug, thiserror::Error)]
pub enum ProdError {
    /// I/O error opening or reading the file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The ZIP container could not be opened.
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The XML could not be parsed.
    #[error("xml error: {0}")]
    Xml(#[from] quick_xml::Error),
    /// No `ApplicationProgram` element was found in any product XML.
    #[error("no ApplicationProgram found in .knxprod")]
    NoApplicationProgram,
    /// A base64 `<Data>` payload failed to decode.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A numeric attribute could not be parsed.
    #[error("bad numeric attribute {attr}={value:?}")]
    BadNumber {
        /// The attribute name.
        attr: String,
        /// The offending value.
        value: String,
    },
}

/// Read a `.knxprod` file from disk and extract its flash-relevant product data.
///
/// If the container holds several application programs, `application_id` selects
/// one; pass `None` to take the first found.
pub fn read_knxprod(
    path: impl AsRef<Path>,
    application_id: Option<&str>,
) -> Result<ProductData, ProdError> {
    let bytes = std::fs::read(path)?;
    read_knxprod_bytes(&bytes, application_id)
}

/// Read a `.knxprod` from an in-memory buffer.
pub fn read_knxprod_bytes(
    bytes: &[u8],
    application_id: Option<&str>,
) -> Result<ProductData, ProdError> {
    let cursor = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(cursor)?;

    // Collect names of candidate application XML files. The application program
    // lives in a per-manufacturer file like `M-00FA/M-00FA_A-2500-10-51CB.xml`.
    // We skip the master, catalog and hardware files by content inspection.
    let mut names: Vec<String> = Vec::new();
    for i in 0..zip.len() {
        let f = zip.by_index(i)?;
        let name = f.name()?.into_owned();
        if name.ends_with(".xml") {
            names.push(name);
        }
    }

    for name in &names {
        let mut content = String::new();
        zip.by_name(name)?.read_to_string(&mut content)?;
        if !content.contains("<ApplicationProgram") {
            continue;
        }
        if let Some(mut pd) = parse_application_program(&content, application_id)? {
            attach_pei_programs(&mut zip, &names, &mut pd)?;
            return Ok(pd);
        }
    }
    Err(ProdError::NoApplicationProgram)
}

/// The application ids a `Hardware2Program` of the archive lists next to
/// `app_id`, read from every `Hardware.xml`.
fn hardware_partners<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    names: &[String],
    app_id: &str,
) -> Result<Vec<String>, ProdError> {
    let needle = format!("RefId=\"{app_id}\"");
    let mut partners: Vec<String> = Vec::new();
    for name in names.iter().filter(|n| n.ends_with("Hardware.xml")) {
        let mut content = String::new();
        zip.by_name(name)?.read_to_string(&mut content)?;
        if !content.contains(&needle) {
            continue;
        }
        let mut reader = Reader::from_str(&content);
        let mut group: Option<Vec<String>> = None;
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Eof => break,
                Event::Start(e) if e.name().as_ref() == b"Hardware2Program" => {
                    group = Some(Vec::new());
                }
                Event::Start(e) | Event::Empty(e)
                    if e.name().as_ref() == b"ApplicationProgramRef" =>
                {
                    if let (Some(g), Some(id)) = (group.as_mut(), attr(&e, "RefId")) {
                        g.push(id);
                    }
                }
                Event::End(e) if e.name().as_ref() == b"Hardware2Program" => {
                    if let Some(g) = group.take()
                        && g.iter().any(|id| id == app_id)
                    {
                        for id in g {
                            if id != app_id && !partners.contains(&id) {
                                partners.push(id);
                            }
                        }
                    }
                }
                _ => {}
            }
            buf.clear();
        }
    }
    Ok(partners)
}

/// Folds into `pd` what the `PeiProgram`s paired with the application
/// (`Hardware2Program`) bring to the device: ETS downloads such a companion in
/// the same session (an ABB i-bus control element pairs `A-488A-11` with the
/// PEI program `A-488A-21`, which allocates object 5 and writes its PID 16 and
/// PID 13). The real hardware serves those properties and that segment, so the
/// simulated device must too; without them a write to object 5 PID 16 went
/// unanswered and timed the flash out.
fn attach_pei_programs<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    names: &[String],
    pd: &mut ProductData,
) -> Result<(), ProdError> {
    let partners = hardware_partners(zip, names, &pd.application_id)?;
    for id in partners {
        let Some(name) = names.iter().find(|n| n.ends_with(&format!("{id}.xml"))) else {
            continue;
        };
        let mut content = String::new();
        zip.by_name(name)?.read_to_string(&mut content)?;
        let is_pei = content
            .find("<ApplicationProgram ")
            .and_then(|start| {
                let tag = &content[start..];
                tag.find('>').map(|end| &tag[..end])
            })
            .is_some_and(|tag| tag.contains("ProgramType=\"PeiProgram\""));
        if !is_pei {
            continue;
        }
        let Some(pei) = parse_application_program(&content, Some(&id))? else {
            continue;
        };
        for prop in pei.written_props {
            if !pd
                .written_props
                .iter()
                .any(|&(o, p, _, _)| o == prop.0 && p == prop.1)
            {
                pd.written_props.push(prop);
            }
        }
        for object in pei.objects {
            if pd.object(object.lsm_index).is_none() {
                pd.objects.push(object);
            }
        }
        for segment in pei.segments {
            if pd.segment(segment.lsm_index).is_none() {
                pd.segments.push(segment);
            }
        }
    }
    pd.objects.sort_by_key(|o| o.lsm_index);
    Ok(())
}

/// Record the object type a property step declares for the object it
/// addresses by index (both `ObjIdx` and `ObjType` present).
fn record_object_type(
    e: &quick_xml::events::BytesStart<'_>,
    object_types: &mut Vec<(u8, u16)>,
) -> Result<(), ProdError> {
    let object = parse_u32(e, "ObjIdx")?.and_then(|v| u8::try_from(v).ok());
    let object_type = parse_u32(e, "ObjType")?.and_then(|v| u16::try_from(v).ok());
    if let (Some(object), Some(object_type)) = (object, object_type)
        && !object_types.iter().any(|&(o, _)| o == object)
    {
        object_types.push((object, object_type));
    }
    Ok(())
}

/// A property write of a module definition's load procedure (bussard issue
/// #422), resolved per module instance after the parse.
#[derive(Debug, Clone)]
struct ModuleWrite {
    /// The `ModuleDef` it belongs to.
    def: String,
    /// `ObjIdx`, relative to `base_object`'s argument when given.
    object: u8,
    /// `PropId`.
    pid: u8,
    /// The `InlineData` length, when any.
    inline_len: Option<usize>,
    /// `Count`.
    count: u16,
    /// `StartElement`, relative to `base_start`'s argument when given.
    start: usize,
    /// The module argument that holds the base object index (`BaseObjIdx`).
    base_object: Option<String>,
    /// The module argument that holds the base element (`BaseStartElement`).
    base_start: Option<String>,
}

/// A compare's target as `(object, PID, StartElement, Count)`.
type ElementCompare<K> = (K, u8, u16, u16);

/// The compares of one property merged into its element array, as
/// `(key, value, element count)` (bussard issue #422).
///
/// An `LdCtrlCompareProp` checks `Count` elements (default 1) from
/// `StartElement` (default 1), the `InlineData` holding them back to back.
/// A Siemens 07B0 program checks object 4's PID 246 one element at a time
/// (elements 1, 2, 3, 5 and 6 of one octet each); its IP interfaces check
/// elements 1 to 4 and 5 to 6 of a type-50100 object in two steps. A device of
/// that hardware holds all of them in one property, so the value is the
/// elements in order, an element no compare names left 0. The element size is
/// that of the first compare (its `InlineData` over its `Count`); a compare of
/// another size, or of a length `Count` does not divide, keeps the property
/// one element of that compare's value, as before.
fn merge_element_compares<K: PartialEq + Clone>(
    picked: Vec<(ElementCompare<K>, Vec<u8>)>,
) -> Vec<((K, u8), Vec<u8>, u16)> {
    let mut keys: Vec<(K, u8)> = Vec::new();
    for ((k, pid, _, _), _) in &picked {
        if !keys.iter().any(|(kk, p)| kk == k && p == pid) {
            keys.push((k.clone(), *pid));
        }
    }
    keys.into_iter()
        .filter_map(|(k, pid)| {
            let parts: Vec<(usize, usize, &Vec<u8>)> = picked
                .iter()
                .filter(|((kk, p, _, _), _)| *kk == k && *p == pid)
                .map(|((_, _, start, count), v)| (usize::from(*start), usize::from(*count), v))
                .collect();
            let &(_, count, first) = parts.first()?;
            if first.is_empty() || !first.len().is_multiple_of(count) {
                return Some(((k, pid), first.clone(), 1));
            }
            let size = first.len() / count;
            let fits = |&&(_, n, v): &&(usize, usize, &Vec<u8>)| v.len() == n * size;
            let elements = parts
                .iter()
                .filter(fits)
                .map(|&(start, n, _)| start + n - 1)
                .max()?;
            let mut value = vec![0u8; elements * size];
            for &(start, _, v) in parts.iter().filter(fits) {
                let from = (start - 1) * size;
                value.get_mut(from..from + v.len())?.copy_from_slice(v);
            }
            Some(((k, pid), value, u16::try_from(elements).ok()?))
        })
        .collect()
}

/// The PDT code and element size of a `PropType` name of the product
/// schema (KNX 3/7/3 Standardized Identifier Tables §4.1).
/// `None` for a type without a fixed element size.
fn pdt_by_name(name: &str) -> Option<(u8, usize)> {
    if let Some(n) = name.strip_prefix("PDT_GENERIC_") {
        let size: u8 = n.parse().ok()?;
        return (1..=20)
            .contains(&size)
            .then(|| (0x10 + size, usize::from(size)));
    }
    Some(match name {
        "PDT_CHAR" => (0x01, 1),
        "PDT_UNSIGNED_CHAR" => (0x02, 1),
        "PDT_INT" => (0x03, 2),
        "PDT_UNSIGNED_INT" => (0x04, 2),
        "PDT_KNX_FLOAT" => (0x05, 2),
        "PDT_DATE" => (0x06, 3),
        "PDT_TIME" => (0x07, 3),
        "PDT_LONG" => (0x08, 4),
        "PDT_UNSIGNED_LONG" => (0x09, 4),
        "PDT_FLOAT" => (0x0A, 4),
        "PDT_DOUBLE" => (0x0B, 8),
        "PDT_CHAR_BLOCK" => (0x0C, 10),
        "PDT_POLL_GROUP_SETTINGS" => (0x0D, 3),
        "PDT_SHORT_CHAR_BLOCK" => (0x0E, 5),
        "PDT_DATE_TIME" => (0x0F, 8),
        _ => return None,
    })
}

/// Decode an even-length hex string (as used by `InlineData`); `None` on any
/// malformed input rather than a partial value.
///
/// Works on bytes, not `str` slices: a vendor file may carry any UTF-8 in that
/// attribute, and `&s[i..i + 2]` on a multi-byte character panics on a char
/// boundary. A non-ASCII byte simply fails the hex-digit test here.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = hex_digit(pair[0])?;
            let lo = hex_digit(pair[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

/// One ASCII hex digit as its value, or `None` for anything else (including
/// every non-ASCII byte).
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn attr<'a>(e: &'a quick_xml::events::BytesStart<'a>, key: &str) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        if a.key.as_ref() == key.as_bytes() {
            Some(String::from_utf8_lossy(&a.value).into_owned())
        } else {
            None
        }
    })
}

fn parse_u32(e: &quick_xml::events::BytesStart<'_>, key: &str) -> Result<Option<u32>, ProdError> {
    match attr(e, key) {
        None => Ok(None),
        Some(v) => v
            .parse::<u32>()
            .map(Some)
            .map_err(|_| ProdError::BadNumber {
                attr: key.to_string(),
                value: v,
            }),
    }
}

/// Parse an application-program XML string into product data.
///
/// Returns `Ok(None)` if the requested `application_id` is not the one in this
/// file (so the caller keeps scanning other files).
fn parse_application_program(
    xml: &str,
    want_id: Option<&str>,
) -> Result<Option<ProductData>, ProdError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut app_id = String::new();
    let mut app_number: u32 = 0;
    let mut app_version: u32 = 0;
    let mut mask_version = String::new();
    let mut security_capacity = super::model::SecurityCapacity::default();
    let mut in_app = false;

    let mut has_address_table = false;
    let mut has_association_table = false;
    let mut has_comobject_table = false;
    let mut segments: Vec<RelativeSegment> = Vec::new();
    let mut load_procedures: Vec<LoadProcedure> = Vec::new();
    // Compare candidates with the `<when>` guards they sit under; the vendor
    // defaults pick one value per property after the parse (issue #400).
    let mut marker_cands: Candidates<()> = Vec::new();
    let mut device_cands: Candidates<u8> = Vec::new();
    // Keyed with the compare's `StartElement` and `Count`: the compares of
    // one property may each check a few of its elements (bussard issue #422).
    let mut object_cands: Candidates<(u8, u8, u16, u16)> = Vec::new();
    let mut typed_cands: Candidates<(u16, u8, u16, u16)> = Vec::new();
    let mut chooses = ChooseStack::default();
    let mut defaults = Defaults::default();
    let mut written_props: Vec<(u8, u8, usize, u16)> = Vec::new();
    let mut task_segment_lsms: Vec<u8> = Vec::new();
    let mut completes_loads = false;
    let mut compare_mems: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut function_props: Vec<(u8, u8)> = Vec::new();
    let mut typed_lsm_types: Vec<u16> = Vec::new();
    let mut typed_function_props: Vec<(u16, u8)> = Vec::new();
    let mut typed_props: Vec<crate::prod::TypedProperty> = Vec::new();
    let mut object_types: Vec<(u8, u16)> = Vec::new();
    // The `InlineData` length (when any) and `Count` of each property write,
    // sized after the parse from the parameters the product stores in the
    // property (issue #841).
    let mut written_raw: Vec<(PropTarget, u8, Option<usize>, u16)> = Vec::new();
    // The last element any property write reaches (`StartElement` + `Count`
    // - 1), and the `LdCtrlDeclarePropDesc` data types (bussard issue #422).
    let mut write_ends: Vec<(PropTarget, u8, usize)> = Vec::new();
    let mut declared_descs: Vec<(PropTarget, u8, u8, usize)> = Vec::new();
    // Module definitions (bussard issue #422): the property writes of a
    // `<ModuleDef>`'s own load procedure, addressed relative to the module's
    // arguments, and every `<Module>` instance with its numeric arguments.
    let mut cur_module_def: Option<String> = None;
    let mut cur_module: Option<(String, Vec<(String, u32)>)> = None;
    let mut module_writes: Vec<ModuleWrite> = Vec::new();
    let mut module_instances: Vec<(String, Vec<(String, u32)>)> = Vec::new();
    let mut type_bits: std::collections::HashMap<String, TypeSize> = Default::default();
    let mut prop_locs: Vec<PropLocation> = Vec::new();
    let mut cur_ptype: Option<String> = None;
    let mut cur_param_type: Option<String> = None;
    let mut cur_union_bits: Option<u32> = None;
    // Whether the procedure holds a property op, and any other load op.
    let mut property_ops = false;
    let mut other_ops = false;

    // Transient state while parsing a RelativeSegment (which has a child <Data>).
    let mut cur_segment: Option<RelativeSegment> = None;
    let mut in_data = false;
    let mut data_text = String::new();

    // Transient state while parsing a LoadProcedure.
    let mut cur_proc: Option<LoadProcedure> = None;

    let mut buf = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buf)?;
        // A self-closing `<RelativeSegment/>` (no `<Data>` child) never emits an
        // End event, so its segment must be flushed here rather than on End.
        let is_empty_element = matches!(event, Event::Empty(_));
        // A load op that is neither a property op nor the session around it:
        // the procedure is not property-only.
        if in_app
            && let Event::Start(e) | Event::Empty(e) = &event
            && e.name().as_ref().starts_with(b"LdCtrl")
            && !matches!(
                e.name().as_ref(),
                b"LdCtrlConnect"
                    | b"LdCtrlDisconnect"
                    | b"LdCtrlRestart"
                    | b"LdCtrlWriteProp"
                    | b"LdCtrlCompareProp"
            )
        {
            other_ops = true;
        }
        // The size of the parameter type being read, from its first child
        // that gives one.
        if let Some(id) = &cur_ptype
            && let Event::Start(e) | Event::Empty(e) = &event
            && let Some(size) = type_size(e)?
        {
            type_bits.entry(id.clone()).or_insert(size);
        }
        match event {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.name().as_ref() {
                b"ApplicationProgram" => {
                    app_id = attr(&e, "Id").unwrap_or_default();
                    if let Some(want) = want_id
                        && want != app_id
                    {
                        return Ok(None);
                    }
                    app_number = parse_u32(&e, "ApplicationNumber")?.unwrap_or(0);
                    app_version = parse_u32(&e, "ApplicationVersion")?.unwrap_or(0);
                    mask_version = attr(&e, "MaskVersion").unwrap_or_default();
                    // The Data Secure table capacities (bussard issue #537).
                    let rows = |key: &str| -> Result<Option<u16>, ProdError> {
                        Ok(parse_u32(&e, key)?.map(|n| u16::try_from(n).unwrap_or(u16::MAX)))
                    };
                    security_capacity = super::model::SecurityCapacity {
                        group_key_rows: rows("MaxSecurityGroupKeyTableEntries")?,
                        ia_rows: rows("MaxSecurityIndividualAddressEntries")?,
                    };
                    in_app = true;
                }
                b"Parameter" if in_app => {
                    if let Some(id) = attr(&e, "Id") {
                        defaults.parameter(id, attr(&e, "Value"));
                    }
                    if !is_empty_element {
                        cur_param_type = attr(&e, "ParameterType");
                    }
                }
                b"ParameterType" if in_app && !is_empty_element => {
                    cur_ptype = attr(&e, "Id");
                }
                b"Union" if in_app && !is_empty_element => {
                    cur_union_bits = parse_u32(&e, "SizeInBit")?;
                }
                // Where a parameter (or a union of them) lives when the
                // product stores it in a property rather than in memory.
                b"ModuleDef" if in_app && !is_empty_element => {
                    cur_module_def = attr(&e, "Id");
                }
                b"Module" if in_app => {
                    if let Some(def) = attr(&e, "RefId") {
                        if is_empty_element {
                            module_instances.push((def, Vec::new()));
                        } else {
                            cur_module = Some((def, Vec::new()));
                        }
                    }
                }
                b"NumericArg" if in_app => {
                    if let (Some((_, args)), Some(arg), Some(value)) = (
                        cur_module.as_mut(),
                        attr(&e, "RefId"),
                        parse_u32(&e, "Value")?,
                    ) {
                        args.push((arg, value));
                    }
                }
                // A parameter of a module definition is stored relative to
                // the module's base object: not a location of its own.
                b"Property"
                    if in_app
                        && cur_module_def.is_none()
                        && (cur_param_type.is_some() || cur_union_bits.is_some()) =>
                {
                    let target = match (
                        parse_u32(&e, "ObjectIndex")?.and_then(|v| u8::try_from(v).ok()),
                        parse_u32(&e, "ObjectType")?.and_then(|v| u16::try_from(v).ok()),
                    ) {
                        (Some(index), _) => Some(PropTarget::Index(index)),
                        (None, Some(object_type)) => Some(PropTarget::Type(object_type)),
                        (None, None) => None,
                    };
                    let pid = parse_u32(&e, "PropertyId")?.and_then(|v| u8::try_from(v).ok());
                    if let (Some(target), Some(pid)) = (target, pid) {
                        prop_locs.push(PropLocation {
                            target,
                            pid,
                            offset: parse_u32(&e, "Offset")?.unwrap_or(0),
                            bit_offset: parse_u32(&e, "BitOffset")?.unwrap_or(0),
                            size: match (&cur_param_type, cur_union_bits) {
                                (Some(ptype), _) => LocationSize::Type(ptype.clone()),
                                (None, Some(bits)) => LocationSize::Bits(bits),
                                (None, None) => LocationSize::Bits(0),
                            },
                        });
                    }
                }
                b"ParameterRef" if in_app => {
                    if let (Some(id), Some(ref_id)) = (attr(&e, "Id"), attr(&e, "RefId")) {
                        defaults.parameter_ref(id, ref_id, attr(&e, "Value"));
                    }
                }
                b"choose" if in_app && !is_empty_element => {
                    chooses.open_choose(attr(&e, "ParamRefId").unwrap_or_default());
                }
                b"when" if in_app => {
                    let default = attr(&e, "default").is_some_and(|v| v == "true");
                    chooses.open_when(attr(&e, "test").as_deref(), default, !is_empty_element);
                }
                b"AddressTable" if in_app => has_address_table = true,
                b"AssociationTable" if in_app => has_association_table = true,
                b"ComObjectTable" if in_app => has_comobject_table = true,
                b"RelativeSegment" if in_app => {
                    let lsm = parse_u32(&e, "LoadStateMachine")?.unwrap_or(0) as u8;
                    let size = parse_u32(&e, "Size")?.unwrap_or(0);
                    let offset = parse_u32(&e, "Offset")?.unwrap_or(0);
                    let seg = RelativeSegment {
                        lsm_index: lsm,
                        size,
                        offset,
                        data: Vec::new(),
                    };
                    if is_empty_element {
                        segments.push(seg);
                    } else {
                        cur_segment = Some(seg);
                    }
                }
                b"Data" if cur_segment.is_some() => {
                    in_data = true;
                    data_text.clear();
                }
                b"LoadProcedure" if in_app => {
                    let merge_id = parse_u32(&e, "MergeId")?;
                    cur_proc = Some(LoadProcedure {
                        merge_id,
                        steps: Vec::new(),
                    });
                }
                b"LdCtrlRelSegment" => {
                    if let Some(p) = cur_proc.as_mut() {
                        p.steps.push(LdCtrl::RelSegment {
                            lsm_index: parse_u32(&e, "LsmIdx")?.unwrap_or(0) as u8,
                            size: parse_u32(&e, "Size")?.unwrap_or(0),
                            mode: parse_u32(&e, "Mode")?.unwrap_or(0) as u8,
                            fill: parse_u32(&e, "Fill")?.unwrap_or(0) as u8,
                        });
                    }
                }
                b"LdCtrlWriteRelMem" => {
                    if let Some(p) = cur_proc.as_mut() {
                        let verify = attr(&e, "Verify")
                            .map(|v| v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);
                        p.steps.push(LdCtrl::WriteRelMem {
                            obj_index: parse_u32(&e, "ObjIdx")?.unwrap_or(0) as u8,
                            offset: parse_u32(&e, "Offset")?.unwrap_or(0),
                            size: parse_u32(&e, "Size")?.unwrap_or(0),
                            verify,
                        });
                    }
                }
                b"LdCtrlMasterReset" => {
                    if let Some(p) = cur_proc.as_mut() {
                        p.steps.push(LdCtrl::MasterReset {
                            erase_code: parse_u32(&e, "EraseCode")?.unwrap_or(0) as u8,
                            channel: parse_u32(&e, "ChannelNumber")?.unwrap_or(0) as u8,
                        });
                    }
                }
                b"LdCtrlWriteProp"
                    if in_app && cur_module_def.is_some() && attr(&e, "ObjIdx").is_some() =>
                {
                    property_ops = true;
                    if let (Some(def), Some(object), Some(pid)) = (
                        cur_module_def.clone(),
                        parse_u32(&e, "ObjIdx")?.and_then(|v| u8::try_from(v).ok()),
                        parse_u32(&e, "PropId")?.and_then(|v| u8::try_from(v).ok()),
                    ) {
                        module_writes.push(ModuleWrite {
                            def,
                            object,
                            pid,
                            inline_len: attr(&e, "InlineData")
                                .and_then(|hex| decode_hex(&hex))
                                .map(|v| v.len())
                                .filter(|&n| n > 0),
                            count: parse_u32(&e, "Count")?
                                .and_then(|v| u16::try_from(v).ok())
                                .unwrap_or(1),
                            start: parse_u32(&e, "StartElement")?
                                .and_then(|v| usize::try_from(v).ok())
                                .unwrap_or(1)
                                .max(1),
                            base_object: attr(&e, "BaseObjIdx"),
                            base_start: attr(&e, "BaseStartElement"),
                        });
                    }
                }
                b"LdCtrlWriteProp" if in_app => {
                    property_ops = true;
                    record_object_type(&e, &mut object_types)?;
                    let obj_type = parse_u32(&e, "ObjType")?.and_then(|v| u16::try_from(v).ok());
                    let pid8 = parse_u32(&e, "PropId")?.and_then(|v| u8::try_from(v).ok());
                    if parse_u32(&e, "ObjIdx")?.is_none()
                        && let (Some(object_type), Some(pid)) = (obj_type, pid8)
                    {
                        match typed_props
                            .iter_mut()
                            .find(|t| t.object_type == object_type && t.pid == pid)
                        {
                            Some(t) => t.written = true,
                            None => typed_props.push(crate::prod::TypedProperty {
                                object_type,
                                pid,
                                compare: None,
                                written: true,
                                len: 0,
                                count: 1,
                                pdt: None,
                                compare_elements: 1,
                            }),
                        }
                    }
                    let object = parse_u32(&e, "ObjIdx")?.and_then(|v| u8::try_from(v).ok());
                    let pid = parse_u32(&e, "PropId")?.and_then(|v| u8::try_from(v).ok());
                    let inline_len = attr(&e, "InlineData")
                        .and_then(|hex| decode_hex(&hex))
                        .map(|v| v.len())
                        .filter(|&n| n > 0);
                    // `Count` elements of `len / Count` octets (issue #692).
                    let count = parse_u32(&e, "Count")?
                        .and_then(|v| u16::try_from(v).ok())
                        .unwrap_or(1);
                    let target = match (object, obj_type) {
                        (Some(object), _) => Some(PropTarget::Index(object)),
                        (None, Some(object_type)) => Some(PropTarget::Type(object_type)),
                        (None, None) => None,
                    };
                    let start = parse_u32(&e, "StartElement")?
                        .and_then(|v| usize::try_from(v).ok())
                        .unwrap_or(1)
                        .max(1);
                    if let (Some(target), Some(pid)) = (target, pid) {
                        let end = start + usize::from(count.max(1)) - 1;
                        match write_ends
                            .iter_mut()
                            .find(|(t, p, _)| *t == target && *p == pid)
                        {
                            Some(entry) => entry.2 = entry.2.max(end),
                            None => write_ends.push((target, pid, end)),
                        }
                    }
                    if let (Some(target), Some(pid)) = (target, pid)
                        && !written_raw
                            .iter()
                            .any(|&(t, p, _, _)| t == target && p == pid)
                    {
                        written_raw.push((target, pid, inline_len, count));
                    }
                }
                b"LdCtrlUnload" | b"LdCtrlLoad" | b"LdCtrlLoadCompleted" if in_app => {
                    if e.name().as_ref() == b"LdCtrlLoadCompleted" {
                        completes_loads = true;
                    }
                    // A load control on an object named by type (bussard
                    // issue #422: the Gira Eco's type 40960).
                    if parse_u32(&e, "LsmIdx")?.is_none()
                        && let Some(object_type) =
                            parse_u32(&e, "ObjType")?.and_then(|v| u16::try_from(v).ok())
                        && !typed_lsm_types.contains(&object_type)
                    {
                        typed_lsm_types.push(object_type);
                    }
                }
                b"LdCtrlTaskSegment" if in_app => {
                    if let Some(lsm) = parse_u32(&e, "LsmIdx")?.and_then(|v| u8::try_from(v).ok())
                        && !task_segment_lsms.contains(&lsm)
                    {
                        task_segment_lsms.push(lsm);
                    }
                }
                b"LdCtrlDeclarePropDesc" if in_app => {
                    let object = parse_u32(&e, "ObjIdx")?.and_then(|v| u8::try_from(v).ok());
                    let object_type = parse_u32(&e, "ObjType")?.and_then(|v| u16::try_from(v).ok());
                    let target = match (object, object_type) {
                        (Some(object), _) => Some(PropTarget::Index(object)),
                        (None, Some(object_type)) => Some(PropTarget::Type(object_type)),
                        (None, None) => None,
                    };
                    let pid = parse_u32(&e, "PropId")?.and_then(|v| u8::try_from(v).ok());
                    if let (Some(target), Some(pid), Some((pdt, size))) = (
                        target,
                        pid,
                        attr(&e, "PropType").and_then(|t| pdt_by_name(&t)),
                    ) && !declared_descs
                        .iter()
                        .any(|(t, p, _, _)| *t == target && *p == pid)
                    {
                        declared_descs.push((target, pid, pdt, size));
                    }
                }
                b"LdCtrlInvokeFunctionProp" if in_app => {
                    let object = parse_u32(&e, "ObjIdx")?.and_then(|v| u8::try_from(v).ok());
                    let object_type = parse_u32(&e, "ObjType")?.and_then(|v| u16::try_from(v).ok());
                    let pid = parse_u32(&e, "PropId")?.and_then(|v| u8::try_from(v).ok());
                    match (object, object_type, pid) {
                        (Some(object), _, Some(pid))
                            if !function_props.contains(&(object, pid)) =>
                        {
                            function_props.push((object, pid));
                        }
                        (None, Some(object_type), Some(pid))
                            if !typed_function_props.contains(&(object_type, pid)) =>
                        {
                            typed_function_props.push((object_type, pid));
                        }
                        _ => {}
                    }
                }
                b"LdCtrlCompareMem" if in_app => {
                    let address = parse_u32(&e, "Address")?.and_then(|v| u16::try_from(v).ok());
                    let value = attr(&e, "InlineData").and_then(|hex| decode_hex(&hex));
                    if let (Some(address), Some(mut value)) = (address, value) {
                        // `Size` octets are compared; `InlineData` may carry
                        // more (Zennio pads it to 11 octets with zeros).
                        if let Some(size) = parse_u32(&e, "Size")?
                            && let Ok(size) = usize::try_from(size)
                            && size < value.len()
                        {
                            value.truncate(size);
                        }
                        if !compare_mems.iter().any(|(a, _)| *a == address) {
                            compare_mems.push((address, value));
                        }
                    }
                }
                b"LdCtrlCompareProp" => {
                    // The object-0 PID 78 preflight carries the device's
                    // hardware-type marker as inline hex. Capture it so the
                    // simulated device can seed PID 78 with the value its own
                    // vendor procedure expects (see `ProductData`).
                    let pid = parse_u32(&e, "PropId")?.unwrap_or(0);
                    if in_app {
                        property_ops = true;
                        record_object_type(&e, &mut object_types)?;
                    }
                    let obj_idx = parse_u32(&e, "ObjIdx")?;
                    let obj_type = parse_u32(&e, "ObjType")?;
                    // The device object, by index or by type 0.
                    let device_object =
                        obj_idx == Some(0) || (obj_idx.is_none() && obj_type == Some(0));
                    let mut value = attr(&e, "InlineData").and_then(|hex| decode_hex(&hex));
                    let start = parse_u32(&e, "StartElement")?
                        .and_then(|v| u16::try_from(v).ok())
                        .unwrap_or(1)
                        .max(1);
                    let declared_count =
                        parse_u32(&e, "Count")?.and_then(|v| u16::try_from(v).ok());
                    let count = declared_count.unwrap_or(1).max(1);
                    // `InlineData` longer than the `Count` elements it can
                    // hold: the last `Count` octets are the value, the octets
                    // in front of them padding. The Gira IR-Gateway
                    // (`M-0008_A-E000-10`) compares PID 78 with `Count="6"`
                    // and seven octets `00000000200003`; its own parameter
                    // bound to that property (`target_hw_id`, BinaryValue
                    // `AAAAIAAD`) is `00 00 00 20 00 03`. ETS refused both all
                    // seven octets and the first six (ETS sweep, 2026-11-06).
                    if let (Some(v), Some(n)) = (value.as_mut(), declared_count.map(usize::from))
                        && n > 0
                        && v.len() > n
                        && !v.len().is_multiple_of(n)
                    {
                        v.drain(..v.len() - n);
                    }
                    if in_app
                        && !device_object
                        && let (Some(value), Ok(pid)) = (value.clone(), u8::try_from(pid))
                    {
                        match (obj_idx.and_then(|o| u8::try_from(o).ok()), obj_type) {
                            (Some(object), _) => {
                                object_cands.push((
                                    (object, pid, start, count),
                                    value,
                                    chooses.guards(),
                                ));
                            }
                            (None, Some(object_type)) => {
                                if let Ok(object_type) = u16::try_from(object_type) {
                                    if !typed_props
                                        .iter()
                                        .any(|t| t.object_type == object_type && t.pid == pid)
                                    {
                                        typed_props.push(crate::prod::TypedProperty {
                                            object_type,
                                            pid,
                                            compare: None,
                                            written: false,
                                            len: 0,
                                            count: 1,
                                            pdt: None,
                                            compare_elements: 1,
                                        });
                                    }
                                    typed_cands.push((
                                        (object_type, pid, start, count),
                                        value,
                                        chooses.guards(),
                                    ));
                                }
                            }
                            (None, None) => {}
                        }
                    }
                    if in_app
                        && device_object
                        && let Some(value) = value
                    {
                        if pid == 78 {
                            marker_cands.push(((), value.clone(), chooses.guards()));
                        }
                        if let Ok(pid) = u8::try_from(pid) {
                            device_cands.push((pid, value, chooses.guards()));
                        }
                    }
                }
                _ => {}
            },
            Event::Text(t) if in_data => {
                data_text.push_str(&String::from_utf8_lossy(t.as_ref()));
            }
            Event::End(e) => match e.name().as_ref() {
                b"Data" if in_data => {
                    in_data = false;
                    if let Some(seg) = cur_segment.as_mut() {
                        let trimmed: String =
                            data_text.chars().filter(|c| !c.is_whitespace()).collect();
                        seg.data = base64::engine::general_purpose::STANDARD.decode(trimmed)?;
                    }
                }
                b"RelativeSegment" => {
                    if let Some(seg) = cur_segment.take() {
                        segments.push(seg);
                    }
                }
                b"LoadProcedure" => {
                    if let Some(p) = cur_proc.take() {
                        load_procedures.push(p);
                    }
                }
                b"ApplicationProgram" => in_app = false,
                b"ModuleDef" => cur_module_def = None,
                b"Module" => {
                    if let Some(instance) = cur_module.take() {
                        module_instances.push(instance);
                    }
                }
                b"ParameterType" => cur_ptype = None,
                b"Parameter" => cur_param_type = None,
                b"Union" => cur_union_bits = None,
                b"choose" if in_app => chooses.close_choose(),
                b"when" if in_app => chooses.close_when(),
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }

    if app_id.is_empty() {
        return Ok(None);
    }

    // A compare under a `<choose>` holds only on the hardware that branch
    // describes; the simulated device is the hardware the vendor defaults
    // select (issue #400).
    let hardware_type_marker = defaults.pick(&marker_cands).pop().map(|((), v)| v);
    let device_compare_props = defaults.pick(&device_cands);
    // A program-id compare (PID 13, `mfr:2 app:2 version:1`) with a mask
    // compares only the application number (`Mask="0000FFFF00"`), so its
    // InlineData leaves the manufacturer at 0000. ETS checks the manufacturer
    // apart from the compare and refused "a device of another manufacturer"
    // (ABB A-A001, 2026-10-28): a device of that hardware holds its own, the
    // application id's `M-xxxx`, and the version.
    let manufacturer = program_manufacturer(&app_id);
    let object_compare_props: Vec<(u8, u8, Vec<u8>, u16)> =
        merge_element_compares(defaults.pick(&object_cands))
            .into_iter()
            .map(|((o, p), mut v, elements)| {
                if p == 13 && v.len() == 5 && v[..2] == [0, 0] {
                    if let Some(m) = manufacturer {
                        v[..2].copy_from_slice(&m.to_be_bytes());
                    }
                    if v[4] == 0 {
                        v[4] = u8::try_from(app_version).unwrap_or(0);
                    }
                }
                (o, p, v, elements)
            })
            .collect();
    for ((object_type, pid), value, elements) in merge_element_compares(defaults.pick(&typed_cands))
    {
        if let Some(t) = typed_props
            .iter_mut()
            .find(|t| t.object_type == object_type && t.pid == pid)
        {
            t.compare = Some(value);
            t.compare_elements = elements;
        }
    }

    // The size of every written property, and the data type of the
    // parameters it holds (issue #841).
    let mut written_prop_pdts: Vec<(u8, u8, u8)> = Vec::new();
    // Each module instance's writes, at the object and element its arguments
    // name (`BaseObjIdx`, `BaseStartElement`): the Schneider STXF121
    // (`M-0009_A-E0EE-10`) writes `ObjIdx="0" PropId="208" Count="164"
    // BaseObjIdx="…_MD-1_A-1"` in a module instantiated with base objects 6
    // to 9; ETS described object 6's PID 208 and stopped when it was absent
    // (ETS sweep, 2026-11-06).
    for w in &module_writes {
        for (def, args) in &module_instances {
            if *def != w.def {
                continue;
            }
            let arg = |name: &Option<String>| -> u32 {
                name.as_ref()
                    .and_then(|n| args.iter().find(|(a, _)| a == n))
                    .map_or(0, |&(_, v)| v)
            };
            let Ok(object) = u8::try_from(u32::from(w.object) + arg(&w.base_object)) else {
                continue;
            };
            let target = PropTarget::Index(object);
            let start = w.start + usize::try_from(arg(&w.base_start)).unwrap_or(0);
            let end = start + usize::from(w.count.max(1)) - 1;
            match write_ends
                .iter_mut()
                .find(|(t, p, _)| *t == target && *p == w.pid)
            {
                Some(entry) => entry.2 = entry.2.max(end),
                None => write_ends.push((target, w.pid, end)),
            }
            if !written_raw
                .iter()
                .any(|&(t, p, _, _)| t == target && p == w.pid)
            {
                written_raw.push((target, w.pid, w.inline_len, w.count));
            }
        }
    }
    for &(target, pid, inline_len, count) in &written_raw {
        let mut len = inline_len
            .or_else(|| declared_extent(&prop_locs, &type_bits, target, pid))
            .unwrap_or(usize::from(count.max(1)));
        let mut count = count;
        let mut pdt = declared_pdt(&prop_locs, &type_bits, target, pid, len, count);
        // A property the procedure declares (`LdCtrlDeclarePropDesc`) is an
        // array of elements of the declared type, as many as the writes
        // reach and the stored parameters fill (bussard issue #422: the Gira
        // Eco declares type 40960's PID 69 PDT_GENERIC_04 and writes elements
        // 1-25 and 176-200; ETS read 14 elements of it and the sim, holding
        // one element of 794 octets, refused).
        if let Some(&(_, _, declared, size)) = declared_descs
            .iter()
            .find(|(t, p, _, _)| *t == target && *p == pid)
        {
            let reached = write_ends
                .iter()
                .find(|(t, p, _)| *t == target && *p == pid)
                .map_or(usize::from(count.max(1)), |&(_, _, end)| end);
            let elements = len.div_ceil(size).max(reached);
            if let Ok(n) = u16::try_from(elements) {
                len = elements * size;
                count = n;
                pdt = Some(declared);
            }
        }
        match target {
            PropTarget::Index(object) => {
                written_props.push((object, pid, len, count));
                if let Some(pdt) = pdt {
                    written_prop_pdts.push((object, pid, pdt));
                }
            }
            PropTarget::Type(object_type) => {
                if let Some(t) = typed_props
                    .iter_mut()
                    .find(|t| t.object_type == object_type && t.pid == pid)
                {
                    t.len = len;
                    t.count = count;
                    t.pdt = pdt;
                }
            }
        }
    }

    // Build the loadable-object list. Table objects (LSM 1/2/3) are declared by
    // the presence of AddressTable/AssociationTable/ComObjectTable and carry no
    // image (the tool builds those). The application segment (LSM 4) carries the
    // decoded code image.
    let mut objects: Vec<LoadableObject> = Vec::new();
    if has_address_table {
        objects.push(LoadableObject {
            lsm_index: LSM_ADDRESS_TABLE,
            name: "address table".into(),
            max_size: None,
            image: Vec::new(),
        });
    }
    if has_association_table {
        objects.push(LoadableObject {
            lsm_index: LSM_ASSOCIATION_TABLE,
            name: "association table".into(),
            max_size: None,
            image: Vec::new(),
        });
    }
    if has_comobject_table {
        objects.push(LoadableObject {
            lsm_index: LSM_COMOBJECT_TABLE,
            name: "com-object table".into(),
            max_size: None,
            image: Vec::new(),
        });
    }
    for seg in &segments {
        objects.push(LoadableObject {
            lsm_index: seg.lsm_index,
            name: format!("application segment (LSM {})", seg.lsm_index),
            max_size: Some(seg.size),
            image: seg.data.clone(),
        });
    }
    objects.sort_by_key(|o| o.lsm_index);
    objects.dedup_by_key(|o| o.lsm_index);

    Ok(Some(ProductData {
        application_id: app_id,
        application_number: app_number,
        application_version: app_version,
        mask_version,
        objects,
        load_procedures,
        segments,
        hardware_type_marker,
        device_compare_props,
        written_props,
        written_prop_pdts,
        task_segment_lsms: completes_loads.then_some(task_segment_lsms),
        compare_mems,
        function_props,
        typed_lsm_types,
        typed_function_props,
        object_compare_props,
        typed_props,
        object_types,
        property_only: property_ops && !other_ops,
        security_capacity,
    }))
}

/// The interface object a property step or a parameter's `<Property>`
/// addresses: by index (`ObjIdx`, `ObjectIndex`) or by type (`ObjType`,
/// `ObjectType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropTarget {
    Index(u8),
    Type(u16),
}

/// The size of a parameter stored in a property: its parameter type's, or a
/// union's `SizeInBit`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocationSize {
    Type(String),
    Bits(u32),
}

/// A parameter (or union) the product stores in a property
/// (`<Property ObjectType="50001" PropertyId="211" Offset="0" BitOffset="0"/>`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PropLocation {
    target: PropTarget,
    pid: u8,
    /// Octets from the start of the property value.
    offset: u32,
    bit_offset: u32,
    size: LocationSize,
}

/// A parameter type's size, and the property data type a device describes a
/// property holding one value of it with, where the type has a scalar one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TypeSize {
    bits: u32,
    pdt: Option<u8>,
}

/// The size a parameter type's child element declares: `SizeInBit`
/// (`TypeNumber`, `TypeRestriction`, `TypeText`, ...), 32 for `TypeIPAddress`,
/// and the encoding's width for `TypeFloat`. `None` for any other element.
/// An 8, 16 or 32-bit `TypeNumber` is `PDT_(UNSIGNED_)CHAR`, `_INT` or
/// `_LONG`, an IP address `PDT_UNSIGNED_LONG` (Resources 03.05.01, the PDT
/// codes of 03.07.03).
fn type_size(e: &quick_xml::events::BytesStart<'_>) -> Result<Option<TypeSize>, ProdError> {
    let name = e.name();
    let bits = match parse_u32(e, "SizeInBit")? {
        Some(bits) => bits,
        None => match name.as_ref() {
            b"TypeIPAddress" => 32,
            b"TypeFloat" => match attr(e, "Encoding").as_deref() {
                Some("DPT 9") => 16,
                Some("IEEE-754 Single") => 32,
                Some("IEEE-754 Double") => 64,
                _ => return Ok(None),
            },
            _ => return Ok(None),
        },
    };
    let pdt = match (name.as_ref(), attr(e, "Type").as_deref(), bits) {
        (b"TypeNumber", Some("unsignedInt"), 8) => Some(0x02),
        (b"TypeNumber", Some("unsignedInt"), 16) => Some(0x04),
        (b"TypeNumber", Some("unsignedInt"), 32) => Some(0x09),
        (b"TypeNumber", Some("signedInt"), 8) => Some(0x01),
        (b"TypeNumber", Some("signedInt"), 16) => Some(0x03),
        (b"TypeNumber", Some("signedInt"), 32) => Some(0x08),
        (b"TypeIPAddress", _, 32) => Some(0x09),
        _ => None,
    };
    Ok(Some(TypeSize { bits, pdt }))
}

/// The scalar PDT of property `pid` of `target` when every parameter the
/// product stores there fills one whole element of `len / count` octets with
/// a type that has one, the same for all; else `None` (the generic PDT of
/// the element size describes it).
fn declared_pdt(
    locs: &[PropLocation],
    type_bits: &std::collections::HashMap<String, TypeSize>,
    target: PropTarget,
    pid: u8,
    len: usize,
    count: u16,
) -> Option<u8> {
    let elem = len / usize::from(count.max(1));
    let mut pdt = None;
    for l in locs.iter().filter(|l| l.target == target && l.pid == pid) {
        let LocationSize::Type(id) = &l.size else {
            return None;
        };
        let size = type_bits.get(id)?;
        let aligned = l.bit_offset == 0
            && usize::try_from(l.offset).is_ok_and(|o| elem > 0 && o % elem == 0)
            && usize::try_from(size.bits).is_ok_and(|b| b == elem * 8);
        if !aligned || size.pdt.is_none() || (pdt.is_some() && pdt != size.pdt) {
            return None;
        }
        pdt = size.pdt;
    }
    pdt
}

/// The octets of property `pid` of `target` the product's parameters cover:
/// the furthest end (`Offset` + the bit offset and size, rounded up to whole
/// octets) of a parameter stored there, or `None` when none is, or none of
/// their sizes is known.
fn declared_extent(
    locs: &[PropLocation],
    type_bits: &std::collections::HashMap<String, TypeSize>,
    target: PropTarget,
    pid: u8,
) -> Option<usize> {
    locs.iter()
        .filter(|l| l.target == target && l.pid == pid)
        .filter_map(|l| {
            let bits = match &l.size {
                LocationSize::Type(id) => type_bits.get(id)?.bits,
                LocationSize::Bits(bits) => *bits,
            };
            let end = u64::from(l.offset) + (u64::from(l.bit_offset) + u64::from(bits)).div_ceil(8);
            usize::try_from(end).ok()
        })
        .filter(|&n| n > 0)
        .max()
}

/// The manufacturer a device reports in its program id (PID 13 of the
/// application object): the original manufacturer of an OEM application
/// (`M-0007_A-...-O0002` is ABB's program sold by Busch-Jaeger, and the device
/// reports 0002), else the application id's `M-xxxx`. ETS copies the reported
/// value into the TaskSegment records, so a sim reporting 0007 made 40
/// Busch-Jaeger captures differ from what the house device 1.1.44 gives
/// (bussard #640, 2026-11-03).
pub fn program_manufacturer(application_id: &str) -> Option<u16> {
    let oem = application_id
        .rsplit_once("-O")
        .map(|(_, tail)| tail)
        .filter(|t| t.len() == 4 && t.chars().all(|c| c.is_ascii_hexdigit()));
    let hex = match oem {
        Some(t) => t,
        None => application_id.strip_prefix("M-")?.get(..4)?,
    };
    u16::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_program_manufacturer_prefers_the_oem_original() {
        assert_eq!(
            super::program_manufacturer("M-0007_A-A087-11-C77A-O0002"),
            Some(0x0002)
        );
        assert_eq!(
            super::program_manufacturer("M-0002_A-A001-13-63C2"),
            Some(0x0002)
        );
        assert_eq!(
            super::program_manufacturer("M-0071_A-4A11-13-48E1"),
            Some(0x0071)
        );
    }

    use super::*;

    #[test]
    fn test_decode_hex_roundtrips_and_rejects_malformed() {
        assert_eq!(decode_hex("00FA0b"), Some(vec![0x00, 0xFA, 0x0B]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
        // Odd length, non-hex ASCII: refused, not partially decoded.
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn test_decode_hex_non_ascii_does_not_panic() {
        // `&s[i..i + 2]` on a 2-byte character used to panic on a char boundary
        // ("ä" is one char, two bytes). Every byte-length-even non-ASCII string
        // must simply be refused.
        for s in ["ä", "ää", "0ä", "ä0", "€€", "\u{10348}"] {
            assert_eq!(decode_hex(s), None, "{s:?} must be refused, not panic");
        }
    }

    /// A System 7 application program with a CompareMem preflight and a
    /// TaskSegment on LSM 5 only (the Zennio / IRSC 0701 shapes).
    const SYS7_APP: &str = r#"<KNX><ManufacturerData><Manufacturer RefId="M-0071"><ApplicationPrograms>
      <ApplicationProgram Id="M-0071_A-1231-22-E232" ApplicationNumber="4657" ApplicationVersion="34"
          ProgramType="ApplicationProgram" MaskVersion="MV-0701">
        <Static><LoadProcedures><LoadProcedure>
          <LdCtrlCompareMem Address="46608" Size="3" InlineData="5212300000000000000000" />
          <LdCtrlLoad LsmIdx="1" />
          <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="512" />
          <LdCtrlLoadCompleted LsmIdx="1" />
          <LdCtrlTaskSegment LsmIdx="5" Address="17408" />
        </LoadProcedure></LoadProcedures></Static>
      </ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;

    #[test]
    fn test_parse_application_program_reads_task_segments_and_compare_mem() -> Result<(), ProdError>
    {
        let pd =
            parse_application_program(SYS7_APP, None)?.ok_or(ProdError::NoApplicationProgram)?;
        assert_eq!(pd.task_segment_lsms, Some(vec![5]));
        // Size octets of the padded InlineData.
        assert_eq!(pd.compare_mems, vec![(0xB610, vec![0x52, 0x12, 0x30])]);
        Ok(())
    }

    #[test]
    fn test_read_knxprod_bytes_pairs_the_pei_program() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let app = r#"<KNX><ApplicationProgram Id="M-0002_A-488A-11-4A38" ProgramType="ApplicationProgram" MaskVersion="MV-07B0">
          <Static><LoadProcedures><LoadProcedure MergeId="2">
            <LdCtrlWriteProp ObjIdx="4" PropId="16" InlineData="0A" />
          </LoadProcedure></LoadProcedures></Static></ApplicationProgram></KNX>"#;
        let pei = r#"<KNX><ApplicationProgram Id="M-0002_A-488A-21-D09B" ProgramType="PeiProgram" MaskVersion="MV-07B0">
          <Static><Code><RelativeSegment Id="RS-05" Offset="0" Size="34" LoadStateMachine="5" /></Code>
          <LoadProcedures><LoadProcedure MergeId="3">
            <LdCtrlWriteProp ObjIdx="5" PropId="16" InlineData="0A" />
            <LdCtrlWriteProp ObjIdx="5" PropId="13" InlineData="0002488A20" />
          </LoadProcedure></LoadProcedures></Static></ApplicationProgram></KNX>"#;
        let hardware = r#"<KNX><Hardware><Hardware2Programs>
          <Hardware2Program Id="HP-1">
            <ApplicationProgramRef RefId="M-0002_A-488A-11-4A38" />
            <ApplicationProgramRef RefId="M-0002_A-488A-21-D09B" />
          </Hardware2Program></Hardware2Programs></Hardware></KNX>"#;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, body) in [
                ("M-0002/M-0002_A-488A-11-4A38.xml", app),
                ("M-0002/M-0002_A-488A-21-D09B.xml", pei),
                ("M-0002/Hardware.xml", hardware),
            ] {
                zip.start_file(name, options)?;
                zip.write_all(body.as_bytes())?;
            }
            zip.finish()?;
        }
        let pd = read_knxprod_bytes(buf.get_ref(), Some("M-0002_A-488A-11-4A38"))?;
        assert_eq!(pd.application_id, "M-0002_A-488A-11-4A38");
        assert!(pd.written_props.contains(&(4, 16, 1, 1)));
        assert!(pd.written_props.contains(&(5, 16, 1, 1)));
        assert!(pd.written_props.contains(&(5, 13, 5, 1)));
        assert!(pd.object(5).is_some(), "the PEI program's object 5");
        Ok(())
    }

    #[test]
    fn test_read_knxprod_da_tp() -> Result<(), ProdError> {
        let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
            eprintln!("SKIP: DA.tp fixture not present");
            return Ok(());
        };
        let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
        assert_eq!(pd.application_id, "M-00FA_A-2500-10-51CB");
        assert_eq!(pd.application_number, 9472);
        assert_eq!(pd.application_version, 16);
        assert_eq!(pd.mask_version, "MV-07B0");
        // Four loadable objects: address(1), association(2), comobject(3), app(4).
        let indices: Vec<u8> = pd.objects.iter().map(|o| o.lsm_index).collect();
        assert_eq!(indices, vec![1, 2, 3, 4]);
        // The application segment is 256 bytes of image.
        let app = pd.segment(4).expect("app segment");
        assert_eq!(app.size, 256);
        assert_eq!(app.data.len(), 256);
        Ok(())
    }

    #[test]
    fn test_read_knxprod_load_procedures() -> Result<(), ProdError> {
        let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
            eprintln!("SKIP: DA.tp fixture not present");
            return Ok(());
        };
        let pd = read_knxprod_bytes(&fixture, None)?;
        // The DA.tp product declares a RelSegment+MasterReset procedure and a
        // WriteRelMem procedure for object 4.
        let has_rel = pd.load_procedures.iter().any(|p| {
            p.steps.iter().any(|s| {
                matches!(
                    s,
                    LdCtrl::RelSegment {
                        lsm_index: 4,
                        size: 256,
                        ..
                    }
                )
            })
        });
        let has_master_reset = pd.load_procedures.iter().any(|p| {
            p.steps
                .iter()
                .any(|s| matches!(s, LdCtrl::MasterReset { erase_code: 4, .. }))
        });
        let has_write = pd.load_procedures.iter().any(|p| {
            p.steps.iter().any(|s| {
                matches!(
                    s,
                    LdCtrl::WriteRelMem {
                        obj_index: 4,
                        size: 256,
                        ..
                    }
                )
            })
        });
        assert!(has_rel, "expected RelSegment for obj4 size 256");
        assert!(has_master_reset, "expected MasterReset erase code 4");
        assert!(has_write, "expected WriteRelMem for obj4 size 256");
        Ok(())
    }

    /// The MDT `M-0083_A-0054-14-0D63` shape (issue #400): a hardware-revision
    /// parameter selects which object-0 PID 19 value the procedure compares.
    fn branch_app(revision_default: &str, ref_value: &str) -> String {
        format!(
            r#"<KNX><ApplicationProgram Id="M-0083_A-1" MaskVersion="MV-0705"><Static>
          <Parameters>
            <Parameter Id="M-0083_A-1_P-833" Name="HW_Revision" Value="{revision_default}" />
          </Parameters>
          <ParameterRefs><ParameterRef Id="M-0083_A-1_P-833_R-33" RefId="M-0083_A-1_P-833"{ref_value} /></ParameterRefs>
          <LoadProcedures><LoadProcedure>
            <LdCtrlConnect />
            <LdCtrlCompareProp InlineData="00000000014A00000000" ObjIdx="0" PropId="78" />
            <choose ParamRefId="M-0083_A-1_P-833_R-33">
              <when test="0">
                <LdCtrlCompareProp InlineData="00000000" ObjIdx="0" PropId="19" />
                <LdCtrlCompareProp InlineData="AA" ObjIdx="3" PropId="13" />
              </when>
              <when test="1">
                <LdCtrlCompareProp InlineData="01000000" ObjIdx="0" PropId="19" />
                <LdCtrlCompareProp InlineData="BB" ObjIdx="3" PropId="13" />
              </when>
            </choose>
            <LdCtrlUnload LsmIdx="1" />
          </LoadProcedure></LoadProcedures></Static>
          <Dynamic><choose ParamRefId="M-0083_A-1_P-833_R-33"><when test="0" /></choose></Dynamic>
          </ApplicationProgram></KNX>"#
        )
    }

    #[test]
    fn test_parse_application_program_seeds_the_default_branch_compare()
    -> Result<(), Box<dyn std::error::Error>> {
        // Default "from R2.0" (1): the device reports 01000000, not the first
        // compare the file lists.
        let pd = parse_application_program(&branch_app("1", ""), None)?.ok_or("parsed")?;
        assert_eq!(
            pd.device_compare_props,
            vec![
                (78, vec![0, 0, 0, 0, 0x01, 0x4A, 0, 0, 0, 0]),
                (19, vec![0x01, 0x00, 0x00, 0x00])
            ]
        );
        assert_eq!(pd.object_compare_props, vec![(3, 13, vec![0xBB], 1)]);
        assert_eq!(
            pd.hardware_type_marker,
            Some(vec![0, 0, 0, 0, 0x01, 0x4A, 0, 0, 0, 0])
        );
        // Default "to R1.9" (0): the other branch.
        let pd = parse_application_program(&branch_app("0", ""), None)?.ok_or("parsed")?;
        assert_eq!(pd.device_compare_props[1], (19, vec![0x00; 4]));
        assert_eq!(pd.object_compare_props, vec![(3, 13, vec![0xAA], 1)]);
        // A ParameterRef value overrides its Parameter's.
        let pd =
            parse_application_program(&branch_app("0", r#" Value="1""#), None)?.ok_or("parsed")?;
        assert_eq!(
            pd.device_compare_props[1],
            (19, vec![0x01, 0x00, 0x00, 0x00])
        );
        Ok(())
    }

    #[test]
    fn test_parse_application_program_without_a_default_takes_the_first_compare()
    -> Result<(), Box<dyn std::error::Error>> {
        // No ParameterRef declared: no branch is known to hold, so the first
        // compare stays (the behaviour before issue #400).
        let xml = branch_app("1", "").replace(
            r#"<ParameterRefs><ParameterRef Id="M-0083_A-1_P-833_R-33" RefId="M-0083_A-1_P-833" /></ParameterRefs>"#,
            "",
        );
        let pd = parse_application_program(&xml, None)?.ok_or("parsed")?;
        assert_eq!(pd.device_compare_props[1], (19, vec![0x00; 4]));
        Ok(())
    }

    #[test]
    fn test_reader_records_property_procedures() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ManufacturerData><Manufacturer RefId="M-0004"><ApplicationPrograms>
          <ApplicationProgram Id="M-0004_A-1" ApplicationNumber="22" ApplicationVersion="16" MaskVersion="MV-0021">
           <Static><LoadProcedures><LoadProcedure>
            <LdCtrlCompareProp InlineData="0004" ObjType="0" PropId="12" />
            <LdCtrlCompareProp InlineData="0000A04200" Mask="0000FFFF00" ObjIdx="3" PropId="13" />
            <LdCtrlWriteProp ObjType="11" PropId="205" Count="8" Verify="true" />
            <LdCtrlWriteProp ObjType="50001" PropId="211" Verify="false" />
           </LoadProcedure></LoadProcedures></Static>
          </ApplicationProgram>
         </ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        assert!(pd.property_only);
        assert_eq!(pd.device_compare_props, vec![(12, vec![0x00, 0x04])]);
        assert_eq!(
            pd.object_compare_props,
            // Masked compare: the manufacturer and version filled in.
            vec![(3, 13, vec![0x00, 0x04, 0xA0, 0x42, 0x10], 1)]
        );
        assert_eq!(pd.typed_props.len(), 2);
        assert!(pd.typed_props.iter().all(|t| t.written));
        assert_eq!(pd.typed_props[0].object_type, 11);
        assert_eq!(pd.typed_props[1].object_type, 50001);
        Ok(())
    }

    /// Bussard issue #422: compares of single elements of one property merge
    /// into its element array. The steps are those of the Siemens
    /// `M-0001_A-9A01-03-E6C8` (object 4 PID 246, elements 1, 2, 3, 5, 6) and
    /// `M-0001_A-7205-03-6FCB` (type 50100 PID 246, elements 5-6 then 1-4).
    #[test]
    fn test_parse_application_program_merges_element_compares()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ApplicationProgram Id="M-0001_A-9A01-03-E6C8" ApplicationNumber="39425" ApplicationVersion="3" MaskVersion="MV-07B0">
           <Static><LoadProcedures><LoadProcedure>
            <LdCtrlConnect AppliesTo="all" />
            <LdCtrlCompareProp ObjIdx="4" PropId="246" InlineData="05" AppliesTo="all" />
            <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="2" InlineData="93" AppliesTo="all" />
            <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="3" InlineData="04" AppliesTo="all" />
            <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="5" InlineData="00" AppliesTo="all" />
            <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="6" InlineData="51" AppliesTo="all" />
            <LdCtrlCompareProp ObjIdx="4" PropId="202" InlineData="01" AppliesTo="all" />
            <LdCtrlCompareProp InlineData="0003" ObjType="50100" PropId="246" StartElement="5" Count="2" />
            <LdCtrlCompareProp InlineData="04450001" ObjType="50100" PropId="246" Count="4" />
           </LoadProcedure></LoadProcedures></Static>
          </ApplicationProgram></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        assert_eq!(
            pd.object_compare_props,
            vec![
                (4, 246, vec![0x05, 0x93, 0x04, 0x00, 0x00, 0x51], 6),
                (4, 202, vec![0x01], 1)
            ]
        );
        let typed = pd
            .typed_props
            .iter()
            .find(|t| t.object_type == 50100 && t.pid == 246)
            .ok_or("type 50100 PID 246")?;
        assert_eq!(
            typed.compare.as_deref(),
            Some(&[0x04, 0x45, 0x00, 0x01, 0x00, 0x03][..])
        );
        assert_eq!(typed.compare_elements, 6);
        Ok(())
    }

    /// Bussard issue #422: the function properties a procedure calls.
    #[test]
    fn test_parse_application_program_records_function_props()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ApplicationProgram Id="M-0006_A-E01D-01-9030-O0009" ApplicationNumber="57373" ApplicationVersion="1" MaskVersion="MV-0701">
           <Static><LoadProcedures><LoadProcedure>
            <LdCtrlConnect />
            <LdCtrlWriteProp ObjIdx="5" PropId="51" Verify="false" InlineData="01000000000000000000" />
            <LdCtrlInvokeFunctionProp ObjIdx="5" PropId="52" InlineData="04" AppliesTo="full,grp" />
            <LdCtrlInvokeFunctionProp ObjIdx="5" PropId="52" InlineData="10" AppliesTo="full,par" />
            <LdCtrlUnload LsmIdx="1" />
           </LoadProcedure></LoadProcedures></Static>
          </ApplicationProgram></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        assert_eq!(pd.function_props, vec![(5, 52)]);
        Ok(())
    }

    /// Bussard issue #422: `InlineData` octets in front of the last `Count`
    /// are padding (the Gira IR-Gateway `M-0008_A-E000-10-89B0-O0077`, whose
    /// parameter `target_hw_id` holds `00 00 00 20 00 03`).
    #[test]
    fn test_parse_application_program_truncates_compare_padding()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ApplicationProgram Id="M-0008_A-E000-10-89B0-O0077" ApplicationNumber="57344" ApplicationVersion="16" MaskVersion="MV-07B0">
           <Static><LoadProcedures><LoadProcedure MergeId="1">
            <LdCtrlCompareProp AppliesTo="all" InlineData="0008" ObjType="0" PropId="12" />
            <LdCtrlCompareProp AppliesTo="all" InlineData="00000000200003" ObjType="0" PropId="78" Count="6" />
            <LdCtrlCompareProp ObjIdx="0" PropId="72" InlineData="01000001000000000000" StartElement="1" Count="1" />
           </LoadProcedure></LoadProcedures></Static>
          </ApplicationProgram></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        assert_eq!(
            pd.hardware_type_marker,
            Some(vec![0x00, 0x00, 0x00, 0x20, 0x00, 0x03])
        );
        assert!(
            pd.device_compare_props
                .contains(&(78, vec![0x00, 0x00, 0x00, 0x20, 0x00, 0x03]))
        );
        assert!(pd.device_compare_props.contains(&(12, vec![0x00, 0x08])));
        // Count 1 of a 10-octet value is one element: unchanged.
        assert!(
            pd.device_compare_props
                .contains(&(72, vec![1, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        );
        Ok(())
    }

    /// Bussard issue #422: a declared property (`LdCtrlDeclarePropDesc`) is
    /// an array of its declared type as far as the writes reach.
    #[test]
    fn test_parse_application_program_sizes_declared_arrays()
    -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ApplicationProgram Id="M-0008_A-C02A-21-B6D8-O007C" ApplicationNumber="49194" ApplicationVersion="33" MaskVersion="MV-07B0">
           <Static><LoadProcedures><LoadProcedure MergeId="6">
            <LdCtrlDeclarePropDesc ObjType="40960" PropId="69" PropType="PDT_GENERIC_04" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
            <LdCtrlWriteProp AppliesTo="all" ObjType="40960" PropId="69" Count="25" Verify="true" />
            <LdCtrlWriteProp AppliesTo="all" ObjType="40960" PropId="69" StartElement="176" Count="25" Verify="true" />
            <LdCtrlDeclarePropDesc ObjIdx="6" PropId="53" PropType="PDT_UNSIGNED_CHAR" MaxElements="14" ReadAccess="0" WriteAccess="0" Writable="true" />
            <LdCtrlWriteProp ObjIdx="6" PropId="53" Count="14" Verify="false" InlineData="00000000000000000000" />
           </LoadProcedure></LoadProcedures></Static>
          </ApplicationProgram></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        let t = pd
            .typed_props
            .iter()
            .find(|t| t.object_type == 40960 && t.pid == 69)
            .ok_or("PID 69")?;
        assert_eq!((t.len, t.count, t.pdt), (800, 200, Some(0x14)));
        // The Siemens 0701 shape: 14 one-octet elements, not ten octets.
        assert!(pd.written_props.contains(&(6, 53, 14, 14)));
        Ok(())
    }

    /// Bussard issue #841: a property write without `InlineData` is as long
    /// as the parameters the product stores in the property, else one octet
    /// per element.
    #[test]
    fn test_reader_sizes_written_props_from_parameters() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ManufacturerData><Manufacturer RefId="M-00A6"><ApplicationPrograms>
          <ApplicationProgram Id="M-00A6_A-1" ApplicationNumber="20" ApplicationVersion="16" MaskVersion="MV-0021">
           <Static>
            <ParameterTypes>
             <ParameterType Id="PT-U8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="5" maxInclusive="50" /></ParameterType>
             <ParameterType Id="PT-IP"><TypeIPAddress AddressType="IPv4" /></ParameterType>
             <ParameterType Id="PT-B"><TypeRestriction Base="Value" SizeInBit="1"><Enumeration Text="a" Value="0" Id="E-0" /></TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
             <Parameter Id="P-1" Name="a" ParameterType="PT-U8" Value="50"><Property ObjectType="50001" PropertyId="211" Offset="0" BitOffset="0" /></Parameter>
             <Parameter Id="P-2" Name="b" ParameterType="PT-IP" Value="0.0.0.0"><Property ObjectType="11" PropertyId="205" Offset="0" BitOffset="0" /></Parameter>
             <Parameter Id="P-3" Name="c" ParameterType="PT-IP" Value="0.0.0.0"><Property ObjectType="11" PropertyId="205" Offset="28" BitOffset="0" /></Parameter>
             <Parameter Id="P-4" Name="d" ParameterType="PT-B" Value="0"><Property ObjectIndex="7" PropertyId="161" Offset="2" BitOffset="3" /></Parameter>
             <Union SizeInBit="16"><Property ObjectIndex="7" PropertyId="162" Offset="0" BitOffset="0" /><Parameter Id="P-5" Name="e" ParameterType="PT-U8" Offset="0" BitOffset="0" Value="0" /></Union>
             <Parameter Id="P-6" Name="f" ParameterType="PT-U8" Value="1" />
            </Parameters>
            <LoadProcedures><LoadProcedure>
             <LdCtrlWriteProp ObjType="11" PropId="205" Count="8" Verify="true" />
             <LdCtrlWriteProp ObjType="50001" PropId="211" Verify="false" />
             <LdCtrlWriteProp ObjType="50002" PropId="212" Count="3" />
             <LdCtrlWriteProp ObjIdx="7" PropId="161" />
             <LdCtrlWriteProp ObjIdx="7" PropId="162" />
             <LdCtrlWriteProp ObjIdx="7" PropId="163" InlineData="0102" Count="2" />
            </LoadProcedure></LoadProcedures>
           </Static>
          </ApplicationProgram>
         </ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        let typed: Vec<(u16, u8, usize, u16)> = pd
            .typed_props
            .iter()
            .map(|t| (t.object_type, t.pid, t.len, t.count))
            .collect();
        assert_eq!(
            typed,
            vec![(11, 205, 32, 8), (50001, 211, 1, 1), (50002, 212, 3, 3)]
        );
        // PDT_UNSIGNED_LONG per IP address, PDT_UNSIGNED_CHAR for the 8-bit
        // number, nothing where no parameter says.
        let pdts: Vec<Option<u8>> = pd.typed_props.iter().map(|t| t.pdt).collect();
        assert_eq!(pdts, vec![Some(0x09), Some(0x02), None]);
        assert_eq!(
            pd.written_props,
            vec![(7, 161, 3, 1), (7, 162, 2, 1), (7, 163, 2, 2)]
        );
        // A bit field at offset 2 and a union: no scalar type.
        assert!(pd.written_prop_pdts.is_empty());
        Ok(())
    }

    /// Bussard issue #537: the Data Secure table capacities of the application.
    #[test]
    fn test_reader_records_security_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX><ManufacturerData><Manufacturer RefId="M-0004"><ApplicationPrograms>
          <ApplicationProgram Id="M-0004_A-2" ApplicationNumber="1" ApplicationVersion="1" MaskVersion="MV-07B0"
            IsSecureEnabled="true" MaxSecurityGroupKeyTableEntries="1500" MaxSecurityIndividualAddressEntries="70000">
           <Static />
          </ApplicationProgram>
         </ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;
        let pd = parse_application_program(xml, None)?.ok_or("parsed")?;
        assert_eq!(pd.security_capacity.group_key_rows, Some(1500));
        assert_eq!(pd.security_capacity.ia_rows, Some(u16::MAX));
        Ok(())
    }
}
