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
                .any(|&(o, p, _)| o == prop.0 && p == prop.1)
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
    let mut object_cands: Candidates<(u8, u8)> = Vec::new();
    let mut typed_cands: Candidates<(u16, u8)> = Vec::new();
    let mut chooses = ChooseStack::default();
    let mut defaults = Defaults::default();
    let mut written_props: Vec<(u8, u8, usize)> = Vec::new();
    let mut task_segment_lsms: Vec<u8> = Vec::new();
    let mut completes_loads = false;
    let mut compare_mems: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut typed_props: Vec<crate::prod::TypedProperty> = Vec::new();
    let mut object_types: Vec<(u8, u16)> = Vec::new();
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
                    in_app = true;
                }
                b"Parameter" if in_app => {
                    if let Some(id) = attr(&e, "Id") {
                        defaults.parameter(id, attr(&e, "Value"));
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
                            }),
                        }
                    }
                    let object = parse_u32(&e, "ObjIdx")?.and_then(|v| u8::try_from(v).ok());
                    let pid = parse_u32(&e, "PropId")?.and_then(|v| u8::try_from(v).ok());
                    let len = attr(&e, "InlineData")
                        .and_then(|hex| decode_hex(&hex))
                        .map_or(1, |v| v.len().max(1));
                    if let (Some(object), Some(pid)) = (object, pid)
                        && !written_props
                            .iter()
                            .any(|&(o, p, _)| o == object && p == pid)
                    {
                        written_props.push((object, pid, len));
                    }
                }
                b"LdCtrlLoadCompleted" if in_app => completes_loads = true,
                b"LdCtrlTaskSegment" if in_app => {
                    if let Some(lsm) = parse_u32(&e, "LsmIdx")?.and_then(|v| u8::try_from(v).ok())
                        && !task_segment_lsms.contains(&lsm)
                    {
                        task_segment_lsms.push(lsm);
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
                    let value = attr(&e, "InlineData").and_then(|hex| decode_hex(&hex));
                    if in_app
                        && !device_object
                        && let (Some(value), Ok(pid)) = (value.clone(), u8::try_from(pid))
                    {
                        match (obj_idx.and_then(|o| u8::try_from(o).ok()), obj_type) {
                            (Some(object), _) => {
                                object_cands.push(((object, pid), value, chooses.guards()));
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
                                        });
                                    }
                                    typed_cands.push(((object_type, pid), value, chooses.guards()));
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
    let manufacturer = app_id
        .strip_prefix("M-")
        .and_then(|m| m.get(..4))
        .and_then(|m| u16::from_str_radix(m, 16).ok());
    let object_compare_props: Vec<(u8, u8, Vec<u8>)> = defaults
        .pick(&object_cands)
        .into_iter()
        .map(|((o, p), mut v)| {
            if p == 13 && v.len() == 5 && v[..2] == [0, 0] {
                if let Some(m) = manufacturer {
                    v[..2].copy_from_slice(&m.to_be_bytes());
                }
                if v[4] == 0 {
                    v[4] = u8::try_from(app_version).unwrap_or(0);
                }
            }
            (o, p, v)
        })
        .collect();
    for ((object_type, pid), value) in defaults.pick(&typed_cands) {
        if let Some(t) = typed_props
            .iter_mut()
            .find(|t| t.object_type == object_type && t.pid == pid)
        {
            t.compare = Some(value);
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
        task_segment_lsms: completes_loads.then_some(task_segment_lsms),
        compare_mems,
        object_compare_props,
        typed_props,
        object_types,
        property_only: property_ops && !other_ops,
    }))
}

#[cfg(test)]
mod tests {
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
        assert!(pd.written_props.contains(&(4, 16, 1)));
        assert!(pd.written_props.contains(&(5, 16, 1)));
        assert!(pd.written_props.contains(&(5, 13, 5)));
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
        assert_eq!(pd.object_compare_props, vec![(3, 13, vec![0xBB])]);
        assert_eq!(
            pd.hardware_type_marker,
            Some(vec![0, 0, 0, 0, 0x01, 0x4A, 0, 0, 0, 0])
        );
        // Default "to R1.9" (0): the other branch.
        let pd = parse_application_program(&branch_app("0", ""), None)?.ok_or("parsed")?;
        assert_eq!(pd.device_compare_props[1], (19, vec![0x00; 4]));
        assert_eq!(pd.object_compare_props, vec![(3, 13, vec![0xAA])]);
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
            vec![(3, 13, vec![0x00, 0x04, 0xA0, 0x42, 0x10])]
        );
        assert_eq!(pd.typed_props.len(), 2);
        assert!(pd.typed_props.iter().all(|t| t.written));
        assert_eq!(pd.typed_props[0].object_type, 11);
        assert_eq!(pd.typed_props[1].object_type, 50001);
        Ok(())
    }
}
