//! ZIP + XML reader that turns a `.knxprod` into [`ProductData`].

use std::io::Read;
use std::path::Path;

use base64::Engine;
use quick_xml::Reader;
use quick_xml::events::Event;

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
        let name = f.name().to_string();
        if name.ends_with(".xml") {
            names.push(name);
        }
    }

    for name in &names {
        let mut file = zip.by_name(name)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        if !content.contains("<ApplicationProgram") {
            continue;
        }
        if let Some(pd) = parse_application_program(&content, application_id)? {
            return Ok(pd);
        }
    }
    Err(ProdError::NoApplicationProgram)
}

/// Decode an even-length hex string (as used by `InlineData`); `None` on any
/// malformed input rather than a partial value.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
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
    let mut hardware_type_marker: Option<Vec<u8>> = None;

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
                b"LdCtrlCompareProp" => {
                    // The object-0 PID 78 preflight carries the device's
                    // hardware-type marker as inline hex. Capture it so the
                    // simulated device can seed PID 78 with the value its own
                    // vendor procedure expects (see `ProductData`).
                    if in_app
                        && parse_u32(&e, "ObjIdx")?.unwrap_or(u32::MAX) == 0
                        && parse_u32(&e, "PropId")?.unwrap_or(0) == 78
                        && let Some(hex) = attr(&e, "InlineData")
                    {
                        hardware_type_marker = decode_hex(&hex);
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
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }

    if app_id.is_empty() {
        return Ok(None);
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
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
