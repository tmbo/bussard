//! One-time extraction of an application program from an ETS project export
//! into a plain product archive (issue #228, item 3).
//!
//! A `.knxproj` carries, next to the (possibly encrypted) project, the product
//! data of every device in it: `knx_master.xml` and one `M-XXXX/` folder per
//! manufacturer with `Hardware.xml`, `Catalog.xml` and the ApplicationProgram
//! files. Those folders are never encrypted. [`extract_from_project`] copies
//! the entries one application needs, byte for byte, into a new ZIP that
//! [`crate::read_knxprod`] reads exactly as it reads the export: the same
//! entries through the same parser, so the program (and a flash image built
//! from it) is identical. After that the model never needs the export again.

use std::io::{Cursor, Write as _};
use std::path::Path;

use zip::write::SimpleFileOptions;

use crate::container::Container;
use crate::error::{ProdError, Result};

/// An archive [`extract_from_project`] built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The ZIP bytes.
    pub bytes: Vec<u8>,
    /// The application programs it carries (the requested one plus the
    /// companion programs its `Hardware2Program` lists next to it).
    pub applications: Vec<String>,
    /// The file name: `<application-id>.knxprod` (the id starts with the
    /// manufacturer, `M-0004_A-…`).
    pub file_name: String,
}

/// Extracts `application` (an ApplicationProgram id such as
/// `M-0004_A-A012-12-D63A-O000A`) from the project export `project` into a
/// plain product archive.
///
/// The archive holds `knx_master.xml`, the manufacturer's `Hardware.xml` and
/// `Catalog.xml`, the program and its companion programs, copied verbatim.
/// The ZIP is deterministic (fixed timestamps, sorted entries), so extracting
/// the same program from the same export twice gives the same bytes and the
/// same SHA-256.
///
/// # Errors
///
/// The export cannot be read, or it does not hold `application`.
pub fn extract_from_project(project: &Path, application: &str) -> Result<Extracted> {
    let mut container = Container::open(project)?;
    let Some((manufacturer, _)) = application.split_once("_A-") else {
        return Err(ProdError::MissingEntry {
            path: project.to_path_buf(),
            entry: format!("{application}.xml"),
        });
    };
    let entries = container.application_entries();
    if !entries.iter().any(|e| e.application_id == application) {
        return Err(ProdError::MissingEntry {
            path: project.to_path_buf(),
            entry: format!("{manufacturer}/{application}.xml"),
        });
    }
    // The companion programs (a PEI program downloaded in the same session)
    // come from the manufacturer's Hardware2Program groups.
    let mut applications = vec![application.to_string()];
    if let Some(xml) = container.hardware_xml(manufacturer)? {
        let hardware = crate::hardware::parse_hardware(&xml)?;
        for group in hardware.hardware2program.values() {
            if group.iter().any(|id| id == application) {
                for id in group {
                    let held = entries.iter().any(|e| &e.application_id == id);
                    if held && !applications.contains(id) {
                        applications.push(id.clone());
                    }
                }
            }
        }
    }
    applications.sort();

    let mut names: Vec<String> = vec![
        "knx_master.xml".to_string(),
        format!("{manufacturer}/Hardware.xml"),
        format!("{manufacturer}/Catalog.xml"),
    ];
    names.extend(
        entries
            .iter()
            .filter(|e| applications.contains(&e.application_id))
            .map(|e| e.entry.clone()),
    );
    names.sort();
    names.dedup();

    let zip_err = |source| ProdError::Zip {
        path: project.to_path_buf(),
        source,
    };
    let io_err = |source| ProdError::Io {
        path: project.to_path_buf(),
        source,
    };
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for name in &names {
        let Some(bytes) = container.entry_bytes(name)? else {
            continue;
        };
        writer.start_file(name.as_str(), options).map_err(zip_err)?;
        writer.write_all(&bytes).map_err(io_err)?;
    }
    let bytes = writer.finish().map_err(zip_err)?.into_inner();
    Ok(Extracted {
        bytes,
        applications,
        file_name: format!("{application}.knxprod"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "M-0083_A-1234-11-ABCD-O000A";

    fn write_zip(
        path: &Path,
        entries: &[(&str, &str)],
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
        for (name, body) in entries {
            zip.start_file(*name, SimpleFileOptions::default())?;
            zip.write_all(body.as_bytes())?;
        }
        zip.finish()?;
        Ok(())
    }

    const HARDWARE: &str = r#"<KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-0083"><Hardware>
<Products><Product OrderNumber="MDT-BE-04001.02" /></Products>
<Hardware2Programs><Hardware2Program><ApplicationProgramRef RefId="M-0083_A-1234-11-ABCD-O000A" /></Hardware2Program></Hardware2Programs>
</Hardware></Manufacturer></ManufacturerData></KNX>"#;

    const PROGRAM: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-0083"><ApplicationPrograms>
<ApplicationProgram Id="M-0083_A-1234-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Taster" LoadProcedureStyle="MergedProcedure"><Static /></ApplicationProgram>
</ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;

    fn project(dir: &Path) -> std::result::Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let path = dir.join("home.knxproj");
        write_zip(
            &path,
            &[
                ("knx_master.xml", "<KNX/>"),
                ("M-0083/Hardware.xml", HARDWARE),
                ("M-0083/Catalog.xml", "<KNX/>"),
                (&format!("M-0083/{APP}.xml") as &str, PROGRAM),
                ("M-0083/M-0083_A-9999-10-0000.xml", PROGRAM),
                ("P-048B/project.xml", "<KNX/>"),
                ("P-048B/0.xml", "<KNX/>"),
            ],
        )?;
        Ok(path)
    }

    #[test]
    fn test_extract_from_project_round_trips_the_program()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("bussard-extract-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let project = project(&dir)?;
        let extracted = extract_from_project(&project, APP)?;
        assert_eq!(extracted.file_name, format!("{APP}.knxprod"));
        assert_eq!(extracted.applications, vec![APP.to_string()]);
        let archive = dir.join(&extracted.file_name);
        std::fs::write(&archive, &extracted.bytes)?;

        let from_project = crate::read_knxprod(&project)?;
        let from_archive = crate::read_knxprod(&archive)?;
        assert!(!from_archive.is_project_export);
        assert_eq!(from_archive.applications.len(), 1);
        let a = from_project
            .application_by_id(APP)
            .ok_or("app in the export")?;
        let b = from_archive
            .application_by_id(APP)
            .ok_or("app in the archive")?;
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert_eq!(
            format!("{:?}", from_project.hardware),
            format!("{:?}", from_archive.hardware)
        );

        // Deterministic: the same export gives the same bytes.
        assert_eq!(extract_from_project(&project, APP)?.bytes, extracted.bytes);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_extract_from_project_refuses_an_unknown_program()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("bussard-extract-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let project = project(&dir)?;
        assert!(extract_from_project(&project, "M-0083_A-0000-10-0000").is_err());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
