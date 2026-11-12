//! The KNXnet/IP settings of an IP interface imported from the project (issue
//! #391): `<IPConfig>` and `<AdditionalAddresses>` on the device instance
//! become the device file's `[knxnet]` table. The shape follows the real ETS 6
//! export of the IPS 300 SREG (1.1.200): `IPConfig` with `IPAddress` and
//! `MACAddress` only, eight `Address` children 22 to 29.

use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_model::knxnet::IpAssignment;
use bussard_model::{IndividualAddress, Model};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PROJECT_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21">
 <Project Id="P-9999">
  <Installations><Installation>
   <Topology><Area Address="1"><Line Address="1">
    <DeviceInstance Id="P-9999-0_DI-1" Address="200" Name="IP interface">
     <AdditionalAddresses>
      <Address Address="22" Name="" />
      <Address Address="23" Name="" />
      <Address Address="24" Name="" />
     </AdditionalAddresses>
     <IPConfig IPAddress="192.0.2.74" MACAddress="00:00:5E:00:53:01" />
    </DeviceInstance>
    <DeviceInstance Id="P-9999-0_DI-2" Address="201" Name="IP router">
     <IPConfig Assign="Fixed" IPAddress="192.168.1.80" SubnetMask="255.255.255.0" DefaultGateway="192.168.1.1" />
    </DeviceInstance>
    <DeviceInstance Id="P-9999-0_DI-3" Address="5" Name="Actuator" />
   </Line></Area></Topology>
  </Installation></Installations>
 </Project>
</KNX>"#;

fn tmp(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-knxnet-import-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_knxproj(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("knxnet.knxproj");
    let mut zw = ZipWriter::new(std::fs::File::create(&path)?);
    let opts = SimpleFileOptions::default();
    zw.start_file("knx_master.xml", opts)?;
    zw.write_all(br#"<KNX xmlns="http://knx.org/xml/project/21"/>"#)?;
    zw.start_file("P-9999/0.xml", opts)?;
    zw.write_all(PROJECT_XML.as_bytes())?;
    zw.finish()?;
    Ok(path)
}

fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok(s.parse()?)
}

#[test]
fn test_import_ipconfig_and_additional_addresses_fill_knxnet() -> TestResult {
    let dir = tmp("fill")?;
    let model = bussard_product::import(&write_knxproj(&dir)?, None)?;

    let iface = model.devices[&ia("1.1.200")?]
        .device
        .knxnet
        .clone()
        .ok_or("1.1.200 has [knxnet]")?;
    assert_eq!(
        iface.assignment,
        IpAssignment::Dhcp,
        "no Assign: the ETS default"
    );
    assert_eq!(iface.address, None, "a dhcp table holds no address");
    assert_eq!(iface.friendly_name, None);
    assert_eq!(
        iface.tunnels,
        vec![ia("1.1.22")?, ia("1.1.23")?, ia("1.1.24")?]
    );

    let router = model.devices[&ia("1.1.201")?]
        .device
        .knxnet
        .clone()
        .ok_or("1.1.201 has [knxnet]")?;
    assert_eq!(router.assignment, IpAssignment::Static);
    assert_eq!(router.address, Some("192.168.1.80".parse()?));
    assert_eq!(router.netmask, Some("255.255.255.0".parse()?));
    assert_eq!(router.gateway, Some("192.168.1.1".parse()?));
    assert!(router.tunnels.is_empty());

    assert!(model.devices[&ia("1.1.5")?].device.knxnet.is_none());
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_import_knxnet_round_trips_and_validates_clean() -> TestResult {
    let dir = tmp("save")?;
    let model = bussard_product::import(&write_knxproj(&dir)?, None)?;
    let out = dir.join("knx");
    model.save(&out)?;
    let file = std::fs::read_to_string(out.join("devices/1.1.200.toml"))?;
    assert!(
        file.ends_with(
            "[knxnet]\nassignment = \"dhcp\"\ntunnels = [\"1.1.22\", \"1.1.23\", \"1.1.24\"]\n"
        ),
        "{file}"
    );
    assert!(
        !file.contains("MAC") && !file.contains("00:00:5E"),
        "{file}"
    );
    let lock = std::fs::read_to_string(out.join("bussard.lock"))?;
    assert!(
        !lock.contains("tunnels") && !lock.contains("192.168"),
        "{lock}"
    );
    let back = Model::load(&out)?;
    assert_eq!(
        back.devices[&ia("1.1.200")?].device.knxnet,
        model.devices[&ia("1.1.200")?].device.knxnet
    );
    let codes: Vec<&str> = bussard_model::validate(&back)
        .iter()
        .filter(|d| d.location.contains("[knxnet]"))
        .map(|d| d.code)
        .collect();
    assert!(codes.is_empty(), "{codes:?}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
