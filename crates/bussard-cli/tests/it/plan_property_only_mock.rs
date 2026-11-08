//! A System B program whose parameters all live in interface-object
//! properties (issue #944, the shape of the Hager 07B0 actuators
//! `M-0009_A-E804-10-98AD` and `M-0009_A-E805-10-B015`): a code segment, no
//! parameter memory, and every parameter placed in a declared property that
//! an `LdCtrlWriteProp` without `InlineData` writes. After a full flash the
//! plan reads the properties back and finds nothing to change; one changed
//! parameter is planned as one property write. `apply` and `flash
//! --parameters-only` refuse to send that download until the ETS capture of
//! #572 A.4 confirms it; the download itself is tested on the mock device in
//! `bussard-download` (`property_only_partial.rs`).

include!("support/param_mock.rs");

/// The property-only synthetic application (bussard's own work, MIT; no
/// vendor data). Object 10 PID 52 holds two 8-bit parameters, "Delay" at
/// octet 0 (default 5) and "Level" at octet 1 (default 9). The allocation is
/// stated twice, `full` in Mode 1 and `par` in Mode 0, as the Hager programs
/// state it.
const PROPERTY_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard property-only test app" LoadProcedureStyle="ProductDefault"
            MinEtsVersion="5.0">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="dly" Text="Delay" ParameterType="M-00FA_A-0002_PT-0" Value="5"><Property ObjectIndex="10" PropertyId="52" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="lvl" Text="Level" ParameterType="M-00FA_A-0002_PT-0" Value="9"><Property ObjectIndex="10" PropertyId="52" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" Mode="1" Fill="0" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" Mode="0" Fill="0" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full,par" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="2" Verify="false" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0002_O-1_R-1" />
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

/// The property the parameters live in.
const PARAM_PROPERTY: (u8, u8) = (10, 52);

/// Rewrites the device file of 1.1.4 with `params` as its `[parameters]`
/// table (TOML lines), keeping the link of [`write_model`].
fn write_device(bench: &Bench, params: &str) -> TestResult {
    let block = if params.is_empty() {
        String::new()
    } else {
        format!("\n[parameters]\n{params}")
    };
    std::fs::write(
        bench.tmp.join("knx").join("devices").join("1.1.4.toml"),
        format!(
            "address = \"1.1.4\"\nname = \"Parameter test\"\n{block}\n[links]\n1.listen = [\"1/2/0\"]\n"
        ),
    )?;
    Ok(())
}

/// `bussard plan 1.1.4 --json`, parsed.
fn plan_json(bench: &Bench) -> Result<serde_json::Value, Box<dyn Error>> {
    let out = bench.bussard(&["plan", "1.1.4", "--product", bench.product()?, "--json"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    Ok(serde_json::from_str(&stdout)?)
}

/// What a no-op plan must not carry: a change, a write, a parameter
/// difference or a parameter note.
fn plan_problems(plan: &serde_json::Value) -> Vec<String> {
    let mut problems = Vec::new();
    for c in plan["changes"].as_array().into_iter().flatten() {
        problems.push(format!("change: {c}"));
    }
    for (what, n) in plan["writes"].as_object().into_iter().flatten() {
        if n.as_u64().is_some_and(|n| n > 0)
            || n.as_bool() == Some(true)
            || n.is_object()
            || n.as_array().is_some_and(|a| !a.is_empty())
        {
            problems.push(format!("writes {what}: {n}"));
        }
    }
    for d in plan["parameters"]["differences"]
        .as_array()
        .into_iter()
        .flatten()
    {
        problems.push(format!("parameter differs: {d}"));
    }
    if let Some(note) = plan["parameters"]["note"].as_str() {
        problems.push(format!("parameters: {note}"));
    }
    for n in plan["notes"].as_array().into_iter().flatten() {
        if n.as_str().is_some_and(|n| n.starts_with("parameters not")) {
            problems.push(format!("note: {n}"));
        }
    }
    problems
}

#[test]
fn test_plan_after_flash_of_a_property_only_program_is_clean() -> TestResult {
    let Some(bench) = Bench::start_with_app(
        "prop-only-flash",
        MockDevice::running([0, 0]),
        "\"dly@P-0_R-1\" = \"12\"\n",
        PROPERTY_APP_XML,
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["flash", "1.1.4", "--product", bench.product()?, "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    // The verify counts the two parameters the property read-back compared.
    assert!(stdout.contains("2 parameters"), "{stdout}");
    // The flash wrote the property the parameters compose: Delay 12 (0C),
    // Level at its default 9.
    let dev = bench.device();
    assert_eq!(
        dev.properties.get(&PARAM_PROPERTY),
        Some(&(1, vec![0x0C, 0x09])),
        "{stderr}"
    );

    // The plan reads the property back and finds nothing to change.
    let plan = plan_json(&bench)?;
    assert_eq!(plan_problems(&plan), Vec::<String>::new(), "{plan}");
    // Read-only: nothing written after the flash.
    let after = bench.device();
    assert_eq!(after.property_writes, dev.property_writes);
    assert_eq!(after.load_events, dev.load_events);
    Ok(())
}

#[test]
fn test_plan_one_changed_property_parameter_and_apply_refuses() -> TestResult {
    let Some(bench) = Bench::start_with_app(
        "prop-only-apply",
        MockDevice::running([0, 0]),
        "",
        PROPERTY_APP_XML,
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["flash", "1.1.4", "--product", bench.product()?, "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        bench.device().properties.get(&PARAM_PROPERTY),
        Some(&(1, vec![0x05, 0x09]))
    );
    assert_eq!(plan_problems(&plan_json(&bench)?), Vec::<String>::new());

    // One parameter changes: one property write, no memory octet.
    write_device(&bench, "\"lvl@P-1_R-2\" = \"20\"\n")?;
    let plan = plan_json(&bench)?;
    assert_eq!(
        plan["writes"]["parameter_properties"],
        serde_json::json!(["object 10 PID 52"]),
        "{plan}"
    );
    assert_eq!(plan["writes"]["parameter_octets"], 0, "{plan}");
    let changes = plan["changes"].as_array().ok_or("no changes")?;
    assert_eq!(changes.len(), 1, "{plan}");

    // No ETS capture confirms the parameter-only download of such a program
    // yet (#572 A.4): `apply` refuses it, names the capture, writes nothing.
    let flashed = bench.device();
    let out = bench.bussard(&["apply", "1.1.4", "--product", bench.product()?, "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("refusing to apply to 1.1.4"), "{stderr}");
    assert!(stderr.contains("#572"), "{stderr}");
    let dev = bench.device();
    assert_eq!(dev.property_writes, flashed.property_writes, "{stderr}");
    assert_eq!(dev.load_events, flashed.load_events, "{stderr}");
    assert_eq!(dev.memory_writes, flashed.memory_writes, "{stderr}");
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        format!("{stdout}{stderr}").contains("#572"),
        "{stdout}{stderr}"
    );
    assert_eq!(bench.device().property_writes, flashed.property_writes);

    // A full flash writes the changed property; the plan is clean again.
    let out = bench.bussard(&["flash", "1.1.4", "--product", bench.product()?, "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        bench.device().properties.get(&PARAM_PROPERTY),
        Some(&(1, vec![0x05, 0x14]))
    );
    assert_eq!(plan_problems(&plan_json(&bench)?), Vec::<String>::new());
    Ok(())
}
