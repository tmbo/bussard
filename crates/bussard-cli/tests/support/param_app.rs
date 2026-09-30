// The synthetic parameter-test application (issue #119), shared through
// `include!` by the parameter suites.

/// The synthetic application (bussard's own work, MIT; no vendor data).
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard parameter test app" LoadProcedureStyle="ProductDefault">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
              <RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
              <ParameterType Id="M-00FA_A-0002_PT-1" Name="onoff"><TypeRestriction Base="Value" SizeInBit="1">
                <Enumeration Text="Off" Value="0" /><Enumeration Text="On" Value="1" />
              </TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0002_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="obj2" Text="Object 2" ParameterType="M-00FA_A-0002_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
              <ComObject Id="M-00FA_A-0002_O-2" Number="2" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
              <ComObjectRef Id="M-00FA_A-0002_O-2_R-2" RefId="M-00FA_A-0002_O-2" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="par" />
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
                <choose ParamRefId="M-00FA_A-0002_P-1_R-2">
                  <when test="1"><ComObjectRefRef RefId="M-00FA_A-0002_O-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;
