// The synthetic parameter-test application (issue #119), shared through
// `include!` by the parameter suites.
//
// Parameter segment RS-2: octet 0 the threshold; octet 1 bit 0 "Object 2"
// (shows com-object 2), bit 1 free, bits 2..3 "Delay" (shown only with
// Object 2 on, written at its default 0 otherwise), bits 4..7 an internal
// function-block selector (`Access="None"`, reached by no Dynamic section,
// default "no application"), as ETS keeps them on a push-button (issue #285).

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
              <ParameterType Id="M-00FA_A-0002_PT-2" Name="two"><TypeNumber SizeInBit="2" Type="unsignedInt" maxInclusive="3" /></ParameterType>
              <ParameterType Id="M-00FA_A-0002_PT-3" Name="instances"><TypeRestriction Base="Value" SizeInBit="4">
                <Enumeration Text="no application" Value="0" /><Enumeration Text="Light" Value="3" />
              </TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0002_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="obj2" Text="Object 2" ParameterType="M-00FA_A-0002_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-2" Name="dly" Text="Delay" ParameterType="M-00FA_A-0002_PT-2" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="2" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-3" Name="_AppInstanz 1" Text="" ParameterType="M-00FA_A-0002_PT-3" Access="None" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="4" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
              <ParameterRef Id="M-00FA_A-0002_P-2_R-3" RefId="M-00FA_A-0002_P-2" />
              <ParameterRef Id="M-00FA_A-0002_P-3_R-4" RefId="M-00FA_A-0002_P-3" />
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
                  <when test="1"><ComObjectRefRef RefId="M-00FA_A-0002_O-2_R-2" /><ParameterRefRef RefId="M-00FA_A-0002_P-2_R-3" /></when>
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
