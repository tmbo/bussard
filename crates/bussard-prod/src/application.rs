//! ApplicationProgram parsing lives in the shared `bussard-ets` layer; this
//! module re-exports it so `.knxprod` reading and the crate's public API keep a
//! stable path. See [`bussard_ets::application`] for the parser.

pub use bussard_ets::application::{
    ApplicationProgram, ChannelDef, CodeSegment, ComObject, ComObjectRef, EnumValue, LoadOp,
    LoadProcedure, Memory, Parameter, ParameterRef, ParameterType, ParameterTypeDecl,
    ResolvedComObject, ResolvedParameter, SegmentKind, parse_application_program,
};
