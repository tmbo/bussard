//! ApplicationProgram parsing lives in the shared `bussard-ets` layer; this
//! module re-exports it so `.knxprod` reading and the crate's public API keep a
//! stable path. See [`bussard_ets::application`] for the parser.

pub use bussard_ets::application::{
    ApplicationProgram, ChannelDef, ChannelMembership, CodeSegment, ComObject, ComObjectRef,
    ConditionalGroup, EnumValue, LoadChoose, LoadGuard, LoadOp, LoadProcedure, Memory,
    ModuleInstance, Parameter, ParameterRef, ParameterType, ParameterTypeDecl, PropertyLocation,
    ResolvedComObject, ResolvedParameter, SegmentKind, TableLocation, parse_application_program,
};
