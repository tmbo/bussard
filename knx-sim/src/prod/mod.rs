//! Independent `.knxprod` product-data reader (flash-relevant subset).
//!
//! A `.knxprod` is a plain (unencrypted) ZIP of KNX product XML. This reader
//! extracts only what a device needs to model a flash:
//!
//! - the `ApplicationProgram` identity (application number/version, mask);
//! - the loadable-object structure — which load-state-machine indices exist
//!   (address table = 1, association table = 2, com-object table = 3,
//!   application = 4), derived from the presence of `AddressTable`,
//!   `AssociationTable`, `ComObjectTable` and `RelativeSegment` elements;
//! - each `RelativeSegment`'s load-state-machine index, size and base64
//!   application image;
//! - the `LoadProcedures` (`LdCtrlRelSegment`, `LdCtrlWriteRelMem`,
//!   `LdCtrlMasterReset`).
//!
//! It is a clean-room parser: it does not reuse the tool's importer.

mod model;
mod reader;

pub use model::{LdCtrl, LoadProcedure, LoadableObject, ProductData, RelativeSegment};
pub use reader::{ProdError, read_knxprod, read_knxprod_bytes};
