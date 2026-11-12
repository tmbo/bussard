//! A device as its file and its product model show it, in one shape (issue
//! #904): `bussard device --json` and `knx_show_device`.

use bussard_model::device_view::{BlockRow, DeviceView};
use bussard_model::knxnet::{KnxnetConfig, KnxnetFacts};
use bussard_model::{IndividualAddress, Model};
use serde::Serialize;
use serde_json::Value;

use crate::report::Report;

/// An IP interface's KNXnet/IP settings (issue #391): the device file's
/// `[knxnet]` table, what the interface last reported and where they differ.
#[derive(Debug, Clone, Serialize)]
pub struct KnxnetSection {
    /// The device file's `[knxnet]` table.
    pub model: Option<KnxnetConfig>,
    /// What the interface reported the last time it was read.
    pub device: Option<KnxnetFacts>,
    /// Where the two differ.
    pub drift: Vec<String>,
    /// Where the settings live and which tools change them.
    pub how_to_change: String,
}

impl KnxnetSection {
    /// The section of `ia`, `None` for a device with neither a table nor
    /// facts.
    pub fn of(dir: &std::path::Path, model: &Model, ia: IndividualAddress) -> Option<Self> {
        let config = model.devices.get(&ia).and_then(|d| d.device.knxnet.clone());
        let facts = bussard_model::facts::load_facts(dir, ia)
            .ok()
            .flatten()
            .and_then(|r| r.knxnet);
        if config.is_none() && facts.is_none() {
            return None;
        }
        let drift = match (&facts, &config) {
            (Some(f), Some(c)) => f.drift(c),
            _ => Vec::new(),
        };
        Some(KnxnetSection {
            model: config,
            device: facts,
            drift,
            how_to_change: format!(
                "The KNXnet/IP settings live in the [knxnet] table of devices/{ia}.toml \
                 (assignment, address, netmask, gateway, friendly_name, tunnels); \
                 knx_set_interface edits them (knx_set_parameter does not), and \
                 knx_plan_device then knx_apply_device write them to the interface's \
                 KNXnet/IP parameter object. `device` is what the interface reported the last \
                 time it was read (`bussard status {ia}`, `describe`, or a plan)."
            ),
        })
    }
}

/// A device as `bussard device` and `knx_show_device` show it.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceShow {
    /// The view: identity, pages and channels, the scope.
    #[serde(flatten)]
    pub view: DeviceView,
    /// A scoped view's pages, one line each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub block_summary: Vec<String>,
    /// A scoped view's inactive channels, one line each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inactive_channel_summary: Vec<String>,
    /// The inactive pages in detail, on request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inactive_pages: Vec<BlockRow>,
    /// How the listed parameters and links are changed and pushed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub how_to_change: Option<String>,
    /// The device file's TOML, on request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toml: Option<String>,
    /// An IP interface's KNXnet/IP settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knxnet: Option<KnxnetSection>,
    /// Whether bussard writes the device without the override (issue
    /// #1089).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<crate::support::SupportView>,
}

impl DeviceShow {
    /// `view` as is.
    pub fn of(view: DeviceView) -> DeviceShow {
        DeviceShow {
            view,
            block_summary: Vec::new(),
            inactive_channel_summary: Vec::new(),
            inactive_pages: Vec::new(),
            how_to_change: None,
            toml: None,
            knxnet: None,
            support: None,
        }
    }

    /// A scoped view: its pages and inactive channels in one line each,
    /// with the inactive ones in detail when `inactive`.
    pub fn scoped(mut view: DeviceView, inactive: bool) -> DeviceShow {
        let blocks = std::mem::take(&mut view.blocks);
        let channels = std::mem::take(&mut view.inactive_channels);
        let inactive_pages = if inactive {
            blocks
                .iter()
                .chain(&channels)
                .filter(|r| !r.active)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        DeviceShow {
            block_summary: blocks.iter().map(compact_row).collect(),
            inactive_channel_summary: channels.iter().map(compact_row).collect(),
            inactive_pages,
            ..DeviceShow::of(view)
        }
    }
}

impl Report for UnmodelledLive {
    const SCHEMA: u32 = 1;
}

impl Report for DeviceShow {
    const SCHEMA: u32 = 2;
}

/// One page or channel in one line: handle, text, state and counts.
pub fn compact_row(row: &BlockRow) -> String {
    let state = if row.active { "active" } else { "inactive" };
    let text = row
        .text
        .as_deref()
        .map(|t| format!(" {t:?}"))
        .unwrap_or_default();
    format!(
        "{}{text}: {state}, {}, {}",
        row.handle,
        counted(row.parameters, "parameter"),
        counted(row.objects, "object")
    )
}

/// `1 parameter`, `2 parameters`.
fn counted(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// A live read of a device the project does not have.
#[derive(Debug, Clone, Serialize)]
pub struct UnmodelledLive {
    /// The device.
    pub address: String,
    /// Why there is no view of it.
    pub model_view: String,
    /// What it reported.
    pub live: Value,
}
