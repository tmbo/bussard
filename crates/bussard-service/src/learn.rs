//! Learning a group address from live traffic, once for both surfaces
//! (issue #903): what a telegram on a group address says about it
//! ([`observe`]) and the model edit an accepted proposal makes ([`accept`]).
//!
//! `bussard learn` asks the operator at a readline menu between the two; the
//! MCP `knx_infer_group` returns the observation for the assistant to ask.
//! Nothing here touches the bus.

use bussard_model::schema::Link;
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress, Model};
use bussard_monitor::infer::{self, DptCandidate, SendingObject};

/// What the traffic on one group address says about it.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The com object on the sender that sends the GA, when the model links it.
    pub object: Option<SendingObject>,
    /// The DPT candidates, best first.
    pub candidates: Vec<DptCandidate>,
    /// A name built from the sender's device, channel and location.
    pub proposed_name: Option<String>,
}

/// Observes `ga` sent by `sender` with `payloads` (the first one the telegram
/// in question, the rest earlier ones that narrow the candidates). Without
/// payloads the declared DPT of the sending object is the only candidate.
pub fn observe(
    model: &Model,
    ga: GroupAddress,
    sender: Option<IndividualAddress>,
    payloads: &[Vec<u8>],
) -> Observation {
    let object = sender.and_then(|ia| infer::sending_object(model, ia, ga));
    let declared = object.as_ref().and_then(|o| o.declared_dpt);
    let candidates = match payloads.split_first() {
        Some((first, rest)) => infer::refine(infer::infer_dpt(first, declared), rest),
        // Nothing seen yet: still report what the model knows, with the
        // declared DPT as the only candidate.
        None => match declared {
            Some(dpt) => infer::infer_dpt(&placeholder_payload(dpt), Some(dpt)),
            None => Vec::new(),
        },
    };
    // With no link in the model there is no com-object index; `u16::MAX` is
    // an index no com object uses, so the proposal falls back to the device's
    // own name and location.
    let proposed_name = sender.and_then(|ia| {
        infer::propose_name(
            model,
            ia,
            object.as_ref().map(|o| o.index).unwrap_or(u16::MAX),
        )
    });
    Observation {
        object,
        candidates,
        proposed_name,
    }
}

impl Observation {
    /// The name to offer for `ga`: the proposal, else the group's current
    /// name unless it is a placeholder, else `GA <ga>`.
    pub fn name(&self, model: &Model, ga: GroupAddress) -> String {
        self.proposed_name
            .clone()
            .or_else(|| {
                model
                    .groups
                    .groups
                    .get(&ga)
                    .map(|g| g.name.clone())
                    .filter(|n| !is_placeholder_name(ga, n))
            })
            .unwrap_or_else(|| format!("GA {ga}"))
    }
}

/// A zero payload of `dpt`'s size, to list the declared DPT as a candidate
/// before any telegram was seen.
fn placeholder_payload(dpt: Dpt) -> Vec<u8> {
    match dpt.expected_size() {
        Some(bussard_model::ApduSize::Bits(_)) => vec![0],
        Some(bussard_model::ApduSize::Bytes(n)) => vec![0; n as usize],
        None => vec![0],
    }
}

/// Whether a group's name is a placeholder rather than something a human
/// chose.
pub fn is_placeholder_name(ga: GroupAddress, name: &str) -> bool {
    let trimmed = name.trim();
    trimmed.is_empty()
        || trimmed == ga.to_string()
        || trimmed.eq_ignore_ascii_case(&format!("GA {ga}"))
        || trimmed.eq_ignore_ascii_case("unnamed")
        || trimmed.to_lowercase().starts_with("unknown")
}

/// The com objects on `sender` that could send a learned GA: transmit-capable
/// and without a sending GA yet. `None` when the sender is not in the model.
///
/// The wire carries no com-object number, so a link is only written when this
/// leaves exactly one, or the operator names one.
pub fn link_candidates(model: &Model, sender: IndividualAddress) -> Option<Vec<u16>> {
    let loaded = model.devices.get(&sender)?;
    let taken: Vec<u16> = model
        .links
        .links
        .get(&sender)
        .map(|links| {
            links
                .iter()
                .filter(|l| l.send.is_some())
                .map(|l| l.object)
                .collect()
        })
        .unwrap_or_default();
    Some(
        loaded
            .device
            .com_objects
            .iter()
            .filter(|(index, com)| com.flags.contains(Flags::TRANSMIT) && !taken.contains(index))
            .map(|(index, _)| *index)
            .collect(),
    )
}

/// What the operator accepted for a group address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The group's name.
    pub name: String,
    /// Its DPT.
    pub dpt: Dpt,
    /// The GA carries KNX Data Secure traffic (a verified secured telegram),
    /// so `write`/`read` seal their telegrams and `flash`/`apply` program the
    /// group key.
    pub secured: bool,
    /// The sending com object to link the GA to: the device and the object.
    pub link: Option<(IndividualAddress, u16)>,
}

/// Writes `decision` for `ga` into the model: the group (created when new)
/// and, when one was chosen, the sending link in the device file.
pub fn accept(model: &mut Model, ga: GroupAddress, decision: &Decision) {
    let entry = model.groups.groups.entry(ga).or_default();
    entry.name = decision.name.clone();
    entry.dpt = Some(decision.dpt);
    if decision.secured {
        entry.secure = true;
    }
    if let Some((sender, index)) = decision.link {
        let links = model.links.links.entry(sender).or_default();
        match links.iter_mut().find(|l| l.object == index) {
            Some(link) => link.send = Some(ga),
            None => links.push(Link {
                object: index,
                name: None,
                send: Some(ga),
                listen: Vec::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_is_placeholder_name_recognises_generated_names() -> R {
        let ga: GroupAddress = "1/0/1".parse()?;
        assert!(is_placeholder_name(ga, ""));
        assert!(is_placeholder_name(ga, "   "));
        assert!(is_placeholder_name(ga, "1/0/1"));
        assert!(is_placeholder_name(ga, "GA 1/0/1"));
        assert!(is_placeholder_name(ga, "Unnamed"));
        assert!(is_placeholder_name(ga, "Unknown object"));
        assert!(!is_placeholder_name(ga, "Kitchen ceiling light"));
        Ok(())
    }

    #[test]
    fn test_observe_without_a_sender_names_the_ga() -> R {
        let model = crate::history::empty_model();
        let ga: GroupAddress = "1/0/1".parse()?;
        let observation = observe(&model, ga, None, &[vec![0x01]]);
        assert!(observation.object.is_none());
        assert!(observation.proposed_name.is_none());
        assert!(!observation.candidates.is_empty());
        assert_eq!(observation.name(&model, ga), "GA 1/0/1");
        Ok(())
    }

    #[test]
    fn test_placeholder_payload_matches_the_dpt_width() {
        assert_eq!(placeholder_payload(Dpt::new(1, Some(1))).len(), 1);
        assert_eq!(placeholder_payload(Dpt::new(9, Some(1))).len(), 2);
        assert_eq!(placeholder_payload(Dpt::new(16, Some(1))).len(), 14);
    }

    #[test]
    fn test_accept_writes_the_group_and_the_link() -> R {
        let mut model = crate::history::empty_model();
        let ga: GroupAddress = "1/0/1".parse()?;
        let sender: IndividualAddress = "1.1.5".parse()?;
        let decision = Decision {
            name: "Kitchen light".to_string(),
            dpt: "1.001".parse()?,
            secured: true,
            link: Some((sender, 3)),
        };
        accept(&mut model, ga, &decision);
        let group = model.groups.groups.get(&ga).ok_or("group missing")?;
        assert_eq!(group.name, "Kitchen light");
        assert!(group.secure);
        let links = model.links.links.get(&sender).ok_or("links missing")?;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].object, 3);
        assert_eq!(links[0].send, Some(ga));
        Ok(())
    }
}
