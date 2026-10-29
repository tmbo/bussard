//! The product's `AppliesTo="par"` load procedure for a full System B
//! download onto a device that already holds the same application (issue
//! #490, owner decision 2026-10-29).
//!
//! A merged 07B0 application states its application-segment allocation
//! twice: `AppliesTo="full"` with the fill flag set (`Mode="1"`) and
//! `AppliesTo="par"` without it (`Mode="0"`, Configuration Procedures
//! 03_05_03 §3.5.1.2). The planner lowers the `full` one. ETS takes the `par`
//! one when the device already runs the application: the house captures of
//! 1.1.5, 1.1.7, 1.1.9, 1.1.16, 1.1.18, 1.1.47, 1.1.48 and 1.1.12 (the
//! offline oracle rows the issue lists) allocate object 4 with
//! `03 0b <size> 00 00 00 00`, read object 5's load state first and send it
//! no unload when it reads `Unloaded`, and open no factory reset.
//!
//! [`FlashPlan::use_par_procedure`] makes that change on a plan whose device
//! the pre-flight probe found holding this application
//! ([`crate::Freshness::SameApplication`]). The executor's resident-MCB skip
//! keeps the group-object table (object 3) when its MCB already matches, as
//! ETS kept it on 1.1.47, 1.1.48, 1.1.5 and 1.1.12. Nothing else changes:
//! every image is still written in full (no fill, so no sparse write), and
//! the read-back after the restart is the same.

use super::{FlashPlan, FlashStep};
use crate::preflight::ResidentState;
use bussard_mgmt::LoadState;

/// Whether an `AppliesTo` value names the `par` procedure and not the `full`
/// one (`"par"`, but not `"full,par"`).
pub(super) fn is_par_only(applies_to: &str) -> bool {
    let mut tokens = applies_to.split(',').map(str::trim);
    let par = tokens.clone().any(|t| t.eq_ignore_ascii_case("par"));
    par && !tokens.any(|t| t.eq_ignore_ascii_case("full"))
}

impl FlashPlan {
    /// Shapes this full System B plan into the product's `AppliesTo="par"`
    /// load procedure, for a device that already holds this application
    /// (module docs, issue #490):
    ///
    /// - each allocation the `par` procedure restates takes its fill (the
    ///   `Mode="0"` allocation keeps the memory contents);
    /// - an object the plan only unloads (no allocation, no load) gets no
    ///   `Unload` when `resident` read it `Unloaded`, as ETS reads object 5
    ///   and leaves it alone;
    /// - the factory reset the planner adds for a sparse write of a filled
    ///   segment goes when no allocation is filled any more.
    ///
    /// Returns whether the plan changed. A no-op on a System 7, property-only
    /// or parameter-only plan, and on a product that declares no `par`
    /// allocation: those keep the `full` procedure.
    pub fn use_par_procedure(&mut self, resident: Option<&ResidentState>) -> bool {
        if self.sys7.is_some()
            || self.is_property_only()
            || self.is_parameters_only()
            || self.par_allocations.is_empty()
            || self.par_procedure
        {
            return false;
        }
        let mut changed = false;
        for step in &mut self.steps {
            if let FlashStep::AllocateSegment { size, target, fill } = step
                && let Some(&(par_size, par_fill)) = self.par_allocations.get(target)
                && par_size == *size
                && *fill != par_fill
            {
                *fill = par_fill;
                changed = true;
            }
        }
        // The objects the plan loads: an allocation or a StartLoading names them.
        let loaded: Vec<Option<u32>> =
            self.steps
                .iter()
                .filter_map(|s| match s {
                    FlashStep::AllocateSegment { target, .. }
                    | FlashStep::StartLoading { target } => Some(*target),
                    _ => None,
                })
                .collect();
        let unloaded_on_device = |target: &Option<u32>| {
            target.is_some_and(|idx| {
                resident.is_some_and(|r| {
                    r.objects
                        .iter()
                        .any(|o| u32::from(o.index) == idx && o.state == LoadState::Unloaded)
                })
            })
        };
        let before = self.steps.len();
        self.steps.retain(|s| match s {
            FlashStep::Unload { target } => loaded.contains(target) || !unloaded_on_device(target),
            _ => true,
        });
        changed |= self.steps.len() != before;
        let filled = self
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::AllocateSegment { fill: Some(_), .. }));
        if !filled && self.has_factory_reset() {
            self.skip_factory_reset();
            changed = true;
        }
        self.par_procedure = changed;
        changed
    }

    /// Whether [`FlashPlan::use_par_procedure`] shaped this plan: a full
    /// download that runs the product's `par` load procedure.
    pub fn is_par_procedure(&self) -> bool {
        self.par_procedure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preflight::ResidentObject;

    #[test]
    fn test_is_par_only_names_par_without_full() {
        assert!(is_par_only("par"));
        assert!(is_par_only(" Par "));
        assert!(!is_par_only("full,par"));
        assert!(!is_par_only("full"));
        assert!(!is_par_only(""));
    }

    fn resident(objects: &[(u8, LoadState)]) -> ResidentState {
        ResidentState {
            objects: objects
                .iter()
                .map(|&(index, state)| ResidentObject {
                    index,
                    object_type: Some(3),
                    state,
                })
                .collect(),
            ..Default::default()
        }
    }

    /// The house shape (issue #490): the `full`/`par` pair on object 4, the
    /// 07B0 template's unload of object 5, which the plan never loads.
    #[test]
    fn test_use_par_procedure_takes_the_par_allocation() -> Result<(), Box<dyn std::error::Error>> {
        let mut plan = super::super::test_support::par_pair_plan()?;
        assert!(plan.has_factory_reset(), "the full plan opens with a reset");
        let changed = plan.use_par_procedure(Some(&resident(&[
            (4, LoadState::Loaded),
            (5, LoadState::Unloaded),
        ])));
        assert!(changed);
        assert!(plan.is_par_procedure());
        assert!(!plan.has_factory_reset());
        let allocs: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::AllocateSegment { target, fill, .. } => Some((*target, *fill)),
                _ => None,
            })
            .collect();
        assert_eq!(allocs, vec![(Some(4), None)]);
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| matches!(s, FlashStep::Unload { target: Some(5) })),
            "object 5 read Unloaded: no unload"
        );
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Unload { target: Some(4) }))
        );
        Ok(())
    }

    /// An object whose state the probe did not read keeps its unload.
    #[test]
    fn test_use_par_procedure_keeps_an_unread_unload() -> Result<(), Box<dyn std::error::Error>> {
        let mut plan = super::super::test_support::par_pair_plan()?;
        plan.use_par_procedure(Some(&resident(&[(4, LoadState::Loaded)])));
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Unload { target: Some(5) }))
        );
        let mut plan = super::super::test_support::par_pair_plan()?;
        plan.use_par_procedure(None);
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, FlashStep::Unload { target: Some(5) }))
        );
        Ok(())
    }

    /// A product without a `par` allocation keeps the `full` procedure.
    #[test]
    fn test_use_par_procedure_without_par_allocation_is_a_noop()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut plan = super::super::test_support::full_only_plan()?;
        let steps = plan.steps.clone();
        assert!(!plan.use_par_procedure(Some(&resident(&[(5, LoadState::Unloaded)]))));
        assert_eq!(plan.steps, steps);
        assert!(!plan.is_par_procedure());
        Ok(())
    }
}
