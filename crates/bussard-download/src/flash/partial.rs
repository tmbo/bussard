//! The parameter-only download (issue #119): a [`FlashPlan`] cut down to the
//! parameter memory of a device that already runs the application.
//!
//! A full flash unloads every object, allocates and streams every segment,
//! rewrites the tables and restarts. Changing one parameter does not need any
//! of that. ETS rewrites only the parameter octets that changed, then completes
//! the load and restarts (the captures of `1.1.47`, System B, and `1.1.202`,
//! System 7, each wrote one octet of parameter memory). This module derives
//! that shape from the full plan, so the op sequence, the object indices and the
//! images all come from the same vendor procedure the full flash interprets:
//!
//! - **System B**: `StartLoading` the object that holds the parameter segment
//!   (no `Unload`, no `RelSegment`: the segment stays where it is), the
//!   procedure's property writes on that object (the `PID_MCB_TABLE` seed and
//!   the program version, which ETS rewrites on a partial download too), each
//!   parameter image as an absolute write at the base the device reported
//!   through `PID_TABLE_REFERENCE`, `LoadCompleted`, the procedure's MCB checks
//!   on that object, and the terminal restart.
//! - **System 7** (issue #146): `StartLoading` the load-state machine that
//!   holds the parameter segments, each parameter image as an absolute write at
//!   its segment address, `LoadCompleted`, the procedure's MCB reads, and the
//!   restart, preceded by ETS's pre-download restart (without its unloads) and,
//!   on a `VerifyMode` mask, the verify-mode switch (issue #116). No
//!   `AbsSegment` record, no task segment and no task-control op:
//!   the segments stay allocated where they are. A re-sent allocation (the
//!   `0x0700` RAM region) put the Jung 3361-1MWW (`1.1.32`, mask 0705) into load
//!   state Error; ETS's partial download of the same device
//!   (`bad-eg-pm-1-1-18.pcapng`) opens and completes the application LSM
//!   around plain `A_Memory_Write`s and sends nothing else to it. The executor
//!   refuses before the `StartLoading` unless the machine reads `Loaded`.
//!
//! Every parameter image carries the octets the device holds today as its
//! baseline, so the executor writes only the octets that differ. The address,
//! association and group-object tables are never touched.

use std::collections::{BTreeMap, BTreeSet};

use super::{FlashPlan, FlashStep, ImageKind, ImageRef};
use crate::param_plan::ParamRegions;

/// Why a full plan cannot be cut down to a parameter-only download.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartialPlanError {
    /// The procedure writes no parameter image at all.
    #[error(
        "the application's load procedure writes no parameter image, so there is \
         nothing a parameter-only download could rewrite; use a full `bussard flash`"
    )]
    NoParameterSegment,
    /// A parameter segment could not be read back, so its address (System B:
    /// the object's `PID_TABLE_REFERENCE`) or its current content is unknown.
    #[error(
        "parameter segment {segment} could not be read back from the device (its base \
         address or content is unknown), so a parameter-only download cannot place its \
         write; use a full `bussard flash`"
    )]
    UnreadableSegment {
        /// The code-segment id.
        segment: String,
    },
}

impl FlashPlan {
    /// Cuts this full plan down to a parameter-only download against the
    /// parameter memory the device holds today (`regions`, read by
    /// [`crate::read_parameter_regions`] against this same plan).
    ///
    /// See the module docs for the op sequence per system. Fails when the
    /// procedure writes no parameter image, or when a parameter segment was not
    /// read back.
    pub fn parameters_only(&self, regions: &ParamRegions) -> Result<FlashPlan, PartialPlanError> {
        let steps = if self.is_sys7() {
            self.sys7_parameter_steps(regions)?
        } else {
            self.system_b_parameter_steps(regions)?
        };
        let baseline: BTreeMap<String, Vec<u8>> = steps
            .iter()
            .filter_map(|step| match step {
                FlashStep::WriteMem { image, .. } => regions
                    .get(&image.segment_id)
                    .map(|r| (image.segment_id.clone(), r.bytes.clone())),
                _ => None,
            })
            .collect();
        // Issue #290: only the octets a parameter placement covers are
        // compared and written. Every other octet of the image (the segment's
        // fill or `<Data>` where the Dynamic reaches no parameter under the
        // configuration) takes the device's value, so the download leaves it
        // alone, as ETS's download does; where the model's image differs
        // there, the octet is recorded as unwritten.
        let mut images = self.images.clone();
        let mut unwritten: BTreeMap<String, Vec<(usize, u8)>> = BTreeMap::new();
        for (segment, current) in &baseline {
            let Some(image) = images.get_mut(segment) else {
                continue;
            };
            let placed = self.placed.get(segment);
            let mask = self.segment_mask(segment);
            let mut skipped = Vec::new();
            for (i, byte) in image.iter_mut().enumerate() {
                let Some(&held) = current.get(i) else {
                    break;
                };
                if placed.is_some_and(|p| p.contains(&i)) {
                    continue;
                }
                let writable = mask.is_none_or(|m| m.get(i) == Some(&0xFF));
                if writable && *byte != held {
                    skipped.push((i, *byte));
                }
                *byte = held;
            }
            if !skipped.is_empty() {
                unwritten.insert(segment.clone(), skipped);
            }
        }
        Ok(FlashPlan {
            identity: self.identity.clone(),
            device_mask: self.device_mask,
            steps,
            images,
            param_images: self.param_images.clone(),
            spliced_from_template: self.spliced_from_template,
            sys7: self.sys7.clone(),
            confirmed_restart: self.confirmed_restart,
            baseline,
            placed: self.placed.clone(),
            unwritten,
        })
    }

    /// The octets of `segment` a parameter placement writes under the
    /// configuration this plan was built for (issue #290), `None` when no
    /// parameter lands in the segment.
    pub fn placed_octets(&self, segment: &str) -> Option<&std::collections::BTreeSet<usize>> {
        self.placed.get(segment)
    }

    /// The octets a parameter-only download leaves as the device holds them
    /// although the model's image differs there (issue #290), per segment:
    /// each octet's offset and the differing bits (`model ^ device`), in the
    /// form of [`FlashPlan::changed_bits`]. No parameter the configuration
    /// reaches is placed in them, so ETS's download does not write them
    /// either. Empty for a full flash.
    pub fn unwritten_bits(&self) -> BTreeMap<String, Vec<(usize, u8)>> {
        self.unwritten
            .iter()
            .map(|(segment, octets)| {
                let current = self.baseline.get(segment);
                let bits = octets
                    .iter()
                    .map(|&(i, model)| {
                        let held = current.and_then(|c| c.get(i)).copied().unwrap_or(model);
                        (i, model ^ held)
                    })
                    .collect();
                (segment.clone(), bits)
            })
            .collect()
    }

    /// The model's image of `segment`: for a parameter-only download, the
    /// image it writes with the [`FlashPlan::unwritten_bits`] octets put back
    /// to the model's bytes (what a full download writes); for a full flash,
    /// [`FlashPlan::image_bytes`].
    pub fn model_image(&self, segment: &str) -> Option<Vec<u8>> {
        let mut image = self.images.get(segment)?.clone();
        for &(i, model) in self.unwritten.get(segment).into_iter().flatten() {
            if let Some(byte) = image.get_mut(i) {
                *byte = model;
            }
        }
        Some(image)
    }

    /// This parameter-only download rewritten to put `wanted` back (a
    /// parameter backup's memory, segment id to octets): each placed octet
    /// not in `skip` takes the backup's byte, every other octet keeps what the
    /// device holds (issue #290, `bussard restore --parameters`). A segment
    /// `wanted` does not name is left as the device holds it.
    ///
    /// The restore writes the same octets an `apply` of the model may write
    /// (the ones a parameter is placed in under the model's configuration),
    /// so it puts back everything an apply changed, and nothing ETS's
    /// download would leave alone. `skip` names the device-managed octets
    /// (`Access="None"` values the application owns at runtime).
    pub fn restoring(
        &self,
        wanted: &BTreeMap<String, Vec<u8>>,
        skip: &bussard_prod::PlacedOctets,
    ) -> FlashPlan {
        let mut plan = self.clone();
        plan.unwritten = BTreeMap::new();
        for (segment, current) in &self.baseline {
            let Some(image) = plan.images.get_mut(segment) else {
                continue;
            };
            let backup = wanted.get(segment);
            let placed = self.placed.get(segment);
            let skipped = skip.get(segment);
            let mut left = Vec::new();
            for (i, byte) in image.iter_mut().enumerate() {
                let held = current.get(i).copied();
                let restored = backup.and_then(|b| b.get(i)).copied();
                let writes = placed.is_some_and(|p| p.contains(&i))
                    && !skipped.is_some_and(|s| s.contains(&i));
                match (writes, restored, held) {
                    (true, Some(b), _) => *byte = b,
                    (_, _, Some(h)) => {
                        if let Some(b) = restored.filter(|b| *b != h) {
                            left.push((i, b));
                        }
                        *byte = h;
                    }
                    // Past what the device read back: nothing to keep.
                    (false, _, None) | (true, None, None) => {}
                }
            }
            if !left.is_empty() {
                plan.unwritten.insert(segment.clone(), left);
            }
        }
        plan
    }

    /// The System B parameter-only steps (module docs).
    fn system_b_parameter_steps(
        &self,
        regions: &ParamRegions,
    ) -> Result<Vec<FlashStep>, PartialPlanError> {
        // Pass 1: the parameter writes, and the load-state machine that owns
        // their segment: the allocation naming the write's own object index
        // (the master template allocates obj4, obj3, obj1, obj2 before writing
        // any), else the most recent allocation (the single-object shape, whose
        // write names `ObjIdx=0`).
        let mut lsms: BTreeSet<Option<u32>> = BTreeSet::new();
        let mut objects: BTreeSet<u32> = BTreeSet::new();
        let mut allocated: BTreeSet<Option<u32>> = BTreeSet::new();
        let mut last_alloc: Option<Option<u32>> = None;
        let mut writes = 0usize;
        for step in &self.steps {
            match step {
                FlashStep::AllocateSegment { target, .. } => {
                    allocated.insert(*target);
                    last_alloc = Some(*target);
                }
                FlashStep::WriteRelMem { image, target, .. }
                    if image.kind == ImageKind::Parameters =>
                {
                    if !regions.contains_key(&image.segment_id) {
                        return Err(PartialPlanError::UnreadableSegment {
                            segment: image.segment_id.clone(),
                        });
                    }
                    writes += 1;
                    let lsm = if allocated.contains(target) {
                        *target
                    } else {
                        last_alloc.unwrap_or(*target)
                    };
                    lsms.insert(lsm);
                    objects.extend(lsm);
                    objects.extend(target.filter(|t| *t != 0));
                }
                _ => {}
            }
        }
        if writes == 0 {
            return Err(PartialPlanError::NoParameterSegment);
        }

        // Pass 2: keep only what touches that object.
        let mut written: BTreeSet<String> = BTreeSet::new();
        let mut steps = Vec::new();
        for step in &self.steps {
            match step {
                FlashStep::StartLoading { target } | FlashStep::LoadCompleted { target }
                    if lsms.contains(target) =>
                {
                    steps.push(step.clone());
                }
                FlashStep::WriteRelMem { image, .. } if image.kind == ImageKind::Parameters => {
                    // A segment the procedure writes twice is written once: the
                    // image is the whole segment either way.
                    if !written.insert(image.segment_id.clone()) {
                        continue;
                    }
                    if let Some(region) = regions.get(&image.segment_id) {
                        steps.push(FlashStep::WriteMem {
                            address: region.address,
                            image: image.clone(),
                        });
                    }
                }
                FlashStep::WriteProp { obj_idx, .. } if objects.contains(obj_idx) => {
                    steps.push(step.clone());
                }
                FlashStep::LoadImageProp { obj_idx, .. } if objects.contains(obj_idx) => {
                    steps.push(step.clone());
                }
                // Read-only preconditions the vendor asks for stay in.
                FlashStep::CompareProp { .. } | FlashStep::CompareRelMem { .. } => {
                    steps.push(step.clone());
                }
                FlashStep::Restart => steps.push(step.clone()),
                _ => {}
            }
        }
        Ok(steps)
    }

    /// The System 7 parameter-only steps (module docs).
    fn sys7_parameter_steps(
        &self,
        regions: &ParamRegions,
    ) -> Result<Vec<FlashStep>, PartialPlanError> {
        let carries_params = |segment: &str| {
            self.param_images
                .get(segment)
                .is_some_and(|b| !b.is_empty())
        };
        let mut lsms: BTreeSet<u32> = BTreeSet::new();
        for step in &self.steps {
            if let FlashStep::Sys7AbsSegment {
                lsm,
                image: Some(image),
                ..
            } = step
                && carries_params(&image.segment_id)
            {
                if !regions.contains_key(&image.segment_id) {
                    return Err(PartialPlanError::UnreadableSegment {
                        segment: image.segment_id.clone(),
                    });
                }
                lsms.insert(*lsm);
            }
        }
        if lsms.is_empty() {
            return Err(PartialPlanError::NoParameterSegment);
        }
        let mut written: BTreeSet<String> = BTreeSet::new();
        let mut steps = Vec::new();
        for step in &self.steps {
            match step {
                FlashStep::Sys7StartLoading { lsm } | FlashStep::Sys7LoadCompleted { lsm }
                    if lsms.contains(lsm) =>
                {
                    steps.push(step.clone());
                }
                // The parameter segments become plain absolute writes; every
                // other segment record (the code, the RAM region) is left out,
                // and so are the task segment and task-control ops.
                FlashStep::Sys7AbsSegment {
                    address,
                    image: Some(image),
                    ..
                } if carries_params(&image.segment_id) => {
                    if !written.insert(image.segment_id.clone()) {
                        continue;
                    }
                    let address = regions
                        .get(&image.segment_id)
                        .map_or(*address, |region| region.address);
                    steps.push(FlashStep::WriteMem {
                        address,
                        image: ImageRef {
                            kind: ImageKind::Parameters,
                            ..image.clone()
                        },
                    });
                }
                // Read-only checks: the vendor's preconditions, and the MCB
                // reads of objects 1 to 3 that ETS repeats after its partial
                // download.
                FlashStep::Sys7CompareMem { .. }
                | FlashStep::CompareProp { .. }
                | FlashStep::LoadImageProp { .. } => {
                    steps.push(step.clone());
                }
                FlashStep::Restart | FlashStep::Sys7EnableVerifyMode => {
                    steps.push(step.clone());
                }
                // ETS restarts the device before a parameter download too, but
                // unloads nothing (`meteodata-1-1-202.pcapng`, issue #116).
                FlashStep::Sys7PreDownloadRestart { .. } => {
                    steps.push(FlashStep::Sys7PreDownloadRestart { unload: Vec::new() });
                }
                _ => {}
            }
        }
        Ok(steps)
    }

    /// How many octets the parameter-only download writes: the octets of each
    /// parameter image that differ from its baseline. `0` means the device
    /// already holds every value.
    pub fn changed_octets(&self) -> usize {
        self.changed_bits().values().map(Vec::len).sum()
    }

    /// The octets the parameter-only download writes, per code segment: each
    /// written octet's offset in its segment and the bits that differ from
    /// the baseline (`desired ^ current`, MSB first as the encoder places
    /// fields; `0xFF` when the device's octet was not read). The same octets
    /// [`FlashPlan::changed_octets`] counts.
    pub fn changed_bits(&self) -> BTreeMap<String, Vec<(usize, u8)>> {
        self.baseline
            .iter()
            .map(|(segment, current)| {
                let desired = self.images.get(segment).map(Vec::as_slice).unwrap_or(&[]);
                let mask = self.segment_mask(segment);
                let changed: Vec<(usize, u8)> = desired
                    .iter()
                    .enumerate()
                    .filter(|(i, b)| {
                        mask.is_none_or(|m| m.get(*i) == Some(&0xFF)) && current.get(*i) != Some(*b)
                    })
                    .map(|(i, b)| (i, current.get(i).map_or(0xFF, |c| c ^ b)))
                    .collect();
                (segment.clone(), changed)
            })
            .filter(|(_, changed)| !changed.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::plan::plan_flash;
    use crate::flash::test_support::fabricated_app;
    use crate::param_plan::ParamRegion;

    fn region(segment: &str, address: u32, bytes: &[u8]) -> (String, ParamRegion) {
        (
            segment.to_string(),
            ParamRegion {
                segment_id: segment.to_string(),
                address,
                bytes: bytes.to_vec(),
            },
        )
    }

    #[test]
    fn test_parameters_only_system_b_keeps_only_the_parameter_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = fabricated_app();
        let overrides = BTreeMap::from([("P-0_R-0".to_string(), "9".to_string())]);
        let full = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &overrides,
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let segment = "M-1_A-1_RS-2";
        let regions = ParamRegions::from([region(segment, 0x4006, &[7])]);
        let partial = full.parameters_only(&regions)?;
        assert!(partial.is_parameters_only());
        assert!(
            !partial.steps.iter().any(|s| matches!(
                s,
                FlashStep::Unload { .. }
                    | FlashStep::AllocateSegment { .. }
                    | FlashStep::WriteRelMem { .. }
                    | FlashStep::FactoryReset { .. }
            )),
            "no unload, allocation or relative write: {:?}",
            partial.steps
        );
        let writes: Vec<_> = partial
            .steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::WriteMem { address, image } => {
                    Some((*address, image.segment_id.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(writes, vec![(0x4006, segment.to_string())]);
        assert!(matches!(
            partial.steps.first(),
            Some(FlashStep::StartLoading { .. })
        ));
        assert!(matches!(partial.steps.last(), Some(FlashStep::Restart)));
        assert_eq!(partial.changed_octets(), 1);
        assert_eq!(partial.baseline(segment), Some(&[7u8][..]));
        Ok(())
    }

    #[test]
    fn test_parameters_only_refuses_an_unread_segment() -> Result<(), Box<dyn std::error::Error>> {
        let app = fabricated_app();
        let full = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let err = full.parameters_only(&ParamRegions::new());
        assert!(matches!(
            err,
            Err(PartialPlanError::UnreadableSegment { .. })
        ));
        Ok(())
    }

    /// Issue #290: a restore writes the backup's byte on a placed octet,
    /// and leaves a skipped (device-managed) one as the device holds it,
    /// reporting it as unwritten.
    #[test]
    fn test_restoring_writes_placed_octets_and_keeps_skipped_ones()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = fabricated_app();
        let full = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let segment = "M-1_A-1_RS-2";
        assert!(full.placed_octets(segment).is_some_and(|p| p.contains(&0)));
        let regions = ParamRegions::from([region(segment, 0x4006, &[7])]);
        let partial = full.parameters_only(&regions)?;
        let wanted = BTreeMap::from([(segment.to_string(), vec![9u8])]);

        let restore = partial.restoring(&wanted, &bussard_prod::PlacedOctets::new());
        assert_eq!(restore.changed_octets(), 1);
        assert_eq!(restore.image_bytes(segment), Some(&[9u8][..]));
        assert!(restore.unwritten_bits().is_empty());

        let skip = bussard_prod::PlacedOctets::from([(
            segment.to_string(),
            std::collections::BTreeSet::from([0usize]),
        )]);
        let restore = partial.restoring(&wanted, &skip);
        assert_eq!(restore.changed_octets(), 0);
        assert_eq!(restore.image_bytes(segment), Some(&[7u8][..]));
        assert_eq!(
            restore.unwritten_bits().get(segment).map(Vec::as_slice),
            Some(&[(0usize, 9u8 ^ 7)][..])
        );
        assert_eq!(restore.model_image(segment), Some(vec![9u8]));
        Ok(())
    }

    #[test]
    fn test_changed_octets_zero_when_the_device_already_matches()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = fabricated_app();
        let full = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let regions = ParamRegions::from([region("M-1_A-1_RS-2", 0x4006, &[7])]);
        assert_eq!(full.parameters_only(&regions)?.changed_octets(), 0);
        Ok(())
    }
}
