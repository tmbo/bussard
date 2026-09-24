//! The Dynamic section's container structure and what the evaluated tree
//! reports about it: channel and block placements, module ordinals, the visible
//! ref per parameter and label substitution. Parses the fabricated
//! `dynamic_tree.app.xml` fixture (no vendor content).

use std::collections::BTreeMap;

use bussard_ets::application::{
    ApplicationProgram, DynamicNode, flatten_containers, parse_application_program,
};
use bussard_ets::dynamic::{DynamicConfig, evaluate_dynamic, visible_parameter_refs};
use bussard_ets::label::substitute_label;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_ID: &str = "M-00FA_A-00D1-10-0001";

fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
    let xml = include_bytes!("fixtures/dynamic_tree.app.xml");
    Ok(parse_application_program(APP_ID, xml)?)
}

fn evaluate(app: &ApplicationProgram, overrides: &[(&str, &str)]) -> DynamicConfig {
    let overrides: BTreeMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    evaluate_dynamic(app, &overrides)
}

/// The index of `(module, ref)` in `config.parameters`.
fn param_index(config: &DynamicConfig, module: Option<usize>, param_ref: &str) -> Option<usize> {
    config
        .parameters
        .iter()
        .position(|p| p.module == module && p.param_ref_id == param_ref)
}

fn block_ids(config: &DynamicConfig, index: usize) -> Vec<&str> {
    config.parameter_placements[index]
        .blocks
        .iter()
        .map(|b| b.id.as_str())
        .collect()
}

#[test]
fn test_parse_application_program_channel_number_and_label_ref() -> TestResult {
    let app = app()?;
    let ch = app.channel_ref("CH-1").ok_or("CH-1 missing")?;
    assert_eq!(ch.id, "CH-1");
    assert_eq!(ch.number, Some(7));
    assert_eq!(ch.name.as_deref(), Some("Heating"));
    // The en-US translation applies to the channel ref ...
    assert_eq!(ch.text.as_deref(), Some("Heating ({{0:...}})"));
    assert_eq!(ch.text_parameter_ref.as_deref(), Some("P-1_R-1"));
    // ... while the legacy ChannelDef keeps the raw attribute.
    let def = app.channel("CH-1").ok_or("ChannelDef missing")?;
    assert_eq!(def.text.as_deref(), Some("Heizung ({{0:...}})"));

    let md = app.channel_ref("MD-1_CH-1").ok_or("MD-1_CH-1 missing")?;
    assert_eq!(md.number, Some(1));
    assert_eq!(md.text_parameter_ref.as_deref(), Some("MD-1_P-1_R-1"));
    Ok(())
}

#[test]
fn test_parse_application_program_com_object_ref_and_parameter_ref_texts() -> TestResult {
    let app = app()?;
    let cref = app
        .com_object_refs
        .get(&format!("{APP_ID}_O-0_R-1"))
        .ok_or("com-object ref missing")?;
    assert_eq!(cref.text_parameter_ref.as_deref(), Some("P-1_R-1"));

    let text = |r: &str| app.parameter_ref(r).and_then(|p| p.text.as_deref());
    assert_eq!(text("P-2_R-2"), Some("Delay when off"));
    // Translated override.
    assert_eq!(text("P-2_R-3"), Some("Heating delay"));
    assert_eq!(text("P-1_R-1"), None);
    Ok(())
}

#[test]
fn test_parse_application_program_keeps_channel_and_block_containers() -> TestResult {
    let app = app()?;
    // Channel CH-1 (the empty PB-9 dropped) plus the two modules of the
    // flattened ChannelIndependentBlock.
    assert_eq!(app.dynamic.len(), 3);
    let DynamicNode::Channel {
        id,
        number,
        text_parameter_ref,
        children,
        ..
    } = &app.dynamic[0]
    else {
        return Err(format!("expected a channel, got {:?}", app.dynamic[0]).into());
    };
    assert_eq!((id.as_str(), *number), ("CH-1", Some(7)));
    assert_eq!(text_parameter_ref.as_deref(), Some("P-1_R-1"));
    assert_eq!(children.len(), 1);
    let DynamicNode::ParameterBlock {
        id,
        text,
        text_parameter_ref,
        ..
    } = &children[0]
    else {
        return Err("expected a parameter block".into());
    };
    assert_eq!(id, "PB-1");
    assert_eq!(text.as_deref(), Some("Main {{0}}"));
    assert_eq!(text_parameter_ref.as_deref(), Some("P-1_R-1"));
    assert!(matches!(&app.dynamic[1], DynamicNode::Module { id, .. } if id == "MD-1_M-2"));

    let flat = flatten_containers(&app.dynamic);
    assert_eq!(flat[0], DynamicNode::ParameterRefRef("P-1_R-1".into()));
    assert!(flat.iter().all(|n| !matches!(
        n,
        DynamicNode::Channel { .. } | DynamicNode::ParameterBlock { .. }
    )));
    Ok(())
}

#[test]
fn test_evaluate_dynamic_containers_are_transparent() -> TestResult {
    let app = app()?;
    let mut flat = app.clone();
    flat.dynamic = flatten_containers(&app.dynamic);
    for body in flat.module_dynamics.values_mut() {
        *body = flatten_containers(body);
    }
    for overrides in [vec![], vec![("P-3_R-4", "0")]] {
        let a = evaluate(&app, &overrides);
        let b = evaluate(&flat, &overrides);
        assert_eq!(a.parameters, b.parameters);
        assert_eq!(a.com_objects, b.com_objects);
        assert_eq!(a.modules, b.modules);
    }
    Ok(())
}

#[test]
fn test_evaluate_dynamic_block_paths_and_channel() -> TestResult {
    let app = app()?;
    let config = evaluate(&app, &[]);
    assert_eq!(config.parameter_placements.len(), config.parameters.len());
    assert_eq!(config.com_object_placements.len(), config.com_objects.len());

    let i = param_index(&config, None, "P-1_R-1").ok_or("P-1_R-1 not active")?;
    let place = &config.parameter_placements[i];
    assert_eq!(place.channel.as_ref().map(|c| c.id.as_str()), Some("CH-1"));
    assert_eq!(block_ids(&config, i), ["PB-1"]);
    assert!(place.shown);
    assert_eq!(place.module, None);

    let i = param_index(&config, None, "P-2_R-3").ok_or("P-2_R-3 not active")?;
    assert_eq!(block_ids(&config, i), ["PB-1", "PB-2"]);

    let i = param_index(&config, None, "P-4_R-6").ok_or("P-4_R-6 not active")?;
    assert_eq!(block_ids(&config, i), ["PB-1", "PB-2", "PB-3"]);
    let pb3 = &config.parameter_placements[i].blocks[2];
    assert_eq!(pb3.param_ref.as_deref(), Some("P-4_R-6"));
    assert_eq!(pb3.text, None);

    let c = &config.com_object_placements[0];
    assert_eq!(config.com_objects[0].com_object_ref_id, "O-0_R-1");
    assert_eq!(c.channel.as_ref().map(|c| c.number), Some(Some(7)));
    assert_eq!(c.blocks.len(), 1);

    // The Assign-only parameter is written but not shown; it sits where the
    // Assign is.
    let i = param_index(&config, None, "P-5_R-7").ok_or("P-5_R-7 not active")?;
    assert!(!config.parameter_placements[i].shown);
    assert_eq!(block_ids(&config, i), ["PB-1"]);
    Ok(())
}

#[test]
fn test_evaluate_dynamic_module_channel_instances_and_ordinals() -> TestResult {
    let app = app()?;
    let config = evaluate(&app, &[]);
    let ids: Vec<(&str, u32)> = config
        .modules
        .iter()
        .map(|m| (m.id.as_str(), m.ordinal))
        .collect();
    // Walk order is document order (M-2 first); ordinals follow M-<m>.
    assert_eq!(ids, [("MD-1_M-2", 2), ("MD-1_M-1", 1)]);

    for (module, instance, ordinal) in [(0, "MD-1_M-2", 2), (1, "MD-1_M-1", 1)] {
        let i = param_index(&config, Some(module), "MD-1_P-2_R-2").ok_or("module param")?;
        let place = &config.parameter_placements[i];
        let ch = place.channel.as_ref().ok_or("no channel")?;
        assert_eq!((ch.id.as_str(), ch.number), ("MD-1_CH-1", Some(1)));
        assert_eq!(block_ids(&config, i), ["MD-1_PB-1"]);
        assert_eq!(place.module, Some(module));
        assert_eq!(place.module_instance.as_deref(), Some(instance));
        assert_eq!(place.module_ordinal, Some(ordinal));
    }
    Ok(())
}

#[test]
fn test_visible_parameter_refs_skips_inactive_branch_and_records_alternatives() -> TestResult {
    let app = app()?;
    let config = evaluate(&app, &[]);
    let visible = visible_parameter_refs(&app, &config);
    let find = |key: &str| visible.iter().find(|v| v.key == key);

    let p2 = find("P-2").ok_or("P-2 not visible")?;
    assert_eq!(p2.param_ref_id, "P-2_R-3");
    assert!(p2.alternatives.is_empty());

    let p4 = find("P-4").ok_or("P-4 not visible")?;
    assert_eq!(p4.param_ref_id, "P-4_R-5");
    assert_eq!(p4.alternatives, ["P-4_R-6"]);

    let p5 = find("P-5").ok_or("P-5 not visible")?;
    assert_eq!(p5.param_ref_id, "P-5_R-7");

    let m = find("MD-1_M-2_MI-1_P-1").ok_or("module parameter not visible")?;
    assert_eq!(m.parameter_id, "MD-1_P-1");
    assert_eq!(m.ref_key, "MD-1_M-2_MI-1_P-1_R-1");
    assert_eq!(m.module, Some(0));
    assert!(find("MD-1_M-1_MI-1_P-1").is_some());

    // One entry per parameter and instance: 5 application parameters and two
    // per module instance.
    assert_eq!(visible.len(), 5 + 2 * 2);
    assert!(visible.windows(2).all(|w| w[0].index < w[1].index));

    // Switching the mode to 0 takes the other branch and its ref.
    let config = evaluate(&app, &[("P-3_R-4", "0")]);
    let visible = visible_parameter_refs(&app, &config);
    let p2 = visible.iter().find(|v| v.key == "P-2").ok_or("P-2")?;
    assert_eq!(p2.param_ref_id, "P-2_R-2");
    Ok(())
}

#[test]
fn test_dynamic_config_label_and_substitution() -> TestResult {
    let app = app()?;
    let config = evaluate(&app, &[("MD-1_M-1_MI-1_P-1_R-1", "Left")]);
    assert_eq!(
        config.label(&app, None, "P-1_R-1").as_deref(),
        Some("Kitchen")
    );
    // An enumeration label reads its text.
    assert_eq!(
        config.label(&app, None, "P-3_R-4").as_deref(),
        Some("Heating")
    );

    let ch = app.channel_ref("CH-1").ok_or("CH-1")?;
    let text = ch.text.as_deref().ok_or("no text")?;
    let label = config.label(&app, None, "P-1_R-1");
    assert_eq!(
        substitute_label(text, label.as_deref()),
        "Heating (Kitchen)"
    );

    // Module channel: the label is read in the instance the channel sits in.
    let m1 = config
        .modules
        .iter()
        .position(|m| m.id == "MD-1_M-1")
        .ok_or("M-1")?;
    let m2 = config
        .modules
        .iter()
        .position(|m| m.id == "MD-1_M-2")
        .ok_or("M-2")?;
    let md = app.channel_ref("MD-1_CH-1").ok_or("MD-1_CH-1")?;
    let text = md.text.as_deref().ok_or("no text")?;
    let tpr = md.text_parameter_ref.as_deref();
    assert_eq!(
        config.labelled_text(&app, Some(m1), text, tpr),
        "Output {{ArgBeschriftung}} (Left)"
    );
    // Empty default: no label, the placeholder stays for the caller.
    assert_eq!(config.label(&app, Some(m2), "MD-1_P-1_R-1"), None);
    assert_eq!(config.labelled_text(&app, Some(m2), text, tpr), text);

    // Com-object ref text with a label.
    let cref = app
        .com_object_refs
        .get(&format!("{APP_ID}_O-0_R-1"))
        .ok_or("cref")?;
    let text = cref.text.as_deref().ok_or("no text")?;
    assert_eq!(
        config.labelled_text(&app, None, text, cref.text_parameter_ref.as_deref()),
        "Switch (Kitchen)"
    );
    Ok(())
}
