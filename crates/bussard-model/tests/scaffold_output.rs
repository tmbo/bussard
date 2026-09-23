//! `bussard scaffold` output must validate cleanly and satisfy the convention
//! lints of the scheme it was generated for (issue #103 acceptance criteria).

use std::error::Error;
use std::path::PathBuf;

use bussard_model::scaffold::{self, Plan, PlanRoom, Scheme};
use bussard_model::{Model, Severity, validate_in_dir};

/// A fresh, empty temp directory for one test.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bussard-scaffold-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The demo plan: two floors, five rooms, every supported function.
fn demo_plan() -> Plan {
    let rooms = [
        (
            "Ground floor",
            "Kitchen",
            vec!["light", "light-dim", "blind", "heating"],
        ),
        (
            "Ground floor",
            "Living room",
            vec!["light-dim", "blind", "heating", "socket"],
        ),
        ("Ground floor", "Hall", vec!["light"]),
        ("First floor", "Bedroom", vec!["light", "blind", "heating"]),
        ("First floor", "Bath", vec!["light", "heating"]),
    ];
    Plan {
        rooms: rooms
            .into_iter()
            .map(|(floor, room, functions)| PlanRoom {
                floor: floor.to_string(),
                room: room.to_string(),
                functions: functions.into_iter().map(str::to_string).collect(),
            })
            .collect(),
    }
}

/// Scaffolds the demo plan into a fresh directory and validates the result.
fn scaffold_and_validate(tag: &str, scheme: Scheme) -> Result<(), Box<dyn Error>> {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n  gateway: \"127.0.0.1:3671\"\n",
    )?;

    let plan = demo_plan();
    let report = scaffold::scaffold_file(&dir.join("groups.yaml"), &plan, scheme)?;
    assert!(!report.added.is_empty(), "the demo plan must add addresses");
    scaffold::ensure_lint_config(&dir.join("bussard.yaml"), scheme, &report.trades_used)?;

    let model = Model::load(&dir)?;
    assert!(
        model.config.lint.is_some(),
        "the scaffolder must have written a lint: block"
    );
    let diags = validate_in_dir(&model, &dir);

    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "scaffold output must validate: {errors:?}"
    );

    let lints: Vec<_> = diags.iter().filter(|d| d.code.starts_with('L')).collect();
    assert!(
        lints.is_empty(),
        "scaffold output must satisfy its own convention lints: {lints:?}"
    );

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_floor_trade_block_output_passes_validate_and_lints() -> Result<(), Box<dyn Error>> {
    scaffold_and_validate("ftb", Scheme::FloorTradeBlock)
}

#[test]
fn test_function_floor_output_passes_validate_and_lints() -> Result<(), Box<dyn Error>> {
    scaffold_and_validate("ff", Scheme::FunctionFloor)
}

#[test]
fn test_rerun_on_an_extended_plan_keeps_every_address() -> Result<(), Box<dyn Error>> {
    let dir = temp_dir("extend");
    std::fs::create_dir_all(&dir)?;
    let groups_path = dir.join("groups.yaml");

    let first = scaffold::scaffold_file(&groups_path, &demo_plan(), Scheme::FloorTradeBlock)?;

    let mut extended = demo_plan();
    extended.rooms.push(PlanRoom {
        floor: "Basement".to_string(),
        room: "Workshop".to_string(),
        functions: vec!["light".to_string(), "socket".to_string()],
    });
    let second = scaffold::scaffold_file(&groups_path, &extended, Scheme::FloorTradeBlock)?;

    for added in &first.added {
        let Some(group) = second.groups.groups.get(&added.address) else {
            panic!("{} disappeared on the second run", added.address);
        };
        assert_eq!(group.name, added.name, "{} was renamed", added.address);
    }
    assert!(
        !second.added.is_empty(),
        "the new room must have added addresses"
    );
    for added in &second.added {
        assert!(
            added.name.starts_with("Basement Workshop"),
            "only the new room may gain addresses, got {}",
            added.name
        );
    }

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_lint_config_is_written_once() -> Result<(), Box<dyn Error>> {
    let dir = temp_dir("lintcfg");
    std::fs::create_dir_all(&dir)?;
    let config = dir.join("bussard.yaml");
    std::fs::write(&config, "connection:\n  transport: routing\n")?;

    assert!(scaffold::ensure_lint_config(
        &config,
        Scheme::FloorTradeBlock,
        &["light"]
    )?);
    let after_first = std::fs::read_to_string(&config)?;
    assert!(
        !scaffold::ensure_lint_config(&config, Scheme::FloorTradeBlock, &["light"])?,
        "a second run must not append a second lint: block"
    );
    assert_eq!(after_first, std::fs::read_to_string(&config)?);
    assert!(after_first.contains("transport: routing"), "{after_first}");

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
