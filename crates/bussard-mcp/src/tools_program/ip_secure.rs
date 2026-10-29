//! `knx_interface_secure` (issue #398): KNXnet/IP Secure on or off for a KNX
//! IP interface, with the plan, digest and explicit-yes flow of the
//! programming tier. The plan, the wire sequence, the read-back and the key
//! store handling are [`bussard_service::ip_secure`]'s, the same functions
//! `bussard interface secure on|off` calls.
//!
//! Refused when the server's session is a KNXnet/IP Secure session with the
//! target interface itself: the switch restarts the interface and ends the
//! session the server runs on. The owner runs it in a terminal instead.

use bussard_model::IndividualAddress;
use bussard_project::KeyStore;
use bussard_service::ip_secure::{
    Switch, SwitchContext, SwitchPlan, interface_digest_text, plan_off, plan_on, probe_gateway,
    run_switch, secured_through,
};
use bussard_service::secure::KEYRING_PASSWORD_ENV;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::BussardMcp;

/// The plan digest of a switch: the target, the direction, the step lines
/// and the names of the generated credentials (never a value).
fn digest(plan: &SwitchPlan) -> String {
    let full: [u8; 32] = Sha256::digest(interface_digest_text(plan)).into();
    full.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

impl BussardMcp {
    /// Plans, or with `plan_digest` runs, a KNXnet/IP Secure switch.
    pub(super) async fn interface_secure(
        &self,
        address: &str,
        state: &str,
        plan_digest: Option<&str>,
    ) -> Result<Value, String> {
        let (tier, _service, gateway) = self.programming_preflight()?;
        let target: IndividualAddress = address
            .trim()
            .parse()
            .map_err(|e| format!("not an individual address: {e}"))?;
        let switch = match state.trim().to_ascii_lowercase().as_str() {
            "on" => Switch::On,
            "off" => Switch::Off,
            other => return Err(format!("state must be `on` or `off`, got `{other}`")),
        };
        let model = self.state().model.reload();
        let dir = self.state().dir.clone();
        let Some(knxnet) = bussard_service::knxnet::interface_config(&model, target) else {
            return Err(format!(
                "{target} is not planned as a KNX IP interface (devices/{target}.toml needs a \
                 [knxnet] table and no links)"
            ));
        };
        let password = bussard_model::dotenv::var(KEYRING_PASSWORD_ENV)
            .map_err(|_| format!("the key store needs {KEYRING_PASSWORD_ENV}"))?;
        let store = KeyStore::load(&dir, &password)
            .map_err(|e| format!("loading the key store: {e}"))?
            .ok_or_else(|| {
                "no key store (bussard.keys): the interface's FDSK and credentials live there; \
                 import the ETS keyring export with `bussard keys import`"
                    .to_string()
            })?;
        let mut plan = match switch {
            Switch::On => plan_on(&store, target, &knxnet.tunnels),
            Switch::Off => plan_off(&store, target),
        }
        .map_err(|e| e.to_string())?;
        let probed = probe_gateway(&tier.connection).await;
        let gateway_ia = probed.and_then(|(ia, _)| ia);
        if secured_through(&tier.connection, probed, target) {
            return Err(format!(
                "the server's session is a KNXnet/IP Secure session with {target} itself; the \
                 switch restarts {target} and ends it. Run `bussard interface secure {switch} \
                 {target}` in a terminal instead."
            ));
        }
        if switch == Switch::On && gateway_ia == Some(target) && probed.is_some_and(|(_, s)| s) {
            return Err(format!(
                "{target} already runs KNXnet/IP Secure (tunnelling is secure-only)"
            ));
        }
        let digest = digest(&plan);
        let Some(given) = plan_digest else {
            return Ok(json!({
                "ok": true,
                "address": target.to_string(),
                "switch": switch,
                "steps": plan.lines(),
                "generated": plan.generated,
                "question": format!(
                    "Switch KNXnet/IP Secure {switch} on {target} via {gateway}? It restarts \
                     the interface{}.",
                    if plan.generated.is_empty() {
                        String::new()
                    } else {
                        format!(" and first adds to the key store: {}", plan.generated.join(", "))
                    }
                ),
                "plan_digest": digest,
            }));
        };
        if given != digest {
            return Err(format!(
                "the plan_digest {given} does not match the current plan ({digest}); plan again \
                 and ask again"
            ));
        }
        let _guard = tier.bus_lock.lock().await;
        let ctx = SwitchContext {
            config: tier.connection.clone(),
            policy: bussard_service::WritePolicy::transmit(tier.allow_remote_gateway),
            skip_address_check: false,
            dir: &dir,
            keystore_password: &password,
            connect_wait: std::time::Duration::from_secs(10),
        };
        let mut steps_done = Vec::new();
        let mut progress = |line: &str| steps_done.push(line.to_string());
        match run_switch(&ctx, &mut plan, &store, &mut progress).await {
            Ok(outcome) => Ok(json!({
                "ok": outcome.verified(switch),
                "verified": outcome.verified(switch),
                "address": target.to_string(),
                "switch": switch,
                "steps": steps_done,
                "generated": plan.generated,
                "security_mode": outcome.verification.security_mode,
                "tunnel_users": outcome.verification.tunnel_users,
                "gateway_secure_only": outcome.gateway_secure_only,
                "mismatches": outcome.verification.mismatches,
                "key_store_updated": outcome.store_saved_before || outcome.store_saved_after,
            })),
            Err(err) => Ok(json!({
                "ok": false,
                "verified": false,
                "address": target.to_string(),
                "switch": switch,
                "steps": steps_done,
                "error": err.to_string(),
                "recovery": format!(
                    "the key store holds the credentials {target} was given and its FDSK; retry, \
                     or factory-reset {target} and switch it on again (docs/explanation/safety.md)"
                ),
            })),
        }
    }
}
