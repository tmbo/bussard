//! Discover KNXnet/IP gateways on the local network via SEARCH_REQUEST.
//!
//! ```sh
//! cargo run -p bussard-transport --example discover
//! ```

use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface = std::env::args()
        .nth(1)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    let gateways = bussard_transport::discover(Duration::from_secs(3), interface).await?;
    if gateways.is_empty() {
        println!("no KNXnet/IP gateways found");
    } else {
        for gw in gateways {
            println!("{gw:#?}");
        }
    }
    Ok(())
}
