use rustc_version::{version_meta, Channel};
fn main() {
    println!("cargo::rustc-check-cfg=cfg(channel_dev,channel_nightly,channel_beta,channel_stable)");
    println!(
        "cargo::rustc-cfg=channel_{}",
        match version_meta().map_or(Channel::Stable, |meta| meta.channel) {
            Channel::Dev => "dev",
            Channel::Nightly => "nightly",
            Channel::Beta => "beta",
            Channel::Stable => "stable",
        }
    );
}
