use zkm_build::{build_program_with_args, BuildArgs};

/// `ZKAPI_PROFILE=1` builds the guests with cycle-tracker scopes (feature `profile`); their
/// ELFs, and so their vkeys, differ from the production guests'. Use a separate
/// `CARGO_TARGET_DIR` for it, so the production ELFs are not overwritten.
fn main() {
    println!("cargo:rerun-if-env-changed=ZKAPI_PROFILE");
    let features = if std::env::var("ZKAPI_PROFILE").as_deref() == Ok("1") {
        vec!["profile".to_string()]
    } else {
        vec![]
    };
    for guest in ["../guest/request", "../guest/withdrawal"] {
        build_program_with_args(
            guest,
            BuildArgs {
                features: features.clone(),
                ..Default::default()
            },
        );
    }
}
