use std::env;
use std::fs;
use std::path::PathBuf;

fn parse_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    println!("cargo:rerun-if-env-changed={name}");
    match env::var(name) {
        Ok(s) => s
            .parse()
            .unwrap_or_else(|_| panic!("{name}: cannot parse as {}", std::any::type_name::<T>())),
        Err(_) => default,
    }
}

fn main() {
    // Pool composition: N iso7816 cards + M infnoise devices, plus
    // per-source per-round oversampling. Matches the meson options of the
    // original C build.
    let n_iso: usize = parse_or("P11RAND_ISO7816_CARDS", 1);
    let n_inf: usize = parse_or("P11RAND_INFNOISE_DEVICES", 0);
    let iso_in: usize = parse_or("P11RAND_ISO7816_INPUT_BYTES", 32);
    let inf_in: usize = parse_or("P11RAND_INFNOISE_INPUT_BYTES", 32);

    if n_iso + n_inf < 1 {
        panic!("Need at least one source: P11RAND_ISO7816_CARDS or P11RAND_INFNOISE_DEVICES >= 1");
    }
    if n_iso > 0 && (iso_in < 32 || !iso_in.is_multiple_of(32)) {
        panic!("P11RAND_ISO7816_INPUT_BYTES must be >= 32 and a multiple of 32 (got {iso_in})");
    }
    if n_inf > 0 && (inf_in < 32 || !inf_in.is_multiple_of(32)) {
        panic!("P11RAND_INFNOISE_INPUT_BYTES must be >= 32 and a multiple of 32 (got {inf_in})");
    }

    let pool_size = n_iso + n_inf;
    let iso_oversampled = n_iso > 0 && iso_in > 32;
    let inf_oversampled = n_inf > 0 && inf_in > 32;
    let use_chain = pool_size > 1 || iso_oversampled || inf_oversampled;

    println!(
        "cargo:warning=p11rand: pool iso={n_iso}, infnoise={n_inf} (total {pool_size}); chain={use_chain}; per-round iso={iso_in} B inf={inf_in} B"
    );

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR");
    let path = PathBuf::from(out_dir).join("config.rs");
    fs::write(
        &path,
        format!(
            "pub const ISO7816_CARDS: usize = {n_iso};\n\
             pub const INFNOISE_DEVICES: usize = {n_inf};\n\
             pub const ISO7816_INPUT_BYTES: usize = {iso_in};\n\
             pub const INFNOISE_INPUT_BYTES: usize = {inf_in};\n",
        ),
    )
    .expect("write config.rs");

    // Export the module under its conventional name regardless of cargo's
    // `lib` prefix. We also set the SONAME so dlopen-by-soname works.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libp11rand.so.0");
}
