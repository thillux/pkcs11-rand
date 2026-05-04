use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static CHECKED: AtomicBool = AtomicBool::new(false);

pub fn enabled() -> bool {
    if !CHECKED.swap(true, Ordering::Relaxed)
        && std::env::var_os("P11RAND_DEBUG").is_some()
    {
        ENABLED.store(true, Ordering::Relaxed);
    }
    ENABLED.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! logd {
    ($prefix:expr, $($arg:tt)*) => {{
        if $crate::debug::enabled() {
            eprint!("p11rand[{}]: ", $prefix);
            eprintln!($($arg)*);
        }
    }};
}
