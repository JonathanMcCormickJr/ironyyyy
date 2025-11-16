use argon2::{Argon2, Params};

#[cfg(test)]
const ARGON2_MEMORY_COST: u32 = 1024; // smaller for faster tests
#[cfg(not(test))]
const ARGON2_MEMORY_COST: u32 = 65536; // larger for enhanced security

#[cfg(test)]
const ARGON2_TIME_COST: u32 = 1; // smaller for faster tests
#[cfg(not(test))]
const ARGON2_TIME_COST: u32 = 8; // larger for enhanced security

/// # Argon2 Parameters
/// Returns Argon2 parameters configured for secure password hashing and key derivation.
fn argon2_params() -> Result<Params, argon2::Error> {
    Ok(Params::new(
        ARGON2_MEMORY_COST, // memory cost in KiB
        ARGON2_TIME_COST,    // time cost
        1,    // parallelism
        None, // output length (default is 32 bytes)
    )?)
}

/// # Argon Instance
/// Returns a configured Argon2 instance for password hashing and key derivation.
pub fn argon2_instance<'a>() -> Result<Argon2<'a>, argon2::Error> {
    let params = argon2_params()?;
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    ))
}
