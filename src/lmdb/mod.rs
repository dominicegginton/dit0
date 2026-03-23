use lmdb::{Database, Environment};
use std::path::Path;
use std::sync::Arc;

use crate::config::Config;

pub fn init(config: &Config) -> anyhow::Result<(Arc<Environment>, Database, Database)> {
    let lmdb_dir: std::path::PathBuf = std::path::Path::new(&config.data_dir).join("lmdb");
    std::fs::create_dir_all(&lmdb_dir).expect("Failed to create lmdb directory");

    let env = Environment::new()
        .set_max_dbs(3)
        .set_map_size(10 * 1024 * 1024)
        .open(&lmdb_dir)
        .expect("Failed to open LMDB environment");

    let flags = lmdb::DatabaseFlags::empty();

    let otp_db = env
        .create_db(Some("otp"), flags)
        .expect("Failed to create OTP database");
    let lockout_db = env
        .create_db(Some("lockouts"), flags)
        .expect("Failed to create lockouts database");

    Ok((Arc::new(env), otp_db, lockout_db))
}
