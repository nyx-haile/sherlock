use anyhow::{anyhow, Context, Result};
use include_dir::{include_dir, Dir};
use std::path::{Path, PathBuf};

static SKILL_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/skills/sherlock-analyze");

pub fn default_dest() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve HOME directory"))?;
    Ok(home.join(".claude").join("skills").join("sherlock-analyze"))
}

pub fn install(dest: &Path, force: bool) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("create skill dest {}", dest.display()))?;
    let mut written = Vec::new();
    write_dir(&SKILL_DIR, dest, force, &mut written)?;
    Ok(written)
}

fn write_dir(dir: &Dir, dest: &Path, force: bool, written: &mut Vec<PathBuf>) -> Result<()> {
    for sub in dir.dirs() {
        let name = sub
            .path()
            .file_name()
            .ok_or_else(|| anyhow!("bad embedded dir name"))?;
        let target = dest.join(name);
        std::fs::create_dir_all(&target)?;
        write_dir(sub, &target, force, written)?;
    }
    for file in dir.files() {
        let name = file
            .path()
            .file_name()
            .ok_or_else(|| anyhow!("bad embedded file name"))?;
        let target = dest.join(name);
        if target.exists() && !force {
            return Err(anyhow!(
                "{} already exists; pass --force to overwrite",
                target.display()
            ));
        }
        std::fs::write(&target, file.contents())
            .with_context(|| format!("write {}", target.display()))?;
        written.push(target);
    }
    Ok(())
}
