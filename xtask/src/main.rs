use anyhow::Context;
use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

fn main() -> anyhow::Result<()> {
    let out_file = PathBuf::from("kernel-eye-ebpf/src/bindings.rs");

    // Sadece task_struct yapısını üretiyoruz.
    let bindings = aya_tool::generate::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &["task_struct"],
        &[],
    )
    .context("BTF verisinden binding üretilemedi.")?;

    let mut file = File::create(&out_file)?;
    file.write_all(bindings.as_bytes())?;

    println!("Başarıyla üretildi: {:?}", out_file);
    Ok(())
}
