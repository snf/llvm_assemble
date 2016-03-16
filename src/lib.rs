extern crate libc;

pub mod assembler;
pub use assembler::{Arch, Reloc, assemble, assemble2};

#[test]
fn x86_int3() {
    assert_eq!(assemble(Arch::X86, "int3").unwrap(), [0xcc]);
}

#[test]
fn x86_jcc() {
    let bytes = assemble(Arch::X86_64, "nop; jz here; nop; nop; here:").unwrap();
    assert_eq!(bytes, [0x90, 0x74, 0x02, 0x90, 0x90]);
}


#[test]
fn x86_je() {
    let bytes = assemble(Arch::X86_64, "je here;here:").unwrap();
    assert_eq!(bytes, [0x74, 0x00]);
}

#[test]
fn x86_jmp_rel() {
    let addr = 0x1000;
    let reloc = Reloc::new("here", 0x1003);
    let bytes = assemble2(Arch::X86_64, "jmp here", addr, &[reloc]).unwrap();
    assert_eq!(bytes, [0xeb, 0x01]);
}

#[test]
fn missing_label() {
    assert_eq!(assemble(Arch::X86_64, "jz here"), None);
}
