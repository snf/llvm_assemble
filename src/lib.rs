extern crate libc;

pub mod assembler;
pub use assembler::{Arch, Reloc, assemble, assemble2};

#[test]
fn x86_int3() {
    //assert_eq!(assemble(Arch::X86, "int3").unwrap(), [0xcc]);
}

#[test]
fn x86_jcc() {
    let bytes = assemble(Arch::X86_64, "nop; jz here; nop; nop; here:").expect("couldn't compile the code");
    assert_eq!(bytes, [0x90, 0x74, 0x02, 0x90, 0x90]);
}

#[test]
fn x86_jmp_rel() {
    let addr = 0x1000;
    let reloc = Reloc::new("here", 0x1003);
    let bytes = assemble2(Arch::X86_64, "jmp here", addr, &[reloc]).expect("couldn't compile the code");
    assert_eq!(bytes, [0xeb, 0x01]);
}
