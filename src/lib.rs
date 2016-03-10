extern crate libc;

pub mod assembler;
pub use assembler::{Arch, assemble};

#[test]
fn x86_int3() {
    //assert_eq!(assemble(Arch::X86, "int3").unwrap(), [0xcc]);
}

#[test]
fn x86_jcc() {
    let bytes = assemble(Arch::X86_64, "lea rax, [rbx]; jz caca;saraza: ; nop; nop;caca:").expect("couldn't compile the code");
    assert_eq!(bytes, []);
}
