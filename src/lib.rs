extern crate libc;

pub mod assembler;
pub use assembler::{Arch, assemble};

#[test]
fn x86_int3() {
    assert_eq!(assemble(Arch::X86, "int3").unwrap(), [0xcc]);
}
