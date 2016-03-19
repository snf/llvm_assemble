extern crate libc;

pub mod assembler;
pub use assembler::{Arch, Reloc, assemble, assemble2};

#[test]
fn x86_int3() {
    assert_eq!(assemble(Arch::X86, "int3").unwrap(), [0xcc]);
}

#[test]
fn x86_jcc() {
    let bytes = assemble(Arch::X86_64, "nop; jz label0; nop; nop; label0:").unwrap();
    assert_eq!(bytes, [0x90, 0x74, 0x02, 0x90, 0x90]);
}


#[test]
fn x86_je() {
    let bytes = assemble(Arch::X86_64, "je label0;label0:").unwrap();
    assert_eq!(bytes, [0x74, 0x00]);
}

#[test]
fn x86_jmp_rel() {
    let addr = 0x1000;
    let label0 = Reloc::new("label0", 0x1003);
    let bytes = assemble2(Arch::X86_64, "jmp label0", addr, &[label0]).unwrap();
    assert_eq!(bytes, [0xeb, 0x01]);
}

#[test]
fn missing_label() {
    assert_eq!(assemble(Arch::X86_64, "jz label0"), None);
}

#[test]
fn test_x86_64() {
    assert_eq!(assemble(Arch::X86_64, "vandnps ymm0,ymm1,ymm2").unwrap(),
               [0xC5, 0xF4, 0x55, 0xC2]);
}

#[test]
fn test_arm() {
    assert_eq!(assemble(Arch::Arm, "ldrb r3, [r1], #1").unwrap(),
               [0x01, 0x30, 0xd1, 0xe4]);

    assert_eq!(assemble(Arch::Arm, "pop {pc}").unwrap(),
               [0x4, 0xf0, 0x9d, 0xe4]);

    //assert_eq!(assemble(Arch::Arm, "b lr").unwrap(),
    //           [0x1e, 0xff, 0xff, 0x12]);
}

#[test]
fn test_arm64() {
    assert_eq!(assemble(Arch::Arm64, "mul w0, w1, w0").unwrap(),
               [0x20, 0x7c, 0x0, 0x1b]);
}

#[test]
fn test_ppc32() {
    assert_eq!(assemble(Arch::PPC32, "blr").unwrap(),
               [0x4e, 0x80, 0x0, 0x20]);
}

// #[test]
// fn test_mips() {
//     assert_eq!(assemble(Arch::Mips, "sw $s0, 4($sp)").unwrap(),
//                [0x01, 0x30, 0xd1, 0xe4]);
// }
