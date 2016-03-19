# LLVM_Assemble

[![Build Status](https://travis-ci.org/snf/llvm_assemble.svg?branch=master)](https://travis-ci.org/snf/llvm_assemble)


Use LLVM to compile different assembly languages to binary (Rust API).

It (ab)uses LLVM architecture to insert a BinaryStreamer during the
ASM parsing run and output the binary code to a buffer instead of an
object file. It supports inline and external labels/relocations too.

## Use it

It depends on LLVM >= 3.7, zlib and libedit.

In Cargo.toml write:

```
[dependencies.llvm_assemble]
git = "https://github.com/snf/llvm_assemble.git"
```

## Examples

Basic:

```rust
use llvm_assemble::assembler::{Arch, assemble};

fn main() {
    assert_eq!(assemble(Arch::X86, "int3").unwrap(),
               [0xcc]);

    assert_eq!(assemble(Arch::X86_64, "vandnps ymm0,ymm1,ymm2").unwrap(),
               [0xC5, 0xF4, 0x55, 0xC2]);

    assert_eq!(assemble(Arch::X86_64, "je label0; nop; label0:").unwrap(),
               [0x74, 0x01, 0x90]);

    assert_eq!(assemble(Arch::Arm, "ldrb r3, [r1], #1").unwrap(),
               [0x01, 0x30, 0xd1, 0xe4]);

    assert_eq!(assemble(Arch::Arm, "pop {pc}").unwrap(),
               [0x4, 0xf0, 0x9d, 0xe4]);

    assert_eq!(assemble(Arch::Arm64, "mul w0, w1, w0").unwrap(),
               [0x20, 0x7c, 0x0, 0x1b]);

    assert_eq!(assemble(Arch::PPC32, "blr").unwrap(),
               [0x4e, 0x80, 0x0, 0x20]);
}
```

With external relocations:

```rust
use llvm_assemble::assembler::{Arch, Reloc, assemble2};

fn main() {
    let addr = 0x1000;
    let label0 = Reloc::new("label0", 0x1003);
    let bytes = assemble2(Arch::X86_64, "jmp label0", addr, &[label0]).unwrap();
    assert_eq!(bytes, [0xeb, 0x01]);
}

```

## Full disclosure

This was coded as a part of a bigger project and while it works, it is
not really tested in architectures other than x86, x86_64 and ARM. Use
at your own risk of finding bugs.