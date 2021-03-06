#ifdef __cplusplus
extern "C" {
#endif

  #include <stdint.h>
  #include <stddef.h>

  // #define DEBUG

  typedef uint8_t byte;

  /*
    Supported archs by LLVM:

    aarch64    - AArch64 (little endian)
    aarch64_be - AArch64 (big endian)
    amdgcn     - AMD GCN GPUs
    arm        - ARM
    arm64      - ARM64 (little endian)
    armeb      - ARM (big endian)
    bpf        - BPF (host endian)
    bpfeb      - BPF (big endian)
    bpfel      - BPF (little endian)
    cpp        - C++ backend
    hexagon    - Hexagon
    mips       - Mips
    mips64     - Mips64 [experimental]
    mips64el   - Mips64el [experimental]
    mipsel     - Mipsel
    msp430     - MSP430 [experimental]
    nvptx      - NVIDIA PTX 32-bit
    nvptx64    - NVIDIA PTX 64-bit
    ppc32      - PowerPC 32
    ppc64      - PowerPC 64
    ppc64le    - PowerPC 64 LE
    r600       - AMD GPUs HD2XXX-HD6XXX
    sparc      - Sparc
    sparcel    - Sparc LE
    sparcv9    - Sparc V9
    systemz    - SystemZ
    thumb      - Thumb
    thumbeb    - Thumb (big endian)
    x86        - 32-bit X86: Pentium-Pro and above
    x86-64     - 64-bit X86: EM64T and AMD64
    xcore      - XCore
  */
  // We are only supporting a subset
  enum Arch {
    x86,
    x86_64,
    mips,
    mipsel,
    arm,
    armeb,
    thumb,
    arm64,
    ppc32,
    ppc64,
    sparc,
    systemz
  };

  typedef struct {
    char *name;
    uint64_t addr;
  } Reloc_A;

  void free_vec(byte *vec);
  int assemble(enum Arch arch, const char *instructions, const uint64_t addr, const Reloc_A *relocs, const size_t n_relocs, byte **out, size_t *out_len);

#ifdef __cplusplus
}
#endif
