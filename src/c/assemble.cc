#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCTargetAsmParser.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"

#include <iostream>

#include "assemble.h"

using namespace llvm;

// Utils to evaluate MCExpr with Symbol

typedef struct {
  StringRef name;
  uint64_t addr;
} VReloc;

typedef struct {
  MCFixup fixup;
  size_t start_offset;
} VFixup;


class MCBinaryStreamer: public MCStreamer {
public:
  raw_ostream &OS;
  const MCAsmInfo *MAI;
  std::unique_ptr<MCCodeEmitter> Emitter;
  std::unique_ptr<MCAsmBackend> AsmBackend;
  std::vector<byte> &OutMb;
  std::vector<VFixup> VFixups;
  std::vector<VReloc> ORelocs;
  uint64_t Address;
  const Reloc_A *Relocs;
  size_t N_Relocs;
  bool *Failed;
  size_t pos = 0;

  MCBinaryStreamer(MCContext &Context, MCAsmBackend *TAB, raw_ostream &OS,
		   MCCodeEmitter *emitter, uint64_t addr, const Reloc_A *relocs,
                   size_t n_relocs, std::vector<byte> &out_mb, bool *failed)
    : MCStreamer(Context), OS(OS), MAI(Context.getAsmInfo()),
      Emitter(emitter), AsmBackend(TAB), OutMb(out_mb),
      Address(addr), Relocs(relocs), N_Relocs(n_relocs),
      Failed(failed)
  {
    OS << "starting";
    OS << '\n';
  }

  bool FindReloc(const char *name, int64_t *res) {
    for(size_t i = 0; i < N_Relocs; i++) {
      OS << Relocs[i].name << " ?= " << name << "\n";
      if (strcmp(Relocs[i].name, name) == 0) {
        *res = Relocs[i].addr;
        return true;
      }
    }
    for(VReloc reloc: ORelocs) {
      if (strcmp(reloc.name.data(), name) == 0) {
        *res = reloc.addr;
        return true;
      }
    }
    return false;
  }

  bool EvaluateFixup(VFixup *vfixup) {
    const MCExpr *expr = vfixup->fixup.getValue();
    const MCFixupKindInfo &Info =
      AsmBackend->getFixupKindInfo(vfixup->fixup.getKind());
    size_t offset = vfixup->start_offset + vfixup->fixup.getOffset();
    int64_t res = 0;

    if (EvaluateExpr(expr, &res)) {

      OS << "evalExpr ret: " << res << "\n";
      if (Info.Flags & MCFixupKindInfo::FKF_IsPCRel) {
        res -= Address;
        res -= offset;
      }

      int64_t mask = (1 << Info.TargetSize) - 1;
      if (res > mask) {
        OS << "fixup bigger than addr\n";
        return false;
      }
      res &= mask;

      OS << "after mask: " << res << "\n";
      for(size_t i = 0; i < Info.TargetSize / 8; i++) {
        size_t off = offset + i;
        uint64_t b = (res & ((1 << ((i+1) * 8)) - 1)) >> i;
        OS << "overwriting at off: " << off
           << " with value: " << b << "\n";
        OutMb[off] = b;
      }

      return true;
    } else {
      return false;
    }
  }

  bool EvaluateExpr(const MCExpr *expr, int64_t *res) {
    switch (expr->getKind()) {
    case MCExpr::ExprKind::Target: {
      // return cast<MCTargetExpr>(this)->evaluateAsRelocatableImpl(Res, Layout,
      //                                                            Fixup);
      llvm_unreachable("Target not supported");
      return false;
    }

    case MCExpr::ExprKind::Constant: {
      *res = cast<MCConstantExpr>(expr)->getValue();
      return true;
    }

    case MCExpr::ExprKind::SymbolRef: {
      const MCSymbolRefExpr *SRE = cast<MCSymbolRefExpr>(expr);
      const MCSymbol &Sym = SRE->getSymbol();

      const StringRef Name = Sym.getName();
      if (FindReloc(Name.data(), res)) {
        return true;
      } else {
        return false;
      }
      llvm_unreachable("SymbolRef not supported");
      return -1;
    }

    case MCExpr::ExprKind::Unary: {
      const MCUnaryExpr *AUE = cast<MCUnaryExpr>(expr);
      int64_t Value;

      if (!EvaluateExpr(AUE->getSubExpr(), &Value)) {
        return false;
      }

      switch (AUE->getOpcode()) {
      case MCUnaryExpr::LNot:
        *res = !Value;
        break;
      case MCUnaryExpr::Minus:
        *res = -Value;
        break;
      case MCUnaryExpr::Not:
        *res = ~Value;
        break;
      case MCUnaryExpr::Plus:
        *res = Value;
        break;
      }
      return true;
    }

    case MCExpr::ExprKind::Binary: {
      const MCBinaryExpr *ABE = cast<MCBinaryExpr>(expr);
      int64_t LHS, RHS;

      if (!EvaluateExpr(ABE->getLHS(), &LHS) ||
          !EvaluateExpr(ABE->getRHS(), &RHS)) {
        return false;
      }

      // FIXME: We need target hooks for the evaluation. It may be limited in
      // width, and gas defines the result of comparisons differently from
      // Apple as.
      switch (ABE->getOpcode()) {
      case MCBinaryExpr::AShr: *res = LHS >> RHS; break;
      case MCBinaryExpr::Add:  *res = LHS + RHS; break;
      case MCBinaryExpr::And:  *res = LHS & RHS; break;
      case MCBinaryExpr::Div:
        // Handle division by zero. gas just emits a warning and keeps going,
        // we try to be stricter.
        // FIXME: Currently the caller of this function has no way to understand
        // we're bailing out because of 'division by zero'. Therefore, it will
        // emit a 'expected relocatable expression' error. It would be nice to
        // change this code to emit a better diagnostic.
        if (RHS == 0)
          return false;
        *res = LHS / RHS;
        break;
      case MCBinaryExpr::EQ:   *res = LHS == RHS; break;
      case MCBinaryExpr::GT:   *res = LHS > RHS; break;
      case MCBinaryExpr::GTE:  *res = LHS >= RHS; break;
      case MCBinaryExpr::LAnd: *res = LHS && RHS; break;
      case MCBinaryExpr::LOr:  *res = LHS || RHS; break;
      case MCBinaryExpr::LShr: *res = uint64_t(LHS) >> uint64_t(RHS); break;
      case MCBinaryExpr::LT:   *res = LHS < RHS; break;
      case MCBinaryExpr::LTE:  *res = LHS <= RHS; break;
      case MCBinaryExpr::Mod:  *res = LHS % RHS; break;
      case MCBinaryExpr::Mul:  *res = LHS * RHS; break;
      case MCBinaryExpr::NE:   *res = LHS != RHS; break;
      case MCBinaryExpr::Or:   *res = LHS | RHS; break;
      case MCBinaryExpr::Shl:  *res = uint64_t(LHS) << uint64_t(RHS); break;
      case MCBinaryExpr::Sub:  *res = LHS - RHS; break;
      case MCBinaryExpr::Xor:  *res = LHS ^ RHS; break;
      }

      return true;
    }
    }

    llvm_unreachable("Invalid assembly expression kind!");
    return false;
  }

  void FinishImpl() {
    // for (Label label: VLabels) {
    //   OS << "fixing label: " << label.name;
    //   OS << " offset: " << label.offset;
    //   OS << "\n";
    // }
    // OS << "finishing!";
    //AsmBackend->getFixupKindInfo(F.getKind())
    for (VFixup vfixup: VFixups) {
      OS << "fixing: " << *vfixup.fixup.getValue()
         << " offset: " << vfixup.fixup.getOffset()
         << "\n";
      if (!EvaluateFixup(&vfixup)) {
        OS << "failed to set fixup\n";
        *Failed = true;
        return;
      }
    }
    OS << "done!\n";
  }

  bool EmitSymbolAttribute(MCSymbol *Symbol,
			   MCSymbolAttr Attribute) { return false; }

  void EmitCommonSymbol(MCSymbol *Symbol, uint64_t Size,
			unsigned ByteAlignment) { }

  void EmitZerofill(MCSection *Section, MCSymbol *Symbol = nullptr,
		    uint64_t Size = 0, unsigned ByteAlignment = 0) { }

  void EmitLabel(MCSymbol *Symbol) {
    VReloc reloc;
    reloc.name = Symbol->getName();
    reloc.addr = Address + pos;
    ORelocs.push_back(reloc);
  }

  void EmitInstruction(const MCInst &Inst, const MCSubtargetInfo &STI) {
    OS << "instruction";
    OS << Inst << '\n';
    SmallString<256> Code;
    SmallVector<MCFixup, 4> Fixups;
    raw_svector_ostream VecOS(Code);
    Emitter->encodeInstruction(Inst, VecOS, Fixups, STI);

    // If we are showing fixups, create symbolic markers in the encoded
    // representation. We do this by making a per-bit map to the fixup item index,
    // then trying to display it as nicely as possible.
    SmallVector<uint8_t, 64> FixupMap;
    FixupMap.resize(Code.size() * 8);
    for (unsigned i = 0, e = Code.size() * 8; i != e; ++i)
      FixupMap[i] = 0;

    // if (Fixups.size() != 0 || Code.size() == 0) {
    //   std::cerr << std::endl << "fixups!" << std::endl;
    //   *Failed = true;
    //   return;
    // }

    for (unsigned i = 0, e = Fixups.size(); i != e; ++i) {
      // Check
      MCFixup &F = Fixups[i];
      const MCFixupKindInfo &Info = AsmBackend->getFixupKindInfo(F.getKind());
      for (unsigned j = 0; j != Info.TargetSize; ++j) {
        unsigned Index = F.getOffset() * 8 + Info.TargetOffset + j;
        assert(Index < Code.size() * 8 && "Invalid offset in fixup!");
        FixupMap[Index] = 1 + i;
      }
      // Save the Fixup too
      VFixup vfixup = { Fixups[i], pos };
      VFixups.push_back(vfixup);
    }

    // FIXME: Note the fixup comments for Thumb2 are completely bogus since the
    // high order halfword of a 32-bit Thumb2 instruction is emitted first.
    OS << "encoding: [";

    for (unsigned i = 0, e = Code.size(); i != e; ++i) {

      // Copy to memory buffer
      OutMb.push_back(Code[i]);

      pos++;

      if (i)
	OS << ',';

      // See if all bits are the same map entry.
      uint8_t MapEntry = FixupMap[i * 8 + 0];
      for (unsigned j = 1; j != 8; ++j) {
	if (FixupMap[i * 8 + j] == MapEntry)
	  continue;

	MapEntry = uint8_t(~0U);
	break;
      }

      if (MapEntry != uint8_t(~0U)) {
	if (MapEntry == 0) {
	  OS << format("0x%02x", uint8_t(Code[i]));
	} else {
	  if (Code[i]) {
	    // FIXME: Some of the 8 bits require fix up.
	    OS << format("0x%02x", uint8_t(Code[i])) << '\''
	       << char('A' + MapEntry - 1) << '\'';
	  } else
	    OS << char('A' + MapEntry - 1);
	}
      } else {
	// Otherwise, write out in binary.
	OS << "0b";
	for (unsigned j = 8; j--;) {
	  unsigned Bit = (Code[i] >> j) & 1;

	  unsigned FixupBit;
	  if (MAI->isLittleEndian())
	    FixupBit = i * 8 + j;
	  else
	    FixupBit = i * 8 + (7-j);

	  if (uint8_t MapEntry = FixupMap[FixupBit]) {
	    assert(Bit == 0 && "Encoder wrote into fixed up bit!");
	    OS << char('A' + MapEntry - 1);
	  } else
	    OS << Bit;
	}
      }
    }
    OS << "]\n";

    for (unsigned i = 0, e = Fixups.size(); i != e; ++i) {
      MCFixup &F = Fixups[i];
      const MCFixupKindInfo &Info = AsmBackend->getFixupKindInfo(F.getKind());
      OS << "  fixup " << char('A' + i) << " - " << "offset: " << F.getOffset()
         << ", value: " << *F.getValue() << ", kind: " << Info.Name
         << ", TargetOffset: " << Info.TargetOffset
         << ", TargetSize: " << Info.TargetSize
        ;
    }
  }
};

static std::pair<const Target *, std::string> GetTarget(StringRef &ArchName) {
  // Figure out the target triple.
  std::string TripleName = sys::getDefaultTargetTriple();
  Triple TheTriple(Triple::normalize(TripleName));

  // Get the target specific parser.
  std::string Error;
  const Target *TheTarget = TargetRegistry::lookupTarget(ArchName, TheTriple,
                                                         Error);
  if (!TheTarget) {
    errs() << "GetTarget: : " << Error;
    TheTarget = nullptr;
  }

#ifdef DEBUG_cplusplus
  // Before
  std::cout << "TheTriple: " << TripleName << std::endl;
#endif

  // Update the triple name and return the found target.
  TripleName = TheTriple.getTriple();

#ifdef DEBUG_cplusplus
  // After
  std::cout << "TheTriple: " << TripleName << std::endl;
#endif

  return std::make_pair(TheTarget, TripleName);
}

static std::unique_ptr<tool_output_file> GetOutputStream() {
  std::string OutputFilename = "-";

  std::error_code EC;
  auto Out = llvm::make_unique<tool_output_file>(OutputFilename, EC,
                                                 sys::fs::F_None);
  if (EC) {
    errs() << EC.message() << '\n';
    return nullptr;
  }

  return Out;
}

static int AssembleInput(const Target *TheTarget,
                         SourceMgr &SrcMgr, MCContext &Ctx, MCStreamer &Str,
                         MCAsmInfo &MAI, MCSubtargetInfo &STI,
                         MCInstrInfo &MCII, MCTargetOptions &MCOptions,
			 unsigned AsmDialect=0) {
  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(SrcMgr, Ctx, Str, MAI));
  Parser->setAssemblerDialect(AsmDialect);

  std::unique_ptr<MCTargetAsmParser> TAP(
      TheTarget->createMCAsmParser(STI, *Parser, MCII, MCOptions));

  if (!TAP) {
    errs() << "error: this target does not support assembly parsing.\n";
    return 1;
  }

  Parser->setTargetParser(*TAP);

  // Initial .text section
  int Res = Parser->Run(false);

  return Res;
}

static int assemble_llvm(StringRef &arch, StringRef &input_str, uint64_t address,
                         const Reloc_A *relocs, size_t n_relocs,
                         std::vector<byte> &out_bytes)
{
  llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  // Empty options
  MCTargetOptions MCOptions;

  // Define a target
  auto target = GetTarget(arch);
  const Target *TheTarget = target.first;
  std::string TripleName = target.second;

  if (!TheTarget)
    return 1;

  // Now that GetTarget() has (potentially) replaced TripleName, it's safe to
  // construct the Triple object.
  Triple TheTriple(TripleName);

  // Use StringRef as input or STDIN if input_str == "-"
  std::unique_ptr<MemoryBuffer> BufferPtr;
  if (input_str == "-") {
    auto BufferPtrEC =
      MemoryBuffer::getSTDIN();
    if (std::error_code EC = BufferPtrEC.getError()) {
      errs() << "Error getting BufferPtr: " << EC.message() << '\n';
      return 1;
    } else {
      BufferPtr = std::move(*BufferPtrEC);
    }
  } else {
    BufferPtr = MemoryBuffer::getMemBuffer(input_str);
  }


  SourceMgr SrcMgr;

  // Tell SrcMgr about this buffer, which is what the parser will pick up.
  SrcMgr.AddNewSourceBuffer(std::move(BufferPtr), SMLoc());

  std::unique_ptr<MCRegisterInfo> MRI(TheTarget->createMCRegInfo(TripleName));
  assert(MRI && "Unable to create target register info!");

  std::unique_ptr<MCAsmInfo> MAI(TheTarget->createMCAsmInfo(*MRI, TripleName));
  assert(MAI && "Unable to create target asm info!");

  // FIXME: This is not pretty. MCContext has a ptr to MCObjectFileInfo and
  // MCObjectFileInfo needs a MCContext reference in order to initialize itself.
  MCObjectFileInfo MOFI;
  MCContext Ctx(MAI.get(), MRI.get(), &MOFI, &SrcMgr);
  MOFI.InitMCObjectFileInfo(TheTriple, Reloc::Default, CodeModel::Default, Ctx);

  // Package up features to be passed to target/subtarget
  std::string FeaturesStr;


#ifdef DEBUG
  raw_ostream &OS = errs();
#elif defined FILE_DEBUG
  std::unique_ptr<tool_output_file> Out = GetOutputStream();
  if (!Out)
    return 1;
  raw_ostream &OS = Out->os();
#else
  raw_ostream &OS = nulls();
#endif

  SmallVector<char, 0x100> AsmSV(0x100);
  raw_svector_ostream AsmS(AsmSV);

  std::unique_ptr<MCStreamer> Str;

  std::unique_ptr<MCInstrInfo> MCII(TheTarget->createMCInstrInfo());

  std::string MCPU("");
  std::unique_ptr<MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, FeaturesStr));

  // Set up the AsmStreamer.
  MCCodeEmitter *CE = nullptr;
  MCAsmBackend *MAB = nullptr;

  CE = TheTarget->createMCCodeEmitter(*MCII, *MRI, Ctx);
  MAB = TheTarget->createMCAsmBackend(*MRI, TripleName, MCPU);

  out_bytes.reserve(0x100);

  bool failed = false;
  Str.reset(new MCBinaryStreamer(Ctx, MAB, OS, CE, address,
                                 relocs, n_relocs,
                                 out_bytes, &failed));

  int Res = 1;
  // XXX_ remember the last arg is only for X86
  Res = AssembleInput(TheTarget, SrcMgr, Ctx, *Str, *MAI, *STI,
		      *MCII, MCOptions, 1);

  if (failed == true) {
    return -1;
  }

  return Res;
}

void free_vec(byte *vec) {
  free(vec);
}


int assemble(enum Arch arch, const char *instructions, const uint64_t addr, const Reloc_A *relocs, const size_t n_relocs, byte **out, size_t *out_len) {

  StringRef s_arch;
  std::vector<byte> out_vec;

  switch (arch) {
  case x86:
    s_arch = "x86";
    break;
  case x86_64:
    s_arch = "x86-64";
    break;
  case mips:
    s_arch = "mips";
    break;
  case arm:
    s_arch = "arm";
    break;
  case arm64:
    s_arch = "arm64";
    break;
  case thumb:
    s_arch = "thumb";
    break;
  case ppc32:
    s_arch = "ppc32";
    break;
  default:
    return -1;
  }

  StringRef s_instructions(instructions);

  // If it somehow failed, abort
  if (assemble_llvm(s_arch, s_instructions, addr, relocs, n_relocs, out_vec) != 0)
  {
      return -1;
  }

  *out = (byte *)malloc(out_vec.size());
  *out_len = out_vec.size();

  memcpy(*out, out_vec.data(), out_vec.size());

  return 0;
}

/*
int main(int argc, char **argv) {
  StringRef arch(argv[1]);
  StringRef input("-");
  std::vector<byte> out_bytes;

  assemble_llvm(arch, input, out_bytes);
}
*/
