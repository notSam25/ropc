#pragma once
#include "pe-parse/nt-headers.h"
#include "spdlog/spdlog.h"
#include <capstone/capstone.h>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <pe-parse/parse.h>
#include <stdexcept>
#include <vector>

// Utilities for finding rop gadgets
namespace ropc::gadget {
enum class GadgetError { InvalidPath = 0, CantRead, CapstoneError };
using Gadget = std::vector<cs_insn>;

static std::expected<std::vector<Gadget>, GadgetError>
FindGadgets(const std::filesystem::path &Path,
            size_t MaxInstructionDepth = 5) noexcept {
  // Invalid path or not a file
  if (false == std::filesystem::exists(Path) ||
      true == std::filesystem::is_directory(Path)) {
    return std::unexpected(GadgetError::InvalidPath);
  }

  // API such as cs_insn_group are unsupported in diet mode
  if (cs_support(CS_SUPPORT_DIET)) {
    return std::unexpected(GadgetError::CapstoneError);
  }

  // Attempt to open file
  auto pe = peparse::ParsePEFromFile(Path.c_str());
  if (nullptr == pe) {
    return std::unexpected(GadgetError::CantRead);
  }

  struct PotentialRet {
    // Section buffer
    const peparse::bounded_buffer *_boundedBuffer;
    const std::uint64_t _sectionBase, _offset;
  };

  std::vector<PotentialRet> potentialRets;

  // Find executable sections
  peparse::IterSec(
      pe,
      [](void *cbd, const peparse::VA &SectionBase,
         const std::string &SectionName,
         const peparse::image_section_header &ImageSectionHeader,
         const peparse::bounded_buffer *BoundedBuffer) -> int {
        (void)SectionName;

        // TODO: remove hardcoded .text section filter
        if (0 == (ImageSectionHeader.Characteristics &
                  peparse::IMAGE_SCN_CNT_CODE) ||
            SectionName.find(".text") == std::string::npos) {
          return 0lu;
        }

        spdlog::debug(std::format("Found executable section '{}' size 0x{:x}",
                                  SectionName, BoundedBuffer->bufLen));

        auto *potentialRets = static_cast<std::vector<PotentialRet> *>(cbd);

        for (size_t idx = 0; idx < BoundedBuffer->bufLen; idx++) {
          // Candidiate return instruction(x86/AMD64)
          if (BoundedBuffer->buf[idx] == 0xC3) {
            // Add to list of potential gadgets
            potentialRets->emplace_back(
                PotentialRet{._boundedBuffer = BoundedBuffer,
                             ._sectionBase = SectionBase,
                             ._offset = idx});
          }
        }

        // Always return zero to get through all sections
        return 0lu;
      },
      &potentialRets);

  csh capstone{};
  if (CS_ERR_OK !=
      cs_open(cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_64, &capstone)) {
    return std::unexpected(GadgetError::CapstoneError);
  }

  // Enable detailed decompilation of gadgets(uses more memory and processing
  // power)
  cs_option(capstone, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(capstone, CS_OPT_SKIPDATA, CS_OPT_OFF);

  std::vector<Gadget> gadgets;
#ifdef DumpGadgetsToFile
  auto os = std::ofstream("gadets.txt");
#endif

  for (const auto &pRet : potentialRets) {
    // Capstone disassemble backwards until maximum of MaxInstructionDepth len
    // is found. A subset of instructions is derived from the super set of
    // instructions for a gadget, allowing use of smaller gadgets found in
    // larger ones

    // TODO: potentially perform a binary search method for the initial window
    // position to get the MaxInstructionDepth faster than iteravely. Currently
    // not performant by any measure.

    // The byte immediately after our candidate 0xC3; a validly-aligned
    // decode run must end exactly here, otherwise the "ret" we found at
    // insn[numInsn - 1] is a decode landing on unrelated/misaligned bytes
    // rather than our actual candidate.
    const uint64_t targetEnd = pRet._sectionBase + pRet._offset + 1;

    // idx is the amount of bytes subtracted from pRet position; AKA the start
    // of the sliding window. TODO: change 0x69; is arbitrary funny number
    for (size_t idx = 0; idx < 0x69 && idx <= pRet._offset; idx++) {
      cs_insn *insn = nullptr;
      Gadget gadget;

      size_t numInsn =
          cs_disasm(capstone, pRet._boundedBuffer->buf + pRet._offset - idx,
                    idx + 1, pRet._sectionBase + pRet._offset - idx, 0, &insn);

      if (numInsn >= MaxInstructionDepth) {
        // If we want to keep this gadget or not
        bool badGadget = false;

        const cs_insn &last = insn[numInsn - 1];
        if (last.id != X86_INS_RET || (last.address + last.size) != targetEnd) {
          badGadget = true;
        }

        // Further filter down out gadgets
        for (size_t jdx = 0; false == badGadget && jdx < numInsn - 1; jdx++) {
          cs_insn *curInsn = insn + jdx, *nextInsn = insn + jdx + 1;

          if (curInsn->address + curInsn->size != nextInsn->address) {
            // A decoding failure

            badGadget = true;
            break;
          }

          if (cs_insn_group(capstone, insn, CS_GRP_JUMP)) {
            const cs_x86_op *op = &insn->detail->x86.operands[0];

            if (op->type == X86_OP_IMM) {
              switch (insn->id) {
              case X86_INS_JAE:
              case X86_INS_JA:
              case X86_INS_JBE:
              case X86_INS_JB:
              case X86_INS_JCXZ:
              case X86_INS_JECXZ:
              case X86_INS_JE:
              case X86_INS_JGE:
              case X86_INS_JG:
              case X86_INS_JLE:
              case X86_INS_JL:
              case X86_INS_JNE:
              case X86_INS_JNO:
              case X86_INS_JNP:
              case X86_INS_JNS:
              case X86_INS_JO:
              case X86_INS_JP:
              case X86_INS_JRCXZ:
              case X86_INS_JS:
                break;
              default:
                // filter out jmp literal insns
                badGadget = true;
                break;
              }

              if (badGadget) {
                break;
              }
            }
          }

          if (cs_insn_group(capstone, insn, CS_GRP_CALL) &&
              insn->detail->x86.operands[0].type == X86_OP_IMM) {
            // call IMM aren't great gadgets
            badGadget = true;
            break;
          }

          if (cs_insn_group(capstone, insn, CS_GRP_RET) ||
              cs_insn_group(capstone, insn, CS_GRP_IRET)) {
            badGadget = true;
            break;
          }

          // There's some optimization that can be done here to reduce the
          // surface area of gadgets to be searched. but that may be putting the
          // cart before the horse in this stage of development: Mama always
          // said not to optimize to early!

          auto copy = *curInsn;
          gadget.emplace_back(std::move(copy));
        }

        if (false == badGadget) {
#ifdef DumpGadgetsToFile
          // serialize gadget
          const auto annonimizeGadget = [](const cs_insn &insn) -> std::string {
            // TODO: simplify this with simple regex on mnemonic and operand
            // strings

            if (nullptr == insn.detail) {
              throw std::runtime_error(
                  "expected `detail` field in instruction");
            }

            const cs_x86 &x86 = insn.detail->x86;

            std::string result = std::format(" {} ", insn.mnemonic);

            for (size_t idx = 0; idx < x86.op_count; idx++) {
              const cs_x86_op &op = x86.operands[idx];
              switch (op.type) {
              case x86_op_type::X86_OP_IMM: {
                result += "IMM;";
                break;
              }
              case x86_op_type::X86_OP_REG: {
                result += std::string(insn.op_str) + ";";
                break;
              }
              case x86_op_type::X86_OP_MEM: {
                result += std::string(insn.op_str) + ";";
                break;
              }
              case x86_op_type::X86_OP_INVALID: {
                result += std::string(insn.op_str) + ";";
                break;
              }
              default: {
                throw std::runtime_error("unimplemented operand type");
              };
              }
            }

            return result;
          };

          std::string line = std::format("0x{:X} :", gadget.at(0).address);

#endif
          for (auto &insn : gadget) {
#ifdef DumpGadgetsToFile
            line += annonimizeGadget(insn);
#endif
            // null out details since we free this memory
            insn.detail = nullptr;
          }
#ifdef DumpGadgetsToFile
          os << line << std::endl;
#endif
          // add gaget to list
          gadgets.push_back(std::move(gadget));
        }
      }

      // thou shall not leak memory
      cs_free(insn, numInsn);
    }
  }

  os.close();

  // clean up capstone and pe-parser
  if (auto err = cs_close(&capstone); err != CS_ERR_OK) {
    spdlog::warn(std::format("Failed to close capstone with err: 0x{:x}",
                             static_cast<uint8_t>(err)));
  }

  peparse::DestructParsedPE(pe);

  spdlog::trace(std::format("Found {} gadgets", gadgets.size()));
  return gadgets;
}
} // namespace ropc::gadget
