#pragma once
#include "pe-parse/nt-headers.h"
#include "spdlog/spdlog.h"
#include <capstone/capstone.h>
#include <expected>
#include <filesystem>
#include <format>
#include <pe-parse/parse.h>
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

        // Only look for executable sections. TODO: consider just .TEXT section
        // for simplicity
        if (0 == (ImageSectionHeader.Characteristics &
                  peparse::IMAGE_SCN_CNT_CODE)) {
          return 0lu;
        }

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

  std::vector<Gadget> gadgets;

  for (const auto &pRet : potentialRets) {
    // Capstone disassemble backwards until maximum of MaxInstructionDepth len
    // is found. A subset of instructions is derived from the super set of
    // instructions for a gadget, allowing use of smaller gadgets found in
    // larger ones

    // TODO: potentially perform a binary search method for the initial window
    // position to get the MaxInstructionDepth faster than iteravely. Currently
    // not performant by any measure.

    Gadget gadget;

    // idx is the amount of bytes subtracted from pRet position; AKA the start
    // of the sliding window. TODO: change 0x69; is arbitrary funny number
    for (size_t idx = 0; idx < 0x69 && idx <= pRet._offset; idx++) {
      cs_insn *insn;
      size_t numInsn =
          cs_disasm(capstone, pRet._boundedBuffer->buf + pRet._offset - idx,
                    idx + 1, pRet._sectionBase + pRet._offset - idx, 0, &insn);

      if (numInsn >= MaxInstructionDepth) {
        // If we want to keep this gadget or not
        bool badGadget = false;

        // Filter for last gadget being a RET
        if (insn[numInsn - 1].id != X86_INS_RET) {
          badGadget = true;
        }

        // Further filter down out gadgets
        for (size_t jdx = 0; false == badGadget && jdx < numInsn; jdx++) {
          cs_insn *curInsn = insn + jdx;
          if (cs_insn_group(capstone, curInsn, CS_GRP_JUMP) &&
              (curInsn->id == X86_INS_JMP || curInsn->id == X86_INS_LJMP)) {
            // Unconditional jumps are something to be explicitly filtered
            // out(for now)

            badGadget = true;
            break;
          }

          // TODO: chcek for more categories such as calls

          // There's some optimization that can be done here to reduce the
          // surface area of gadgets to be searched. but that may be putting the
          // cart before the horse in this stage of development: Mama always
          // said not to optimize to early!

          auto copy = *curInsn;
          // TODO: if detail is required later on, copy this structure,
          // otherwise we don't need a dangling pointer
          copy.detail = NULL;
          gadget.emplace_back(std::move(copy));
        }

        if (badGadget) {
          gadget.clear();
        } else {
          gadgets.push_back(std::move(gadget));
        }

        cs_free(insn, numInsn);
      } else {
        cs_free(insn, numInsn);
      }
    }
  }

  // gadgets is now populated with all the gadgets we've filterd down

  if (auto err = cs_close(&capstone); err != CS_ERR_OK) {
    spdlog::warn(std::format("Failed to close capstone with err: 0x{:x}",
                             static_cast<uint8_t>(err)));
  }

  peparse::DestructParsedPE(pe);
  return gadgets;
}
} // namespace ropc::gadget
