#include <gadget.hpp>

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
#include <thread>
#include <vector>

namespace ropc::gadget {

struct RetTarget {
  const peparse::bounded_buffer *_boundedBuffer;
  const std::uint64_t _sectionBase, _offset;
};

struct OutputState {
  std::mutex mutex;
  std::ofstream file{"gadgets.txt"};
};

void DisassembleRegion(const csh &handle, std::span<const RetTarget> target,
                       std::shared_ptr<std::vector<Gadget>> result,
                       std::shared_ptr<OutputState> outputState,
                       const std::size_t maxInstructionDepth) {
  for (const auto &pRet : target) {
    // pRet is a potentiall rop gadget end

    // The exclusive end of the ret gadget
    const std::uint64_t targetEnd = pRet._sectionBase + pRet._offset + 1;

    cs_insn *insn = nullptr;
    Gadget gadget;

    // The walkback length in bytes from the ret position
    for (std::size_t idx = 0; idx < 0x69; idx++) {
      insn = nullptr;
      gadget.clear();

      size_t numInsn =
          cs_disasm(handle, pRet._boundedBuffer->buf + pRet._offset - idx,
                    idx + 1, pRet._sectionBase + pRet._offset - idx, 0, &insn);
      if (numInsn >= maxInstructionDepth) {

        const cs_insn *last = insn + numInsn - 1;
        if (last->id != X86_INS_RET ||
            (last->address + last->size) != targetEnd) {
          cs_free(insn, numInsn);
          continue;
        }

        auto IsBadGadget = [handle, &gadget](const cs_insn insns[],
                                             std::size_t count) -> bool {
          for (std::size_t idx = 0; idx < count; idx++) {
            auto *curInsn = &insns[idx], *nextInsn = &insns[idx + 1];

            // Check if we're properly aligning insns in the gadget
            if (idx < count - 1 &&
                curInsn->address + curInsn->size != nextInsn->address) {
              return true;
            }

            if (cs_insn_group(handle, curInsn, CS_GRP_JUMP)) {
              const cs_x86_op *op = &curInsn->detail->x86.operands[0];

              if (op->type == X86_OP_IMM) {
                switch (curInsn->id) {
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
                  return true;
                }
              }
            }

            if (cs_insn_group(handle, curInsn, CS_GRP_CALL) &&
                curInsn->detail->x86.operands[0].type == X86_OP_IMM) {
              // call IMM aren't great gadgets
              return true;
            }

            gadget.emplace_back(*curInsn);
          }

          return false;
        };

        if (IsBadGadget(insn, numInsn)) {
          cs_free(insn, numInsn);
          continue;
        }

#ifdef DumpGadgetsToFile
        // serialize gadget
        const auto annonimizeGadget = [](const cs_insn &insn) -> std::string {
          if (nullptr == insn.detail) {
            throw std::runtime_error("expected `detail` field in instruction");
          }

          if (0 == insn.detail->x86.op_count) {
            return std::format(" {};", insn.mnemonic);
          } else {
            return std::format(" {} {};", insn.mnemonic, insn.op_str);
          }

          // TODO: simplify this with simple regex on mnemonic and operand
          // strings

          const cs_x86 &x86 = insn.detail->x86;

          std::string result = std::format(" {} ", insn.mnemonic);

          for (std::size_t opc = 0; opc < x86.op_count; opc++) {
            const cs_x86_op &op = x86.operands[opc];
            switch (op.type) {
            case x86_op_type::X86_OP_IMM: {
              result += "IMM| ";
              break;
            }
            case x86_op_type::X86_OP_REG: {
              result += std::string(insn.op_str) + "|";
              break;
            }
            case x86_op_type::X86_OP_MEM: {
              result += std::string(insn.op_str) + "|";
              break;
            }
            case x86_op_type::X86_OP_INVALID: {
              result += std::string(insn.op_str) + "|";
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
        {
          std::lock_guard lock(outputState->mutex);
          outputState->file << line << std::endl;
        }
#endif
        // add gaget to list
        result->push_back(std::move(gadget));

        cs_free(insn, numInsn);
        break;
      }

      // thou shall not leak memory
      cs_free(insn, numInsn);
    }
  }
}

std::vector<Gadget>
ParellelComputeGadgets(const csh &handle,
                       const std::vector<RetTarget> &retTargets,
                       const std::size_t maxInstructionDepth) {
  std::size_t numCores = std::thread::hardware_concurrency();
  if (numCores == 0)
    numCores = 1;

  using ThreadData =
      std::pair<std::jthread, std::shared_ptr<std::vector<Gadget>>>;

  std::vector<ThreadData> threads;
  threads.reserve(numCores);

  auto os = std::make_shared<OutputState>();

  for (std::size_t idx = 0; idx < numCores; ++idx) {
    const std::size_t begin = retTargets.size() * idx / numCores;
    const std::size_t end = retTargets.size() * (idx + 1) / numCores;

    auto target =
        std::span<const RetTarget>{retTargets}.subspan(begin, end - begin);
    auto part = std::make_shared<std::vector<Gadget>>();

    threads.emplace_back(std::jthread(DisassembleRegion, std::cref(handle),
                                      target, part, os, maxInstructionDepth),
                         part);
  }

  for (auto &[thread, part] : threads)
    thread.join();

  std::size_t total = 0;
  for (const auto &[thread, part] : threads)
    total += part->size();

  std::vector<Gadget> result;
  result.reserve(total);

  for (auto &[thread, part] : threads) {
    result.insert(result.end(), std::make_move_iterator(part->begin()),
                  std::make_move_iterator(part->end()));
  }

  return result;
}

std::expected<std::vector<Gadget>, GadgetError>
FindGadgets(const std::filesystem::path &Path,
            const std::size_t MaxInstructionDepth) noexcept {
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

  std::vector<RetTarget> potentialRets;

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

  auto gadgets = ParellelComputeGadgets(
      std::cref(capstone), std::cref(potentialRets), MaxInstructionDepth);

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
