#pragma once
#include <capstone/capstone.h>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <pe-parse/parse.h>
#include <vector>

// Utilities for finding rop gadgets
namespace ropc::gadget {
enum class GadgetError { InvalidPath = 0, CantRead, CapstoneError };
using Gadget = std::vector<cs_insn>;

std::expected<std::vector<Gadget>, GadgetError>
FindGadgets(const std::filesystem::path &Path,
            size_t MaxInstructionDepth = 5) noexcept;
} // namespace ropc::gadget
