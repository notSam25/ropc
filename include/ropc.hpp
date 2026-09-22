#pragma once
#include <filesystem>
#include "gadget.hpp"

namespace ropc {
class Engine {
public:
  explicit Engine() = default;
  ~Engine() = default;

private:
  // File on disk which we're going to disassemble to search for gadgets
  std::filesystem::path _binPath{};
};
} // namespace ropc
