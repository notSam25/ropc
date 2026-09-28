#include "spdlog/spdlog-inl.h"
#include <capstone/x86.h>
#include <gadget.hpp>

int main(void) {
  std::printf("Hello, World!\n");

  std::filesystem::path binPath{BIN_DIR};
  spdlog::set_level(spdlog::level::level_enum::trace);
  if (auto gadgets = ropc::gadget::FindGadgets(
          binPath / "ntoskrnl_"
                    "54f57116bcbbe96da72088130a8f949e13884a3db39d81f4b80cb26a88"
                    "de00ac.exe");
      gadgets) {
  } else {
    spdlog::error(std::format("Failed to disassemble gadgets: {}",
                              static_cast<std::uint8_t>(gadgets.error())));
  }

  return 0lu;
}
