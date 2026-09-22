include(FetchContent)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.15.0)

FetchContent_Declare(
   peparse 
    GIT_REPOSITORY https://github.com/trailofbits/pe-parse.git
    GIT_TAG 9e4e3587969ea2410dadda1ccfa909aec1121d09)

FetchContent_Declare(
    triton
    GIT_REPOSITORY https://github.com/JonathanSalwan/Triton.git
    GIT_TAG bc84cf745e99768e07d51dcd734eba35c59f1b3e
  )
FetchContent_MakeAvailable(spdlog peparse triton)

cmake_minimum_required(VERSION 3.13)

find_path(CAPSTONE_INCLUDE_DIR
    NAMES capstone/capstone.h
    REQUIRED
)

find_library(CAPSTONE_LIBRARY
    NAMES capstone
    REQUIRED
)

project(ropc LANGUAGES CXX)

# set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE APP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(${PROJECT_NAME} ${APP_SOURCES})

target_include_directories(${PROJECT_NAME}
  # TODO: make this private except for the API
  PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
            "${CAPSTONE_INCLUDE_DIR}"
)

# Warnings used in every build configuration
target_compile_options(${PROJECT_NAME}
  PUBLIC
        -Wno-unknown-pragmas
        -Wno-deprecated-declarations
        -Wall
        -Wextra
        -Wpedantic
)

# Debug-only compiler options
target_compile_options(${PROJECT_NAME}
  PUBLIC
        $<$<CONFIG:Debug>:
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
            -g
            -O0
        >
)

# Debug-only linker options
target_link_options(${PROJECT_NAME}
  PUBLIC
        $<$<CONFIG:Debug>:
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        >
)

target_link_libraries(${PROJECT_NAME}
  PUBLIC
    spdlog::spdlog_header_only
    pe-parse::pe-parse
    triton
        "${CAPSTONE_LIBRARY}"
)

add_subdirectory(tests)
