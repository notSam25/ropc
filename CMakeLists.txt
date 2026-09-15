include(FetchContent)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.15.0)

FetchContent_MakeAvailable(spdlog)

cmake_minimum_required(VERSION 3.13)

project(ropc LANGUAGES CXX)

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
)

add_subdirectory(tests)
