cmake_minimum_required(VERSION 3.21)
project(BasedAuth HOMEPAGE_URL "https://basedauth.com" LANGUAGES C CXX VERSION 1.0.0)

find_package(Corrosion QUIET 0.6)
if(NOT Corrosion_FOUND)
  include(FetchContent)

  FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY "https://github.com/corrosion-rs/corrosion.git"
    GIT_TAG "1499b14e4906a2890f5cee1547c8848db261753d" # v0.6.1
  )

  FetchContent_MakeAvailable(Corrosion)
endif()

list(PREPEND CMAKE_MODULE_PATH ${Corrosion_SOURCE_DIR}/cmake)
find_package(Rust 1.92 REQUIRED MODULE)

corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    CRATE_TYPES staticlib
)

add_library(BasedAuth INTERFACE)
add_library(BasedAuth::BasedAuth ALIAS BasedAuth)

target_link_libraries(BasedAuth INTERFACE basedauth)

target_include_directories(BasedAuth INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
