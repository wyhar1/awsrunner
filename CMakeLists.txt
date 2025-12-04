cmake_minimum_required(VERSION 3.16)
project(arb_ws_watcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL (Homebrew)
find_package(OpenSSL REQUIRED)

# Find Boost.System (required for Boost.Asio/Beast linking)
find_package(Boost 1.70 COMPONENTS system)
if (NOT Boost_FOUND)
  message(FATAL_ERROR "Boost not found. Please install Boost (e.g. 'brew install boost') and re-run CMake. Detected Homebrew prefix: $ENV{HOMEBREW_PREFIX}")
endif()

# Include project headers (nlohmann/json.hpp under include/)
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add Boost include dirs
include_directories(${Boost_INCLUDE_DIRS})

# We deliberately DO NOT call find_package(Boost ...) anymore.
# Beast/Asio + System are header-only in modern Boost, so just add include dirs.
# Homebrew installs headers to /opt/homebrew/include by default.
include_directories(/opt/homebrew/include)

# Make sure we don't try to link non-existent Boost::system via auto-linking
add_definitions(
  -DBOOST_ERROR_CODE_HEADER_ONLY
  -DBOOST_SYSTEM_NO_LIB
  -DBOOST_ASIO_NO_DEPRECATED
)

add_executable(arb_ws_watcher src/main.cpp)

# Link libraries: Boost.System + OpenSSL
target_link_libraries(arb_ws_watcher PRIVATE ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)

# On macOS, networking/tls usually doesn't need extra frameworks for this use,
# but if you ever see unresolved symbols, uncomment:
# target_link_libraries(arb_ws_watcher PRIVATE "-framework CoreFoundation" "-framework Security")
