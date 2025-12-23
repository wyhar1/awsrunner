cmake_minimum_required(VERSION 3.16)
project(arb_ws_watcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL (Homebrew)
find_package(OpenSSL REQUIRED)

# Prefer Homebrew boost headers/libs; project historically used Homebrew includes.
# Add include for Homebrew
include_directories(/opt/homebrew/include)

# Include project headers (nlohmann/json.hpp under include/)
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add Boost include dirs (if Boost found via system it may point elsewhere)
# We'll prefer Homebrew boost libs to avoid Anaconda conflicts.
include_directories(/opt/homebrew/include)

add_executable(arb_ws_watcher src/main.cpp)

# Explicitly link Homebrew libboost_system to avoid linking against Anaconda's boost (which drags a different libc++)
set(HOMEBREW_BOOST_SYSTEM "/opt/homebrew/lib/libboost_system.dylib")
if(EXISTS ${HOMEBREW_BOOST_SYSTEM})
  message(STATUS "Linking against Homebrew boost_system: ${HOMEBREW_BOOST_SYSTEM}")
  target_link_libraries(arb_ws_watcher PRIVATE ${HOMEBREW_BOOST_SYSTEM} OpenSSL::SSL OpenSSL::Crypto)
else()
  message(STATUS "Homebrew boost_system not found at ${HOMEBREW_BOOST_SYSTEM}; falling back to system linking")
  target_link_libraries(arb_ws_watcher PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

add_executable(kalshi_post_test src/kalshi_post_test.cpp)
# Link with OpenSSL and system libs
target_link_libraries(kalshi_post_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
