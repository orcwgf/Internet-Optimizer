cmake_minimum_required(VERSION 3.21)

project(NetPilot VERSION 1.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "NetPilot is a Windows application (it uses the Windows IP Helper API).")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NETPILOT_BUILD_TESTS "Build the NetPilot test suite" ON)
option(NETPILOT_STATIC_RUNTIME
  "Link the MSVC runtime statically so the exe runs without a redistributable" ON)

if(MSVC AND NETPILOT_STATIC_RUNTIME)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---------------------------------------------------------------------------
# Platform-independent core (formatting, risk rules, filters, TUI buffer)
# ---------------------------------------------------------------------------
add_library(netpilot_core STATIC
  src/util.cpp
  src/config.cpp
  src/risk.cpp
  src/filter.cpp
  src/screen.cpp
)
target_include_directories(netpilot_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(netpilot_core PUBLIC
  UNICODE
  _UNICODE
  NOMINMAX
  WIN32_LEAN_AND_MEAN
  _WIN32_WINNT=0x0A00
)

# ---------------------------------------------------------------------------
# Windows executable
# ---------------------------------------------------------------------------
add_executable(netpilot
  src/main.cpp
  src/app.cpp
  src/render.cpp
  src/console.cpp
  src/sysinfo.cpp
)
target_link_libraries(netpilot PRIVATE
  netpilot_core
  iphlpapi
  ws2_32
  version
  advapi32
  shell32
  ole32
  user32
)

if(MSVC)
  target_compile_options(netpilot_core PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
  target_compile_options(netpilot PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
endif()

set_target_properties(netpilot PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

install(TARGETS netpilot RUNTIME DESTINATION .)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(NETPILOT_BUILD_TESTS)
  enable_testing()
  add_executable(netpilot_tests tests/test_core.cpp)
  target_link_libraries(netpilot_tests PRIVATE netpilot_core)
  target_compile_definitions(netpilot_tests PRIVATE UNICODE _UNICODE NOMINMAX)
  if(MSVC)
    target_compile_options(netpilot_tests PRIVATE /W4 /permissive- /utf-8)
  endif()
  set_target_properties(netpilot_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
  add_test(NAME core COMMAND netpilot_tests)

  # Fixture used by manual/integration checks: a process that holds a
  # listening socket so NetPilot has something harmless to suspend and stop.
  add_executable(netpilot_test_holder tests/socket_holder.cpp)
  target_link_libraries(netpilot_test_holder PRIVATE ws2_32)
  set_target_properties(netpilot_test_holder PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
endif()
