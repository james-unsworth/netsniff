
cmake_minimum_required(VERSION 3.16)
project(netsniff C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Export compile_commands.json (clangd, clang-tidy, etc.)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options that look good in a portfolio and help debugging
option(NS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(NS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(NS_ENABLE_WERROR "Treat warnings as errors" OFF)

add_executable(netsniff
  src/main.c
  src/cli.c
  src/capture.c
  src/util.c
  src/decode_eth.c
  src/decode_ipv4.c
  src/decode_ipv6.c
  src/decode_l4.c
  src/ifaces.c
)

target_include_directories(netsniff PRIVATE include)

if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(netsniff PRIVATE -Wall -Wextra -Wpedantic)

  if (NS_ENABLE_WERROR)
    target_compile_options(netsniff PRIVATE -Werror)
  endif()

  if (NS_ENABLE_ASAN)
    target_compile_options(netsniff PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(netsniff PRIVATE -fsanitize=address)
  endif()

  if (NS_ENABLE_UBSAN)
    target_compile_options(netsniff PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(netsniff PRIVATE -fsanitize=undefined)
  endif()
endif()

find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

if (NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap not found.")
endif()

target_include_directories(netsniff PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(netsniff PRIVATE ${PCAP_LIBRARY})

add_custom_target(run
  COMMAND netsniff
  DEPENDS netsniff
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

include(GNUInstallDirs)

install(TARGETS netsniff
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)


