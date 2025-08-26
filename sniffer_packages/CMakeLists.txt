cmake_minimum_required(VERSION 3.21)

# Set project first for better error messages
project(sniffer_packages LANGUAGES C CXX)

# Check if .NET assembly attributes file exists before configuring it
set(NET_ATTR_FILE "${CMAKE_SOURCE_DIR}/sniffer_packages/x64/Debug/.NETFramework,Version=v4.7.2.AssemblyAttributes.cpp")
if(EXISTS "${NET_ATTR_FILE}")
    set_source_files_properties(
        ${NET_ATTR_FILE}
        PROPERTIES
        COMPILE_OPTIONS "/clr"
    )
endif()

# Sources from sniffer_packages/
# Add this line to include the directory containing packages.h
include_directories(${CMAKE_SOURCE_DIR}/sniffer_packages)

# Verify source files exist before adding them
set(SNIFFER_SOURCES "")
foreach(SRC_FILE 
    mainFunc.cpp
    ipc.cpp
    packages_globals.cpp)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SRC_FILE}")
        list(APPEND SNIFFER_SOURCES "${SRC_FILE}")
    else()
        message(WARNING "Source file not found: ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_FILE}")
    endif()
endforeach()

# Header files - optional but good to include for IDE projects
set(SNIFFER_HEADERS "")
foreach(HDR_FILE
    builderDevice.h
    ether_ntoa.h
    handleProto.h
    ipc.h
    packages.h
    struct.h)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${HDR_FILE}")
        list(APPEND SNIFFER_HEADERS "${HDR_FILE}")
    else()
        message(WARNING "Header file not found: ${CMAKE_CURRENT_SOURCE_DIR}/${HDR_FILE}")
    endif()
endforeach()

# Abort if no source files were found
if(NOT SNIFFER_SOURCES)
    message(FATAL_ERROR "No source files found for sniffer_packages library. Check source file paths.")
endif()

# Create the library with verified sources
add_library(sniffer_packages SHARED ${SNIFFER_SOURCES} ${SNIFFER_HEADERS})
target_compile_features(sniffer_packages PUBLIC cxx_std_20)
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_compile_definitions(sniffer_packages PRIVATE WINx64)
endif()

# On Apple platforms, alias some Linux/Windows struct field tokens and constants
# to their BSD/macOS equivalents to keep legacy code compiling without edits.
if(APPLE)
  target_compile_definitions(sniffer_packages PRIVATE
    ip_vhl=ip_hl
    sport=th_sport
    dport=th_dport
    IPv4_ETHERTYPE=ETHERTYPE_IP
    SIZE_ETHERNET=ETHER_HDR_LEN
  )
endif()

# Definitions (mirror vcxproj)
target_compile_definitions(sniffer_packages
    PRIVATE
        $<$<CONFIG:Debug>:_DEBUG>
        _CONSOLE
        _CRT_SECURE_NO_WARNINGS
)

# Define WINx64 only on Windows 64-bit like in Debug|x64
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_compile_definitions(sniffer_packages PRIVATE WINx64)
endif()

# Includes: project local
target_include_directories(sniffer_packages
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Warnings and runtime per-compiler
if(MSVC)
  # clang-cl also sets MSVC=ON; restrict MSVC-only flags to the MSVC compiler
  if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(sniffer_packages PRIVATE /permissive- /Zc:twoPhase- /Zc:strictStrings- /W4)
  else()
    # clang-cl: use MSVC-style warning level
    target_compile_options(sniffer_packages PRIVATE /W4)
  endif()
  # MultiThreadedDebugDLL (/MDd) in Debug, MultiThreadedDLL (/MD) in others
  set_property(TARGET sniffer_packages PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(sniffer_packages PRIVATE -Wall -Wextra -Wpedantic)
endif()

# On Windows, export all symbols when building a shared lib (helps when no .def file is provided)
if(WIN32)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Try to use vcpkg (recommended)
# - Requires: vcpkg integrate via toolchain, e.g. -DCMAKE_TOOLCHAIN_FILE=.../vcpkg.cmake
# - Ports: pcapplusplus and system libs (ws2_32, iphlpapi)
find_package(PcapPlusPlus CONFIG QUIET)

# Portable thread library
# Do not prefer pthread on Windows/MSVC; MSVC doesn't use pthreadVC2
set(THREADS_PREFER_PTHREAD_FLAG OFF)
find_package(Threads REQUIRED)

if(PcapPlusPlus_FOUND)
  message(STATUS "Found PcapPlusPlus at ${PcapPlusPlus_DIR}")
  if(WIN32)
    target_link_libraries(sniffer_packages
        PRIVATE
          PcapPlusPlus::Pcap++
          PcapPlusPlus::Packet++
          PcapPlusPlus::Common++
          ws2_32
          iphlpapi
    )
  else()
    target_link_libraries(sniffer_packages
        PRIVATE
          PcapPlusPlus::Pcap++
          PcapPlusPlus::Packet++
          PcapPlusPlus::Common++
    )
  endif()
else()
  message(STATUS "PcapPlusPlus not found via CMake config. Trying fallbacks...")
  if(WIN32)
    # Fallback to local SDK paths in repo: header/WpdPack/WpdPack
    set(WPDPACK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../header/WpdPack/WpdPack" CACHE PATH "Path to WpdPack root")

    if(NOT EXISTS "${WPDPACK_ROOT}")
      message(FATAL_ERROR "WpdPack not found at ${WPDPACK_ROOT}. Expected repo-local SDK under header/WpdPack/WpdPack")
    endif()

    # Includes
    target_include_directories(sniffer_packages PRIVATE
        "${WPDPACK_ROOT}/Include"
        "${WPDPACK_ROOT}/Include/pcap"
         "${WPDPACK_ROOT}/lib"
    )

    # Determine correct lib dir for arch
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib/x64")
    else()
      set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib")
    endif()

    # Resolve absolute library paths to avoid relying on global link directories
    find_library(WPCAP_LIB NAMES wpcap PATHS "${_WPDPACK_LIBDIR}" NO_DEFAULT_PATH)
    find_library(PACKET_LIB NAMES Packet PATHS "${_WPDPACK_LIBDIR}" NO_DEFAULT_PATH)

    if(NOT WPCAP_LIB OR NOT PACKET_LIB)
      message(FATAL_ERROR "Could not find wpcap.lib and/or Packet.lib under ${_WPDPACK_LIBDIR}.\n"
                           "Checked path: ${_WPDPACK_LIBDIR}\n"
                           "Make sure the repo contains header/WpdPack/WpdPack with Lib/x64/wpcap.lib and Packet.lib for x64 builds.")
    else()
      message(STATUS "Using WinPcap/Npcap from ${WPDPACK_ROOT} (libs: ${_WPDPACK_LIBDIR})")
    endif()

    # Optionally allow prebuilt PcapPlusPlus directory, but it's not required
    set(PCAPPP_LIB_DIR "" CACHE PATH "Path to PcapPlusPlus prebuilt lib directory (optional)")
    if(PCAPPP_LIB_DIR AND EXISTS "${PCAPPP_LIB_DIR}")
      message(STATUS "(Optional) Using PcapPlusPlus libs from ${PCAPPP_LIB_DIR}")
      link_directories("${PCAPPP_LIB_DIR}")
    endif()

    target_link_libraries(sniffer_packages
        PRIVATE
          ws2_32
          iphlpapi
          ${WPCAP_LIB}
          ${PACKET_LIB}
    )
  else()
    # Unix/macOS fallback - use system libpcap
    find_library(PCAP_LIBRARY pcap REQUIRED)
    if(NOT PCAP_LIBRARY)
      message(FATAL_ERROR "libpcap not found. Install with: brew install libpcap")
    endif()
    
    # Try to find pcap headers
    find_path(PCAP_INCLUDE_DIR pcap.h
      PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
    )
    
    if(PCAP_INCLUDE_DIR)
      target_include_directories(sniffer_packages PRIVATE ${PCAP_INCLUDE_DIR})
    endif()
    
    target_link_libraries(sniffer_packages
        PRIVATE
          ${PCAP_LIBRARY}
          Threads::Threads
    )
    
    message(STATUS "Using system libpcap: ${PCAP_LIBRARY}")
  endif()
endif()

# Ensure predictable output paths (placed after add_library)
set_target_properties(sniffer_packages PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Avoid PDB API contention in MSVC parallel builds (error C1090)
if(MSVC)
  target_compile_options(sniffer_packages PRIVATE /FS)
endif()

# Summary
message(STATUS "sniffer_packages: OUTPUT (shared lib) => ${CMAKE_BINARY_DIR}/lib")
message(STATUS "sniffer_packages: BUILD TYPE => ${CMAKE_BUILD_TYPE}")
message(STATUS "sniffer_packages sources: ${SNIFFER_SOURCES}")
