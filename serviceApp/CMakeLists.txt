cmake_minimum_required(VERSION 3.21)

project(serviceApp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  add_compile_options(/Zc:__cplusplus /bigobj)
endif()

add_executable (serviceApp
  "serviceApp.cpp" "serviceApp.h"
  #"Npcap.cpp" "Npcap.h"
  "package_global.cpp" "package_global.h"
  "FileLogger.h"
  "StreamSession.cpp" "StreamSession.h"
  "NpcapCommands.cpp" "NpcapCommands.h"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET serviceApp PROPERTY CXX_STANDARD 20)
endif()

if(MSVC)
  target_compile_options(serviceApp PRIVATE /FS)
  target_compile_options(serviceApp PRIVATE 
    $<$<CONFIG:Debug>:/Od /Zi /RTC1>
    $<$<CONFIG:Release>:/O2>
  )
  target_link_options(serviceApp PRIVATE 
    $<$<CONFIG:Debug>:/DEBUG:FULL>
  )
endif()


set(WPDPACK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../header/WpdPack/WpdPack" CACHE PATH "Path to WpdPack root")
if(NOT EXISTS "${WPDPACK_ROOT}")
  message(FATAL_ERROR "WpdPack not found at ${WPDPACK_ROOT}. Expected repo-local SDK under header/WpdPack/WpdPack")
endif()

# Make WpdPack headers visible to all subprojects (sniffer_packages, etc.)
include_directories(
  "${WPDPACK_ROOT}/Include"
  "${WPDPACK_ROOT}/Include/pcap"
)

# Includes (pcap.h is under Include/pcap, but including both is fine)
target_include_directories(serviceApp PRIVATE
  "${WPDPACK_ROOT}/Include"
  "${WPDPACK_ROOT}/Include/pcap"
)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  # Building standalone - include sniffer_packages
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../sniffer_packages" "${CMAKE_CURRENT_BINARY_DIR}/sniffer_packages_build")
endif()

target_link_libraries(serviceApp PRIVATE sniffer_packages)
add_dependencies(serviceApp sniffer_packages)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib/x64")
else()
  set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib")
endif()

find_library(WPCAP_LIB NAMES wpcap PATHS "${_WPDPACK_LIBDIR}" NO_DEFAULT_PATH)
find_library(PACKET_LIB NAMES Packet PATHS "${_WPDPACK_LIBDIR}" NO_DEFAULT_PATH)
if(NOT WPCAP_LIB OR NOT PACKET_LIB)
  message(FATAL_ERROR "Could not find wpcap.lib and/or Packet.lib under ${_WPDPACK_LIBDIR}")
else()
  message(STATUS "Using WinPcap/Npcap from ${WPDPACK_ROOT} (libs: ${_WPDPACK_LIBDIR})")
endif()

# Link
target_link_libraries(serviceApp PRIVATE
  ws2_32
  iphlpapi
  ${WPCAP_LIB}
  ${PACKET_LIB}
)

# Copy sniffer_packages DLL and PDB from sniffer_packages/bin/Debug to serviceApp/Debug
set(SNIFFER_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../sniffer_packages/bin/Debug")
add_custom_command(TARGET serviceApp POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SNIFFER_SOURCE_DIR}/sniffer_packages.dll" $<TARGET_FILE_DIR:serviceApp>
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SNIFFER_SOURCE_DIR}/sniffer_packages.pdb" $<TARGET_FILE_DIR:serviceApp>
  COMMENT "Copying sniffer_packages DLL and PDB from ${SNIFFER_SOURCE_DIR} to serviceApp output directory")

find_file(WPCAP_DLL NAMES wpcap.dll
  PATHS "${_WPDPACK_LIBDIR}" "$ENV{SystemRoot}/System32/Npcap" "$ENV{ProgramFiles}/Npcap"
  NO_DEFAULT_PATH)
find_file(PACKET_DLL NAMES Packet.dll
  PATHS "${_WPDPACK_LIBDIR}" "$ENV{SystemRoot}/System32/Npcap" "$ENV{ProgramFiles}/Npcap"
  NO_DEFAULT_PATH)

if(WPCAP_DLL AND PACKET_DLL)
  add_custom_command(TARGET serviceApp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${WPCAP_DLL}" $<TARGET_FILE_DIR:serviceApp>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PACKET_DLL}" $<TARGET_FILE_DIR:serviceApp>
    COMMENT "Copying Npcap runtime DLLs to output")
else()
  message(WARNING "Npcap runtime DLLs (wpcap.dll/Packet.dll) not found in ${_WPDPACK_LIBDIR} or system locations. The app may require an Npcap runtime installed to run.")
endif()
