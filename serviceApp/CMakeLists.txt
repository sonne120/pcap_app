cmake_minimum_required(VERSION 4.1)

# Add source to this project's executable.
add_executable (serviceApp "serviceApp.cpp" "serviceApp.h" "Npcap.cpp" "Npcap.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET serviceApp PROPERTY CXX_STANDARD 20)
endif()

 if(WIN32)
    # Fallback to local SDK paths in repo: header/WpdPack/WpdPack
set(WPDPACK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../header/WpdPack/WpdPack" CACHE PATH "Path to WpdPack root")
if(NOT EXISTS "${WPDPACK_ROOT}")
  message(FATAL_ERROR "WpdPack not found at ${WPDPACK_ROOT}. Expected repo-local SDK under header/WpdPack/WpdPack")
endif()

# Includes (pcap.h is under Include/pcap, but including both is fine)
target_include_directories(serviceApp PRIVATE
  "${WPDPACK_ROOT}/Include"
  "${WPDPACK_ROOT}/Include/pcap"
)

# Determine correct lib dir for arch
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib/x64")
else()
  set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib")
endif()

# Resolve absolute library paths
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

endif()

if(WIN32)
  # Try to locate the runtime DLLs (they may not be included in WpdPack)
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
endif()
