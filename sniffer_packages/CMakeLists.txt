cmake_minimum_required(VERSION 3.21)

project(sniffer_packages LANGUAGES C CXX)

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# Platform Check

if(NOT (WIN32 OR APPLE))
    message(FATAL_ERROR "This project only supports Windows and Apple platforms.")
endif()

# ----------------------------------------------------------------------------
# Architecture Detection (Windows)
# ----------------------------------------------------------------------------
if(WIN32)
    set(_RAW_PLATFORM "")
    if(CMAKE_VS_PLATFORM_NAME)
        set(_RAW_PLATFORM "${CMAKE_VS_PLATFORM_NAME}")
    elseif(CMAKE_GENERATOR_PLATFORM)
        set(_RAW_PLATFORM "${CMAKE_GENERATOR_PLATFORM}")
    elseif(CMAKE_SYSTEM_PROCESSOR)
        set(_RAW_PLATFORM "${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    
    string(TOLOWER "${_RAW_PLATFORM}" _RAW_PLATFORM_LC)
    
    set(SNIFFER_ARCH_X86   FALSE)
    set(SNIFFER_ARCH_X64   FALSE)
    set(SNIFFER_ARCH_ARM64 FALSE)
    
    if(_RAW_PLATFORM_LC MATCHES "^(win32|x86|i[3-6]86)$")
        set(SNIFFER_ARCH_X86 TRUE)
    elseif(_RAW_PLATFORM_LC MATCHES "^(x64|x86_64|amd64)$")
        set(SNIFFER_ARCH_X64 TRUE)
    elseif(_RAW_PLATFORM_LC MATCHES "arm64" OR _RAW_PLATFORM_LC MATCHES "aarch64")
        set(SNIFFER_ARCH_ARM64 TRUE)
    endif()
endif()

# ----------------------------------------------------------------------------
# Sources
# ----------------------------------------------------------------------------
set(SNIFFER_SOURCES
    mainFunc.cpp
    ipc.cpp
    packages_globals.cpp
    builderDevice.cpp
    Sniffer.cpp
)
set(SNIFFER_HEADERS
    builderDevice.h
    ether_ntoa.h
    handleProto.h
    ipc.h
    packages.h
    struct.h
    Sniffer.h
)

add_library(sniffer_packages SHARED ${SNIFFER_SOURCES} ${SNIFFER_HEADERS})

target_include_directories(sniffer_packages PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Platform Specific Settings

if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    
    target_compile_definitions(sniffer_packages PRIVATE WIN32_LEAN_AND_MEAN)
    
    if(SNIFFER_ARCH_X86)
        target_compile_definitions(sniffer_packages PRIVATE SNIFFER_ARCH_X86)
    elseif(SNIFFER_ARCH_X64)
        target_compile_definitions(sniffer_packages PRIVATE SNIFFER_ARCH_X64)
    elseif(SNIFFER_ARCH_ARM64)
        target_compile_definitions(sniffer_packages PRIVATE SNIFFER_ARCH_ARM64)
    endif()

    if(MSVC)
        target_compile_options(sniffer_packages PRIVATE /permissive- /W4 /FS)
        target_compile_options(sniffer_packages PRIVATE
            $<$<CONFIG:Debug>:/Od /Zi /RTC1>
            $<$<CONFIG:Release>:/O2>
        )
        target_link_options(sniffer_packages PRIVATE $<$<CONFIG:Debug>:/DEBUG:FULL /INCREMENTAL:NO>)
    endif()

    # WpdPack (WinPcap/Npcap)
    set(WPDPACK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../header/WpdPack/WpdPack")
    if(EXISTS "${WPDPACK_ROOT}")
        set(_WPDPACK_LIBDIR "")
        if(SNIFFER_ARCH_X86)
            set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib")
        elseif(SNIFFER_ARCH_X64)
            set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib/x64")
        elseif(SNIFFER_ARCH_ARM64)
            set(_WPDPACK_LIBDIR "${WPDPACK_ROOT}/Lib/arm64")
        endif()

        if(EXISTS "${_WPDPACK_LIBDIR}")
            target_include_directories(sniffer_packages PRIVATE "${WPDPACK_ROOT}/Include" "${WPDPACK_ROOT}/Include/pcap")
            find_library(WPCAP_LIB NAMES wpcap PATHS "${_WPDPACK_LIBDIR}" NO_DEFAULT_PATH)
            find_library(PACKET_LIB NAMES Packet PATHS "${_WPDPACK_LIBDIR}" NO_DEFAULT_PATH)
            
            if(WPCAP_LIB AND PACKET_LIB)
                target_link_libraries(sniffer_packages PRIVATE ws2_32 iphlpapi ${WPCAP_LIB} ${PACKET_LIB})
                target_compile_definitions(sniffer_packages PRIVATE SNIFFER_CAPTURE_ENABLED=1)
            else()
                message(WARNING "WpdPack libraries not found in ${_WPDPACK_LIBDIR}. Building stub.")
                target_compile_definitions(sniffer_packages PRIVATE SNIFFER_PCAP_DISABLED SNIFFER_CAPTURE_ENABLED=0)
            endif()
        else()
             message(WARNING "WpdPack lib dir not found: ${_WPDPACK_LIBDIR}. Building stub.")
             target_compile_definitions(sniffer_packages PRIVATE SNIFFER_PCAP_DISABLED SNIFFER_CAPTURE_ENABLED=0)
        endif()
    else()
        message(WARNING "WpdPack root not found at ${WPDPACK_ROOT}. Building stub.")
        target_compile_definitions(sniffer_packages PRIVATE SNIFFER_PCAP_DISABLED SNIFFER_CAPTURE_ENABLED=0)
    endif()

elseif(APPLE)
    target_compile_definitions(sniffer_packages PRIVATE
        ip_vhl=ip_hl
        sport=th_sport
        dport=th_dport
        IPv4_ETHERTYPE=ETHERTYPE_IP
        SIZE_ETHERNET=ETHER_HDR_LEN
    )
    
    target_compile_options(sniffer_packages PRIVATE -Wall -Wextra -Wpedantic)

    find_path(PCAP_INCLUDE_DIR pcap.h PATHS /usr/include /usr/local/include /opt/homebrew/include)
    find_library(PCAP_LIBRARY NAMES pcap PATHS /usr/lib /usr/local/lib /opt/homebrew/lib)
    
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        target_include_directories(sniffer_packages PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(sniffer_packages PRIVATE ${PCAP_LIBRARY})
        target_compile_definitions(sniffer_packages PRIVATE SNIFFER_CAPTURE_ENABLED=1)
    else()
        message(WARNING "libpcap not found. Building stub.")
        target_compile_definitions(sniffer_packages PRIVATE SNIFFER_PCAP_DISABLED SNIFFER_CAPTURE_ENABLED=0)
    endif()
endif()

# Output directories
set_target_properties(sniffer_packages PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
