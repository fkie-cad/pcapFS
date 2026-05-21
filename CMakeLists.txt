cmake_minimum_required(VERSION 3.21)
project(pcapFS VERSION 0.6.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "pcapFS is Linux-only (requires FUSE3).")
endif()

set(PCAPFS_INDEX_VERSION_MAJOR 0)
set(PCAPFS_INDEX_VERSION_MINOR 6)

include(FetchContent)
include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules/)
list(APPEND CMAKE_PREFIX_PATH ${PROJECT_SOURCE_DIR}/dependencies/)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH TRUE)

configure_file(${PROJECT_SOURCE_DIR}/src/versions.h.in
        ${PROJECT_BINARY_DIR}/generated/versions.h @ONLY)

# get Fusepp; we mirror into a Fusepp/ subdirectory
FetchContent_Declare(Fusepp
        GIT_REPOSITORY https://github.com/jachappell/Fusepp.git
        GIT_TAG        cd58b6bbadfd20bf17d83411e4af2c9afa87d253
        GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(Fusepp)
set(fusepp_include_dir ${PROJECT_BINARY_DIR}/fusepp-include)
file(MAKE_DIRECTORY ${fusepp_include_dir}/Fusepp)
file(COPY
        ${fusepp_SOURCE_DIR}/Fuse.h
        ${fusepp_SOURCE_DIR}/Fuse.cpp
        ${fusepp_SOURCE_DIR}/Fuse-impl.h
        DESTINATION ${fusepp_include_dir}/Fusepp)
add_library(fusepp_iface INTERFACE)
target_include_directories(fusepp_iface INTERFACE ${fusepp_include_dir})
add_library(Fusepp::Fusepp ALIAS fusepp_iface)

# get cpptoml; needs a patch on top of the unmaintained skystrife/cpptoml repo.
set(CPPTOML_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(ENABLE_LIBCXX OFF CACHE INTERNAL "")
FetchContent_Declare(cpptoml
        GIT_REPOSITORY https://github.com/skystrife/cpptoml.git
        GIT_TAG        fededad7169e538ca47e11a9ee9251bc361a9a65
        GIT_SHALLOW    TRUE
        PATCH_COMMAND  patch -p1 -N -i ${PROJECT_SOURCE_DIR}/cmake/patches/cpptoml.patch || true)
# EXCLUDE_FROM_ALL suppresses cpptoml's own install rules so its header and
# CMake config files don't leak into our `cmake --install` output. Replace
# with `FetchContent_MakeAvailable(cpptoml EXCLUDE_FROM_ALL)` once the
# minimum CMake is >= 3.28.
FetchContent_GetProperties(cpptoml)
if(NOT cpptoml_POPULATED)
    FetchContent_Populate(cpptoml)
    add_subdirectory(${cpptoml_SOURCE_DIR} ${cpptoml_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
# cpptoml's own CMakeLists exposes an INTERFACE target named `cpptoml`;
# alias it to match the cpptoml::cpptoml convention used by the source.
if(NOT TARGET cpptoml::cpptoml)
    add_library(cpptoml::cpptoml ALIAS cpptoml)
endif()

# get nlohmann_json. Prefer system version if available.
option(PCAPFS_USE_SYSTEM_JSON "Use system nlohmann_json if available" ON)
if(PCAPFS_USE_SYSTEM_JSON)
    find_package(nlohmann_json 3.12.0 QUIET)
endif()
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(nlohmann_json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG        v3.12.0
            GIT_SHALLOW    TRUE)
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    # See cpptoml block above re: EXCLUDE_FROM_ALL
    FetchContent_GetProperties(nlohmann_json)
    if(NOT nlohmann_json_POPULATED)
        FetchContent_Populate(nlohmann_json)
        add_subdirectory(${nlohmann_json_SOURCE_DIR} ${nlohmann_json_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
endif()

find_package(Boost COMPONENTS filesystem iostreams log program_options regex serialization REQUIRED)
find_package(FUSE3 REQUIRED)
find_package(OpenSSL 3 REQUIRED)
find_package(PcapPlusPlus 25.05 REQUIRED)
find_package(ZLIB REQUIRED)

set(PCAPFS_COMMON_SOURCES
        src/commontypes.h
        src/config.cpp
        src/decodemap.h
        src/exceptions.h
        src/index.cpp
        src/logging.cpp
        src/properties.cpp
        src/utils.cpp
        src/pcapfs.cpp
        src/dirlayout.cpp
        src/filefactory.cpp
        src/file.cpp
        src/capturefiles/capturefile.cpp
        src/capturefiles/pcap.cpp
        src/capturefiles/pcapng.cpp
        src/crypto/decrypt_symmetric.cpp
        src/crypto/cryptutils.cpp
        src/crypto/ja4.cpp
        src/virtualfiles/cobaltstrike/cs_callback_codes.h
        src/virtualfiles/cobaltstrike/cs_command_codes.h
        src/virtualfiles/cobaltstrike/cs_manager.cpp
        src/keyfiles/tlskey.cpp
        src/keyfiles/xorkey.cpp
        src/keyfiles/cskey.cpp
        src/virtualfiles/virtualfile.cpp
        src/virtualfiles/ftp.cpp
        src/virtualfiles/ftpcontrol.cpp
        src/virtualfiles/ftp/ftp_commands.cpp
        src/virtualfiles/ftp/ftp_response_codes.h
        src/virtualfiles/ftp/ftp_manager.cpp
        src/virtualfiles/ftp/ftp_utils.cpp
        src/virtualfiles/dns.cpp
        src/virtualfiles/http.cpp
        src/virtualfiles/tls.cpp
        src/virtualfiles/tcp.cpp
        src/virtualfiles/udp.cpp
        src/virtualfiles/xor.cpp
        src/virtualfiles/cobaltstrike.cpp
        src/virtualfiles/ssh.cpp
        src/virtualfiles/dhcp.cpp
        src/virtualfiles/smbcontrol.cpp
        src/virtualfiles/smb/smb_packet.cpp
        src/virtualfiles/smb/smb_structs.h
        src/virtualfiles/smb/smb_messages.h
        src/virtualfiles/smb/smb_constants.h
        src/virtualfiles/smb/smb_utils.cpp
        src/virtualfiles/smb/smb_manager.cpp
        src/virtualfiles/serverfile.cpp
        src/virtualfiles/smb.cpp
        src/virtualfiles/serverfile_manager.cpp
        )

set(PCAPFS_LINK_LIBRARIES
        Boost::filesystem Boost::iostreams Boost::log Boost::program_options Boost::regex Boost::serialization
        cpptoml::cpptoml
        FUSE3::FUSE3
        Fusepp::Fusepp
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        PcapPlusPlus::PcapPlusPlus
        ZLIB::ZLIB
        )

set(COMPILE_FEATURES cxx_std_14)

add_library(pcapfs_obj OBJECT ${PCAPFS_COMMON_SOURCES})
target_compile_features(pcapfs_obj PUBLIC ${COMPILE_FEATURES})
target_compile_options(pcapfs_obj PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(pcapfs_obj PUBLIC ${PCAPFS_LINK_LIBRARIES})
target_include_directories(pcapfs_obj PUBLIC ${PROJECT_BINARY_DIR}/generated)
target_compile_definitions(pcapfs_obj PRIVATE "DEBUG=$<CONFIG:Debug>")

add_executable(pcapfs src/main.cpp)
target_link_libraries(pcapfs PRIVATE pcapfs_obj)

install(TARGETS pcapfs RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if (BUILD_TESTING)
    find_package(Catch2 2 REQUIRED)
    include(CTest)
    include(Catch)
    set(TEST_PCAP_PATH ${PROJECT_SOURCE_DIR}/tests/system/system-tests.pcap)
    set(UNIT_TEST_KEY_FILE_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/unit/keyfiles)
    set(TEST_DATA_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/data)
    configure_file(${PROJECT_SOURCE_DIR}/tests/unit/constants.h.in
            ${PROJECT_BINARY_DIR}/generated/tests/unit/constants.h @ONLY)
    add_executable(unittests
            tests/unit/main.cpp
            tests/unit/test-command-line-options.cpp
            tests/unit/test-utils.cpp
            tests/unit/test-index.cpp
            )
    target_link_libraries(unittests PRIVATE pcapfs_obj Catch2::Catch2)
    target_include_directories(unittests PRIVATE
            ${PROJECT_BINARY_DIR}/generated/tests/unit)
    catch_discover_tests(unittests)
endif ()
