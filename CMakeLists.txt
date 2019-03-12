cmake_minimum_required(VERSION 3.8)
project(pcapFS VERSION 0.3.0 LANGUAGES CXX)
set(PCAPFS_INDEX_VERSION_MAJOR 0)
set(PCAPFS_INDEX_VERSION_MINOR 3)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules/)
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_SOURCE_DIR}/dependencies/)

list(INSERT CMAKE_INCLUDE_PATH 0 ${CMAKE_SOURCE_DIR}/dependencies/include/)
set(ENV{PKG_CONFIG_PATH}
        ${CMAKE_SOURCE_DIR}/dependencies/lib/pkgconfig/:${CMAKE_SOURCE_DIR}/dependencies/lib64/pkgconfig/)

configure_file(${CMAKE_SOURCE_DIR}/src/versions.h.in ${CMAKE_SOURCE_DIR}/src/versions.h)

find_package(Boost COMPONENTS filesystem iostreams log program_options system serialization REQUIRED)
find_package(cpptoml REQUIRED)
find_package(FUSE3 REQUIRED)
find_package(Fusepp REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(ZLIB REQUIRED)

set(PCAPFS_COMMON_SOURCES
        src/commontypes.h
        src/config.cpp
        src/decodemap.h
        src/exceptions.h
        src/index.cpp
        src/offsets.h
        src/logging.cpp
        src/properties.h
        src/utils.cpp
        src/pcapfs.cpp
        src/dirlayout.cpp
        src/filefactory.cpp
        src/file.cpp
        src/capturefiles/capturefile.cpp
        src/capturefiles/pcap.cpp
        src/capturefiles/pcapng.cpp
        src/keyfiles/sslkey.cpp
        src/keyfiles/xorkey.cpp
        src/virtualfiles/virtualfile.cpp
        src/virtualfiles/ftp.cpp
        src/virtualfiles/ftpcontrol.cpp
        src/virtualfiles/ftp/ftp_commands.cpp
        src/virtualfiles/ftp/ftp_response_codes.h
        src/virtualfiles/ftp/ftp_port_bridge.cpp
        src/virtualfiles/dns.cpp
        src/virtualfiles/http.cpp
        src/virtualfiles/ssl.cpp
        src/virtualfiles/tcp.cpp
        src/virtualfiles/udp.cpp
        src/virtualfiles/xor.cpp
        )

set(PCAPFS_LINK_LIBRARIES
        Boost::filesystem Boost::iostreams Boost::log Boost::program_options Boost::system Boost::serialization
        FUSE3::FUSE3
        Fusepp::Fusepp
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        PcapPlusPlus::PcapPlusPlus
        ZLIB::ZLIB
        )

set(COMPILE_FEATURES cxx_std_14)

add_executable(pcapfs src/main.cpp ${PCAPFS_COMMON_SOURCES})
target_compile_options(pcapfs PRIVATE -Wall -Wextra)
target_compile_features(pcapfs PRIVATE ${COMPILE_FEATURES})
target_link_libraries(pcapfs PRIVATE ${PCAPFS_LINK_LIBRARIES})


if (BUILD_TESTING)
    find_package(Catch2 REQUIRED)
    include(CTest)
    include(Catch)
    set(TEST_PCAP_PATH ${CMAKE_SOURCE_DIR}/tests/system/system-tests.pcap)
    set(UNIT_TEST_KEY_FILE_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/unit/keyfiles)
    set(TEST_DATA_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/data)
    configure_file(${CMAKE_SOURCE_DIR}/tests/unit/constants.h.in ${CMAKE_SOURCE_DIR}/tests/unit/constants.h)
    add_executable(unittests
            ${PCAPFS_COMMON_SOURCES}
            tests/unit/main.cpp
            tests/unit/test-command-line-options.cpp
            tests/unit/test-utils.cpp
            tests/unit/test-index.cpp
            )
    target_compile_features(unittests PRIVATE ${COMPILE_FEATURES})
    target_link_libraries(unittests PRIVATE ${PCAPFS_LINK_LIBRARIES} Catch2::Catch2)
    catch_discover_tests(unittests)
endif ()
