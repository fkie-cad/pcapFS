cmake_minimum_required(VERSION 3.8)
project(pcapFS VERSION 0.1.0 LANGUAGES CXX)
set(PCAPFS_INDEX_VERSION_MAJOR 1)
set(PCAPFS_INDEX_VERSION_MINOR 1)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules/)
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_SOURCE_DIR}/dependencies/)

list(INSERT CMAKE_INCLUDE_PATH 0 ${CMAKE_SOURCE_DIR}/dependencies/include/)
set(ENV{PKG_CONFIG_PATH}
        ${CMAKE_SOURCE_DIR}/dependencies/lib/pkgconfig/:${CMAKE_SOURCE_DIR}/dependencies/lib64/pkgconfig/)

configure_file(${CMAKE_SOURCE_DIR}/src/versions.h.in ${CMAKE_SOURCE_DIR}/src/versions.h)

find_package(FUSE3 REQUIRED)
find_package(Fusepp REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(Boost COMPONENTS filesystem iostreams log program_options system serialization REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(pcapfs
        src/commontypes.h
        src/config.cpp
        src/decodemap.h
        src/exceptions.h
        src/index.cpp
        src/offsets.h
        src/logging.cpp
        src/main.cpp
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

target_compile_options(pcapfs PRIVATE -Wall -Wextra)
target_compile_features(pcapfs PRIVATE cxx_std_14)

target_link_libraries(pcapfs PRIVATE
        Boost::filesystem Boost::iostreams Boost::log Boost::program_options Boost::system Boost::serialization
        FUSE3::FUSE3
        Fusepp::Fusepp
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        PcapPlusPlus::PcapPlusPlus
        ZLIB::ZLIB
        )
