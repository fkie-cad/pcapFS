# FindFusepp.cmake
#
# Finds the Fusepp library.
#
# This will define the following variables
#
#    Fusepp_FOUND
#    Fusepp_INCLUDE_DIRS
#
# and the following imported targets
#
#    Fusepp::Fusepp
#

if (Fusepp_INCLUDE_DIR)
    set(Fusepp_FIND_QUIETLY TRUE)
endif ()

find_path(Fusepp_INCLUDE_DIR
        NAMES Fuse-impl.h
        PATH_SUFFIXES Fusepp)

mark_as_advanced(Fuse_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Fusepp
        REQUIRED_VARS Fusepp_INCLUDE_DIR
        )

if (Fusepp_FOUND)
    set(Fusepp_INCLUDE_DIRS ${Fusepp_INCLUDE_DIR})
endif ()

if (Fusepp_FOUND AND NOT TARGET Fusepp::Fusepp)
    add_library(Fusepp::Fusepp INTERFACE IMPORTED)
    set_target_properties(Fusepp::Fusepp PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${Fusepp_INCLUDE_DIR}"
            )
endif ()
