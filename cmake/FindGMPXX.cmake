
find_path(GMPXX_INCLUDE_DIR gmpxx.h)

# TODO: get version

find_library(GMPXX_LIBRARY NAMES gmpxx)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMPXX
    FOUND_VAR GMPXX_FOUND
    REQUIRED_VARS
        GMPXX_LIBRARY
        GMPXX_INCLUDE_DIR
)

if(GMPXX_FOUND AND NOT TARGET GMP::GMPXX)
    add_library(GMP::GMPXX UNKNOWN IMPORTED)
    set_target_properties(GMP::GMPXX PROPERTIES
        IMPORTED_LOCATION "${GMPXX_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GMPXX_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(
    GMPXX_INCLUDE_DIR
    GMPXX_LIBRARY
)
