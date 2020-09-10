option(ABY_BUILD_EXE "Build executables" OFF)
set(ABY_LIBRARY_TYPE 
    CACHE STRING "[STATIC | SHARED | MODULE] The type of library in which ABY will be built. Default: STATIC"
)
set_property(CACHE ABY_LIBRARY_TYPE PROPERTY STRINGS "STATIC" "SHARED" "MODULE")

string(TOUPPER "${ABY_LIBRARY_TYPE}" ABY_LIBRARY_TYPE)
if("${ABY_LIBRARY_TYPE}" STREQUAL "")
    set(ABY_LIBRARY_TYPE "SHARED")
elseif(NOT "${ABY_LIBRARY_TYPE}" STREQUAL "STATIC" AND
       NOT "${ABY_LIBRARY_TYPE}" STREQUAL "SHARED" AND
       NOT "${ABY_LIBRARY_TYPE}" STREQUAL "MODULE")
    message(WARNING 
        "Unknown library type: ${ABY_LIBRARY_TYPE}. "
        "Setting ABY_LIBRARY_TYPE to default value."
    )
    set(ABY_LIBRARY_TYPE "SHARED")
endif()

set(DEPENDENCY_DIR "${DEPENDENCY_DIR}" CACHE PATH "Path to directory, where dependencies will be downloaded.")
if(DEPENDENCY_DIR STREQUAL "")
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/extern/dependencies")
        file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/extern/dependencies")
    endif()
    set(DEPENDENCY_DIR "${CMAKE_SOURCE_DIR}/extern/dependencies")
endif()

# Set build type to `Release` if none was specified:
# (cf. https://gitlab.kitware.com/cmake/community/wikis/FAQ#how-can-i-change-the-default-build-mode-and-see-it-reflected-in-the-gui)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release
        CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "None" "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif(NOT CMAKE_BUILD_TYPE)

#Cache Variables related to ENCRYPTO_utils dependency
set(ENCRYPTO_utils_SOURCE
    CACHE PATH "Path to ENCRYPTO_utils source.")
set(ENCRYPTO_utils_REPOSITORY https://github.com/oliver-schick/ENCRYPTO_utils.git
    CACHE STRING "Git repository of ENCRYPTO_utils project.")
set(ENCRYPTO_utils_TAG origin/master
    CACHE STRING "Git tag of downloaded ENCRYPTO_utils project.")

#Cache Variables related to OTExtension dependency
set(OTExtension_SOURCE
    CACHE PATH "Path to OTExtension source.")
set(OTExtension_REPOSITORY https://github.com/oliver-schick/OTExtension.git
    CACHE STRING "Git repository of OTExtension project.")
set(OTExtension_TAG origin/master
    CACHE STRING "Git tag of downloaded OTExtension project.")

#Cache Variables related to BOOST dependency
option(DOWNLOAD_BOOST "Set to download boost libraries." OFF)
set(BOOST_SOURCE
    CACHE PATH "Path to boost source location.")
set(BOOST_URL https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.bz2
    CACHE STRING "Boost download URL.")
set(BOOST_URL_HASH SHA256=8f32d4617390d1c2d16f26a27ab60d97807b35440d45891fa340fc2648b04406
    CACHE STRING "Boost download URL SHA256 checksum.")

#Cache Variables related to BOOST_CMAKE dependency
set(BOOST_CMAKE_SOURCE
    CACHE PATH "Path to boost-cmake source.")
set(BOOST_CMAKE_REPOSITORY https://github.com/Orphis/boost-cmake.git
    CACHE STRING "Repository to boost-cmake project.")
set(BOOST_CMAKE_TAG 70b12f62da331dd402b78102ec8f6a15d59a7af9
    CACHE STRING "Git tag of boost-cmake")

#Cache Variables related to GMP dependency
option(BUILD_GMP "Build GMP library if none is found." OFF)
option(FORCE_GMP_BUILD "Force building of GMP library (use if installed GMP library is not compatible with build)." OFF)
set(GMP_LIBRARY_DIR
    CACHE PATH "Path to GMP library.")
set(GMP_INCLUDES
    CACHE PATH "Path to GMP include directories.")
set(GMP_SOURCE
    CACHE PATH "Path to GMP source (If building GMP).")
set(GMP_URL https://gmplib.org/download/gmp/gmp-6.2.0.tar.lz
    CACHE STRING "URL of GMP source.")
set(GMP_URL_HASH SHA512=9975e8766e62a1d48c0b6d7bbdd2fccb5b22243819102ca6c8d91f0edd2d3a1cef21c526d647c2159bb29dd2a7dcbd0d621391b2e4b48662cf63a8e6749561cd 
    CACHE STRING "Hash of GMP source archive.")
set(GMP_LIBRARY_TYPE
    CACHE STRING "[SHARED | STATIC]: Type of GMP library linked to project.")
set_property(CACHE GMP_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED)
mark_as_advanced(FORCE_GMP_BUILD)

include(AndroidCacheVariables)
