cmake_minimum_required(VERSION 3.13)

#Set download command according to whether sorce directory is available and if
#a dependency directory is given, in order to cash downloads in dependency directory
if(NOT "${GMP_SOURCE}" STREQUAL "")
    set(GMP_DOWNLOAD_COMMANDS URL "${GMP_SOURCE}")
else()
    set(GMP_DOWNLOAD_COMMANDS URL "${GMP_URL}" URL_HASH "${GMP_URL_HASH}")
    if(NOT "${DEPENDENCY_DIR}" STREQUAL "")
        list(APPEND GMP_DOWNLOAD_COMMANDS DOWNLOAD_DIR ${DEPENDENCY_DIR})
    endif()
endif()

include(ExternalBuildHelper)

#Set Environment variables and configure flags, depending on whether building for Android or Linux
if(ANDROID)
    get_android_target_compiler(GMP_ANDROID_COMPILER_PREFIX GMP_ANDROID_COMPILER_DIR)
    set(GMP_CONFIGURE_FLAGS --prefix=<INSTALL_DIR> --host=${CMAKE_C_COMPILER_TARGET})
    set(GMP_ENVIRONMENT_VARIABLES
        "CC=${GMP_ANDROID_COMPILER_DIR}/${GMP_ANDROID_COMPILER_PREFIX}-clang"
        "CFLAGS=-Wno-unused-command-line-argument -Wno-unused-value -Wno-shift-op-parentheses"
    )
    set(GMPXX_ENVIRONMENT_VARIABLES
        "CXX=${GMP_ANDROID_COMPILER_DIR}/${GMP_ANDROID_COMPILER_PREFIX}-clang++"
        "CXXFLAGS=-Wno-unused-command-line-argument -Wno-unused-value -Wno-shift-op-parentheses"
    )
else()
    set(GMP_CONFIGURE_FLAGS --prefix=<INSTALL_DIR>)
    set(GMP_ENVIRONMENT_VARIABLES "")
    set(GMPXX_ENVIRONMENT_VARIABLES "")
endif()

#Set Environment variables and configure flags, depending on whether building with or without c++ support
if(NOT GMP_ONLY)
    list(APPEND GMP_CONFIGURE_FLAGS --enable-cxx)
    list(APPEND GMP_ENVIRONMENT_VARIABLES ${GMPXX_ENVIRONMENT_VARIABLES})
endif()

#Set Environment variables and configure flags, depending on whether building with or without c++ support
if("${GMP_LIBRARY_TYPE}" STREQUAL "STATIC")
    list(APPEND GMP_CONFIGURE_FLAGS --enable-static --disable-shared)
elseif("${GMP_LIBRARY_TYPE}" STREQUAL "SHARED")
    list(APPEND GMP_CONFIGURE_FLAGS --enable-shared --disable-static)
endif()

find_program(MAKE_EXE NAMES gmake nmake make)

include(ExternalProject)
ExternalProject_Add(GMP
    PREFIX GMP_PREFIX
    ${GMP_DOWNLOAD_COMMANDS}
    UPDATE_DISCONNECTED TRUE
    CONFIGURE_COMMAND "${CMAKE_COMMAND}" -E env ${GMP_ENVIRONMENT_VARIABLES} <SOURCE_DIR>/configure ${GMP_CONFIGURE_FLAGS}
    BUILD_COMMAND "${CMAKE_COMMAND}" -E env ${GMP_ENVIRONMENT_VARIABLES} ${MAKE_EXE}
    INSTALL_COMMAND "${CMAKE_COMMAND}" -E env ${GMP_ENVIRONMENT_VARIABLES} ${MAKE_EXE} install
)
ExternalProject_Get_Property(GMP INSTALL_DIR)
ExternalProject_Get_Property(GMP BINARY_DIR)

#Path that will be created upon downloading the GMP library
set(GMP_INCLUDE_DIR "${INSTALL_DIR}/include")
set(GMP_LIB_DIR "${INSTALL_DIR}/lib")

add_imported_library(TARGET GMP::GMP ${GMP_LIBRARY_TYPE}
    EXTERNAL_TARGET GMP
    EXTERNAL_LIB_DIR "lib"
    EXTERNAL_LIB_NAME gmp
    EXTERNAL_INCLUDES "include"
)
add_imported_library(TARGET GMP::GMPXX ${GMP_LIBRARY_TYPE}
    EXTERNAL_TARGET GMP
    EXTERNAL_LIB_DIR "lib"
    EXTERNAL_LIB_NAME gmpxx
    EXTERNAL_INCLUDES "include"
)
