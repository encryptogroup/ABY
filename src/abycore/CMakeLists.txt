cmake_minimum_required(VERSION 3.13)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules")

#Watch out when changing name of ABY_* variables: 
#They are referenced as ${PROJECT_NAME}_* in InstallConfig.cmake, 
#ExternalBuildHelper.cmake and AddBOOST_CMAKE.cmake
if(ANDROID)
     if(ANDROID_ARM_NEON)
         set(ABY_INSTALL_PREFIX "platforms/${ANDROID_PLATFORM}/arch-${ANDROID_SYSROOT_ABI}/NEON")
     else(ANDROID_ARM_NEON)
         set(ABY_INSTALL_PREFIX "platforms/${ANDROID_PLATFORM}/arch-${ANDROID_SYSROOT_ABI}")
     endif(ANDROID_ARM_NEON)
     set(ABY_INSTALL_INCLUDE "${ABY_INSTALL_PREFIX}/include")
     set(ABY_INSTALL_LIB "${ABY_INSTALL_PREFIX}/lib")
     set(ABY_INSTALL_ARCHIVE "${ABY_INSTALL_PREFIX}/lib")
     set(ABY_INSTALL_CONFIG "")
else(ANDROID)
     set(ABY_INSTALL_PREFIX "")
     set(ABY_INSTALL_INCLUDE "include")
     set(ABY_INSTALL_LIB "lib")
     set(ABY_INSTALL_ARCHIVE "lib")
     set(ABY_INSTALL_CONFIG "")
endif(ANDROID)

#Watch out when changing name of variable ABY_DEPENDENCIES_TO_EXPORT:
#It is referenced as ${PROJECT_NAME}_DEPENDENCIES_TO_EXPORT in AddBoost.cmake
set(ABY_DEPENDENCIES_TO_EXPORT)

if(ANDROID AND CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${ANDROID_NDK}/usr/local" 
        CACHE PATH "Default install directory for android builds." FORCE)
endif()

if(NOT TARGET stdc++fs)
    list(APPEND BOOST_TARGETS_REQUIRED Boost::boost Boost::filesystem)
endif()

include(AddGMP)
include(AddBoost)
include(AddENCRYPTO_utils)
include(AddOTExtension)
find_package(Threads REQUIRED)

add_library(aby ${ABY_LIBRARY_TYPE}
    aby/abyparty.cpp
    aby/abysetup.cpp
    circuit/abycircuit.cpp
    circuit/arithmeticcircuits.cpp
    circuit/booleancircuits.cpp
    circuit/circuit.cpp
    circuit/share.cpp
    DGK/dgkparty.cpp
    DJN/djnparty.cpp
    sharing/arithsharing.cpp
    sharing/boolsharing.cpp
    sharing/sharing.cpp
    sharing/splut.cpp
    sharing/yaoclientsharing.cpp
    sharing/yaoserversharing.cpp
    sharing/yaosharing.cpp
)
set_target_properties(aby PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
if(NOT TARGET stdc++fs)
    set_target_properties(aby PROPERTIES COMPILE_DEFINITIONS USE_BOOST_FILESYSTEM)
endif()

add_library(ABY::aby ALIAS aby)

target_compile_options(aby PRIVATE "-Wall" "-Wextra")

target_include_directories(aby
    PUBLIC
        $<INSTALL_INTERFACE:${ABY_INSTALL_INCLUDE}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
)
target_link_libraries(aby
    PUBLIC OTExtension::otextension
    PUBLIC ENCRYPTO_utils::encrypto_utils
    PUBLIC GMP::GMP
    PUBLIC Threads::Threads
    PRIVATE Boost::filesystem
)

include(InstallConfig)
install_config(ABY_INSTALL_LOCATION "ABY" ABY::aby)

install(TARGETS aby ${ABY_DEPENDENCIES_TO_EXPORT}
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION "${ABY_INSTALL_LIB}"
        LIBRARY DESTINATION "${ABY_INSTALL_LIB}"
        INCLUDES DESTINATION "${ABY_INSTALL_INCLUDE}")
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DESTINATION "${ABY_INSTALL_INCLUDE}"
        FILES_MATCHING REGEX ".*\\.h(pp|h)?$" REGEX ".*cmake.*" EXCLUDE)
export(TARGETS aby ${ABY_DEPENDENCIES_TO_EXPORT}
       NAMESPACE "${PROJECT_NAME}::"
       FILE "${PROJECT_NAME}Targets.cmake")
install(EXPORT "${PROJECT_NAME}Targets"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${ABY_INSTALL_LOCATION}")
