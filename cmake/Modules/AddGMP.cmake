cmake_minimum_required(VERSION 3.13)

#If cache variable is not set, use same library type as project.
if(NOT ANDROID AND "${GMP_LIBRARY_TYPE}" STREQUAL "")
    set(GMP_LIBRARY_TYPE "${${PROJECT_NAME}_LIBRARY_TYPE}")
#Emit an info message if library was set to another type than shared for android builds. 
elseif(ANDROID AND NOT "${GMP_LIBRARY_TYPE}" STREQUAL "" AND NOT "${GMP_LIBRARY_TYPE}" STREQUAL "SHARED")
    set(GMP_LIBRARY_TYPE "SHARED")
    message(STATUS "Only shared GMP builds supported for Android.")
#Set GMP to shared without emiting a status message, if cache variable is not set.
elseif(ANDROID)
    set(GMP_LIBRARY_TYPE "SHARED")
endif()

#Try to find GMP and GMPXX, unless user requests that GMP must be built.
if(NOT FORCE_GMP_BUILD)
    if(NOT TARGET GMP::GMP)
        find_package(GMP QUIET)
        #if target was added through find_package we install FindGMP.cmake as Config file
        if(TARGET GMP::GMP)
            set(GMP_FOUND TRUE)
            install(FILES ${PROJECT_SOURCE_DIR}/cmake/Modules/FindGMP.cmake
                DESTINATION "GMP"
	        RENAME "GMPConfig.cmake")
        endif()
    endif()
    if(NOT TARGET GMP::GMPXX)
        find_package(GMPXX QUIET)
        #if target was added through find_package we install FindGMPXX.cmake as Config file
        if(TARGET GMP::GMPXX)
            set(GMPXX_FOUND TRUE)
            install(FILES ${PROJECT_SOURCE_DIR}/cmake/Modules/FindGMPXX.cmake
                DESTINATION "GMPXX"
	        RENAME "GMPXXConfig.cmake")
        endif()
   endif()
endif()

if(NOT TARGET GMP::GMP OR NOT TARGET GMP::GMPXX)
    set(PFX ${CMAKE_${GMP_LIBRARY_TYPE}_LIBRARY_PREFIX})
    set(SFX ${CMAKE_${GMP_LIBRARY_TYPE}_LIBRARY_SUFFIX})
    set(GMP_LIBRARY_NAME ${PFX}gmp${SFX})
    set(GMPXX_LIBRARY_NAME$ ${PFX}gmpxx${SFX})
    include(ExternalBuildHelper)
    #gmp library can be found at user provided locations.
    if(EXISTS "${GMP_LIBRARY_DIR}/${GMP_LIBRARY_NAME}"
       AND EXISTS "${GMP_LIBRARY_DIR}/${GMPXX_LIBRARY_NAME}" 
       AND EXISTS "${GMP_INCLUDES}/gmp.h" 
       AND EXISTS "${GMP_INCLUDES}/gmpxx.h")
        message(STATUS "Found GMP and GMPXX at given location.")
        add_imported_library(TARGET GMP::GMP ${GMP_LIBRARY_TYPE}
                             EXTERNAL_LIB_DIR "${GMP_LIBRARY_DIR}"
                             EXTERNAL_LIB_NAME gmp
                             EXTERNAL_INCLUDES "${GMP_INCLUDES}")
        add_imported_library(TARGET GMP::GMPXX ${GMP_LIBRARY_TYPE}
                             EXTERNAL_LIB_DIR "${GMP_LIBRARY_DIR}"
                             EXTERNAL_LIB_NAME gmpxx
                             EXTERNAL_INCLUDES "${GMP_INCLUDES}")
    #If gmp library cannot be found, but is allowed to be build.
    elseif(BUILD_GMP OR FORCE_GMP_BUILD)
        message(STATUS "Adding GMP and GMPXX library to build.")
        set(GMP_ONLY OFF)
        include(BuildGMP)
    #Emit an error message if gmp library or gmp include directories cannot be found in cached variables
    #and either option BUILD_GMP or FORCE_GMP_BUILD is not set.
    else()
        message(SEND_ERROR "Did not find gmp in standard location." 
                           " Either set GMP_LIBRARY_DIR and GMP_INCLUDES to valid locations" 
                           " or enable GMP build by setting BUILD_GMP. ")
        return()
    endif()
    #Install gmp libraries.
    install_imported_library(GMP::GMP "GMP")
    install_imported_library(GMP::GMPXX "GMPXX")
endif()
