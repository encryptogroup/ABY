cmake_minimum_required(VERSION 3.13)

#get_android_target_compiler(<out-name> [out-dir])
#
#Calculates a target compiler name for android platform specific builds, based on the current 
#build parameters set by the android toolchain file. The android toolchain file must set the 
#variables ANDROID_ABI, ANDROID_TOOLCHAIN_ROOT and ANDROID_PLATFORM_LEVEL to correct values.
#
#out-var will be set to the appropriate target that can be passed as -target option to clang.
#out-dir is optional and if provided will be set to the directory containing the target specific 
#compilers. 
#For more information See https://developer.android.com/ndk/guides/other_build_systems
#
#Example 1: get_android_target_compiler(TARGET_COMPILER_NAME)
#           set(ENVIRONMENT "CXX=clang++" "CXXFLAGS=-target ${TARGET_COMPILER_NAME}")
#
#Example 2: get_android_target_compiler(COMPILER_PREFIX COMPILER_DIR)
#           set(ENVIRONMENT "CXX=${COMPILER_DIR}/${COMPILER_PREFIX}-clang++")
#
function(get_android_target_compiler RESULT_NAME)
    #If ANDROID_ABI is empty, there is no target to be found. Emit warning.
    if("${ANDROID_ABI}" STREQUAL ""
       OR NOT EXISTS "${ANDROID_TOOLCHAIN_ROOT}"
       OR "${ANDROID_PLATFORM_LEVEL}" STREQUAL "")
        message(SEND_ERROR "ANDROID_ABI, ANDROID_TOOLCHAIN_ROOT or ANDROID_PLATFORM_LEVEL were not set"
                           " to valid values. Cannot set android target compiler to any valid value.")
        return()
    endif()
    set(RES_DIR "${ANDROID_TOOLCHAIN_ROOT}/bin")
    if("${ANDROID_ABI}" STREQUAL "armeabi-v7a" OR "${ANDROID_ABI}" STREQUAL "armeabi-v7a with NEON")
        set(RES "armv7a-linux-androideabi${ANDROID_PLATFORM_LEVEL}")
    elseif("${ANDROID_ABI}" STREQUAL "arm64-v8a")
        set(RES "aarch64-linux-android${ANDROID_PLATFORM_LEVEL}")
    elseif("${ANDROID_ABI}" STREQUAL "x86")
        set(RES "i686-linux-android${ANDROID_PLATFORM_LEVEL}")
    elseif("${ANDROID_ABI}" STREQUAL "x86_64")
        set(RES "x86_64-linux-android${ANDROID_PLATFORM_LEVEL}")
    else()
        message(SEND_ERROR "Unsupported ANDROID_ABI: ${ANDROID_ABI}")
        return()
    endif()
    set(${RESULT_NAME} "${RES}" PARENT_SCOPE)
    #User provided second optional argument. Subsequent arguments are ignored.
    if(${ARGC} GREATER 1)
        set(${ARGV1} "${RES_DIR}" PARENT_SCOPE)
    endif()
endfunction()

#add_imported_library(TARGET <target> [SHARED|STATIC] 
#                     [EXTERNAL_TARGET external_target]
#                     [EXTERNAL_INCLUDES paths...]
#                     EXTERNAL_LIB_DIR path
#                     EXTERNAL_LIB_NAME name
#                     [EXTERNAL_LIB_NAME_IS_FULL]
#                     [NO_GLOBAL] [NO_WARN])
#
#Creates a linkable imported library from a target created with ExternalProject_Add,
#if EXTERNAL_TARGET is passed or simply import a library from a given location.
#TARGET <target>: the name of the created library target
#    [SHARED|STATIC]: The type of the imported library. If you don't specify any, UNKNOWN will be used.
#[EXTERNAL_TARGET external_target]: The name of the target added through ExternalProject_Add.
#                                   If it is not provided, no dependecy to any external target will
#                                   be defined. In that case, EXTERNAL_LIB_DIR and EXTERNAL_LIB_NAME
#                                   must be absolute paths. 
#EXTERNAL_INCLUDES paths...: Paths to include directories of external target. If no EXTERNAL_TARGET is provided, 
#                            these must be absolute and existing paths. See below for more information.
#EXTERNAL_LIB_DIR path: Path to lib directory or file of external target. If no EXTERNAL_TARGET is provided, 
#                            this must be an absolute and existing paths. See below for more information.
#EXTERNAL_LIB_NAME name: Name of library created by ExternalProject during build. If the library type
#                        is provided along with TARGET, then name may omit library prefixes and suffixes
#[EXTERNAL_LIB_NAME_IS_FULL]: EXTERNAL_LIB_NAME represent full library name. Prevents performing any
#                             checks and modification to library name.
#[NO_GLOBAL]: Created target will not be global.
#[NO_WARN]: Suppress all warnings emitted from this function.
#
#The external library and include directories usually do not exist when calling this function. 
#However, they will be created by ExternalProject, so the user must provide information about
#the include and lib directories, as they vary between each project.
#If a relative path is given for EXTERNAL_INCLUDES or EXTERNAL_LIB_DIR, the INSTALL_DIR property
#of ExternalProject will be used as root directory. If the paths do not exist, they will be
#created. EXTERNAL_INCLUDES and EXTERNAL_LIB_DIR must point to all directories filled with 
#include directories (or libraries in the case of EXTERNAL_LIB_DIR) that are created by the 
#external project after the install step of ExternalProject completes.
#
#This function may also be used to create an imported target that does not depend on a target created
#by ExternalProject_Add, by omitting EXTERNAL_TARGET. In this case EXTERNAL_INCLUDES and EXTERNAL_LIB_DIR must 
#point to absolute directories that already exist.
#
#Example 1: add_imported_library(TARGET Foo::foo STATIC
#                                EXTERNAL_TARGET Foo
#                                EXTERNAL_INCLUDES include fooinclude
#                                EXTERNAL_LIB_DIR lib
#                                EXTERNAL_LIB_NAME foo)
#
#Example 2: add_imported_library(TARGET Bar
#                                EXTERNAL_LIB_DIR /usr/lib
#                                EXTERNAL_LIB_NAME libbar.a)
#
function(add_imported_library)
    #Parse arguments
    set(options NO_GLOBAL NO_WARN EXTERNAL_LIB_NAME_IS_FULL)
    set(oneValueArgs EXTERNAL_TARGET EXTERNAL_LIB_DIR EXTERNAL_LIB_NAME)
    set(multiValueArgs TARGET EXTERNAL_INCLUDES)
    cmake_parse_arguments(IMPORT "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT "${IMPORT_UNPARSED_ARGUMENTS}" STREQUAL "")
        message(AUTHOR_WARNING "Arguments ${IMPORT_UNPARSED_ARGUMENTS} not recognized.")
    endif()

    #Handle Arguments passed to function and emit error messages for invalid arguments
    if(NOT IMPORT_TARGET)
        message(SEND_ERROR "(TARGET ${IMPORT_TARGET}) is not valid.")
        return()
    endif()

    list(GET IMPORT_TARGET 0 IMPORT_TARGET_NAME)
    list(LENGTH IMPORT_TARGET IMPORT_TARGET_LENGTH)
    #User did not provide [SHARED|STATIC]
    if(${IMPORT_TARGET_LENGTH} EQUAL 1)
        set(IMPORT_LIBRARY_TYPE UNKNOWN)
    #User provided [SHARED|STATIC]
    elseif(${IMPORT_TARGET_LENGTH} EQUAL 2)
        list(GET IMPORT_TARGET 1 IMPORT_LIBRARY_TYPE)
    #User provided too many arguments for target
    elseif(${IMPORT_TARGET_LENGTH} GREATER 2)
        if(NOT IMPORT_NO_WARN)    
            message(AUTHOR_WARNING "Too many arguments provided for TARGET, additional arguments will be ignored")
        endif()
        list(GET IMPORT_TARGET 1 IMPORT_LIBRARY_TYPE)
    endif()

    #User provided library type, but type is not valid
    if(NOT "${IMPORT_LIBRARY_TYPE}" STREQUAL "SHARED"
       AND NOT "${IMPORT_LIBRARY_TYPE}" STREQUAL "STATIC"
       AND NOT "${IMPORT_LIBRARY_TYPE}" STREQUAL "UNKNOWN")
        if(NOT IMPORT_NO_WARN)
            message(AUTHOR_WARNING "Unrecognized library type: ${IMPORT_LIBRARY_TYPE}. Using UNKNOWN as library type.")
        endif()
        set(IMPORT_LIBRARY_TYPE UNKNOWN)
    endif()
    
    #User provided non-existent EXTERNAL_TARGET
    if(DEFINED IMPORT_EXTERNAL_TARGET AND NOT TARGET "${IMPORT_EXTERNAL_TARGET}")
        message(SEND_ERROR "EXTERNAL_TARGET is set to a value that is not a target."
                           " Please provide a valid target or omit EXTERNAL_TARGET.")
        return()
    endif()

    #Get INSTALL_DIR of external project, as default root directory
    if(DEFINED IMPORT_EXTERNAL_TARGET)
        include(ExternalProject)
        ExternalProject_Get_Property(${IMPORT_EXTERNAL_TARGET} INSTALL_DIR)
    endif()

    #After invocation passed variable name will contain valid and existing path.
    #Variable remains unchanged if it already contained an absolute path. 
    #If the path Variable pointed to did not exist, it will be created
    macro(make_valid path_var)
        if(NOT IS_ABSOLUTE "${${path_var}}" AND DEFINED IMPORT_EXTERNAL_TARGET)
            set(${path_var} "${INSTALL_DIR}/${${path_var}}")
        elseif(NOT IS_ABSOLUTE "${${path_var}}" AND NOT DEFINED IMPORT_EXTERNAL_TARGET)
            message(SEND_ERROR "Did not provide an absolute path: ${${path_var}},"
                               " while not importing from external project.")
            return()
        endif()
        if(NOT EXISTS "${${path_var}}")
            file(MAKE_DIRECTORY "${${path_var}}")
        endif()
    endmacro()

    #Make EXTERNAL_INCLUDES and EXTERNAL_LIB_DIR point to valid directories
    set(VALID_IMPORT_EXTERNAL_INCLUDES)
    foreach(include_dir ${IMPORT_EXTERNAL_INCLUDES})
        make_valid(include_dir)
        list(APPEND VALID_IMPORT_EXTERNAL_INCLUDES "${include_dir}")
    endforeach()
    set(IMPORT_EXTERNAL_INCLUDES ${VALID_IMPORT_EXTERNAL_INCLUDES})
    make_valid(IMPORT_EXTERNAL_LIB_DIR)

    #User did not specify EXTERNAL_LIB_NAME
    if("${IMPORT_EXTERNAL_LIB_NAME}" STREQUAL "")
        message(SEND_ERROR "No EXTERNAL_LIB_NAME provided.")
        return()
    endif()

    #User does not say that EXTERNAL_LIB_NAME represents a full library name, 
    #so checks are made and library prefixes and suffixes may be added or warnings emitted
    if(NOT IMPORT_EXTERNAL_LIB_NAME_IS_FULL)
        set(IMPORT_DISABLE_WARNING_HINT_MESSAGE 
            "Set option EXTERNAL_LIB_NAME_IS_FULL if ${IMPORT_EXTERNAL_LIB_NAME} is full library name.")
        get_filename_component(IMPORT_EXTERNAL_LIB_NAME_EXT "${IMPORT_EXTERNAL_LIB_NAME}" EXT)
        #User did not provide a library name with file extension, but a library type, so we compute full name of library
        if("${IMPORT_EXTERNAL_LIB_NAME_EXT}" STREQUAL "" AND NOT "${IMPORT_LIBRARY_TYPE}" STREQUAL "UNKNOWN")
            set(PFX "${CMAKE_${IMPORT_LIBRARY_TYPE}_LIBRARY_PREFIX}")
            set(SFX "${CMAKE_${IMPORT_LIBRARY_TYPE}_LIBRARY_SUFFIX}")
            if(NOT IMPORT_NO_WARN AND NOT "${PFX}" STREQUAL "" AND "${IMPORT_EXTERNAL_LIB_NAME}" MATCHES "^${PFX}.*")
                message(AUTHOR_WARNING "Library name ${IMPORT_EXTERNAL_LIB_NAME} begins with ${PFX}."
                                       " Will assume library full name is ${PFX}${IMPORT_EXTERNAL_LIB_NAME}${SFX}."
                                       " ${IMPORT_DISABLE_WARNING_HINT_MESSAGE}")
            endif()
            set(IMPORT_EXTERNAL_LIB_NAME "${PFX}${IMPORT_EXTERNAL_LIB_NAME}${SFX}")
            message(STATUS "Name of external library set to ${IMPORT_EXTERNAL_LIB_NAME}")
        #User provided a library name with file extension and library type.
        #Emit warnings if inconsistent, but assume correctness.
        elseif(NOT "${IMPORT_EXTERNAL_LIB_NAME_EXT}" STREQUAL "" AND NOT "${IMPORT_LIBRARY_TYPE}" STREQUAL "UNKNOWN")
            if(NOT IMPORT_NO_WARN)
                macro(escape_special_regex_characters output input)
                    string(REPLACE "." "\\." ${output} "${input}")
                endmacro()
                escape_special_regex_characters(REGEX_SFX "${CMAKE_SHARED_LIBRARY_SUFFIX}")
                set(REGEX_SFX ".*${REGEX_SFX}(\\..*|$)")
                #Library suffix is inconsistent with shared and versioned shared library suffixes
                if("${IMPORT_LIBRARY_TYPE}" STREQUAL "SHARED" AND NOT "${IMPORT_EXTERNAL_LIB_NAME_EXT}" MATCHES "${REGEX_SFX}")
                    message(AUTHOR_WARNING "Given suffix: ${IMPORT_EXTERNAL_LIB_NAME_EXT} is inconsistent with ${IMPORT_LIBRARY_TYPE} suffix."
                                           " ${IMPORT_DISABLE_WARNING_HINT_MESSAGE}")
                endif()
                escape_special_regex_characters(REGEX_SFX "${CMAKE_STATIC_LIBRARY_SUFFIX}")
                set(REGEX_SFX ".*${REGEX_SFX}$")
                #Library suffix is inconsistent with static library suffixes
                if("${IMPORT_LIBRARY_TYPE}" STREQUAL "STATIC" AND NOT "${IMPORT_EXTERNAL_LIB_NAME_EXT}" MATCHES "${REGEX_SFX}")
                    message(AUTHOR_WARNING "Given suffix: ${IMPORT_EXTERNAL_LIB_NAME_EXT} is inconsistent with ${IMPORT_LIBRARY_TYPE} suffix."
                                           " ${IMPORT_DISABLE_WARNING_HINT_MESSAGE}")
                endif()
                #Check if library prefix is consistent
                set(PFX "${CMAKE_${IMPORT_LIBRARY_TYPE}_LIBRARY_PREFIX}")
                if(NOT "${PFX}" STREQUAL "" AND NOT "${IMPORT_EXTERNAL_LIB_NAME}" MATCHES "^${PFX}.*")
                message(AUTHOR_WARNING "Library name ${IMPORT_EXTERNAL_LIB_NAME} does not begin with ${PFX},"
                                       " which is inconsistent with ${IMPORT_LIBRARY_TYPE} prefix."
                                       " ${IMPORT_DISABLE_WARNING_HINT_MESSAGE}")
                endif()
            endif(NOT IMPORT_NO_WARN)
        #User provided no library type. We therefore assume that every library name is correct.
        elseif("${IMPORT_LIBRARY_TYPE}" STREQUAL "UNKNOWN")
            message(STATUS "Name of  external library is set to ${IMPORT_EXTERNAL_LIB_NAME}")
        endif()
    endif(NOT IMPORT_EXTERNAL_LIB_NAME_IS_FULL)

    #Set IMPORT_TARGET_GLOBAL according to option NO_GLOBAL.
    if(IMPORT_NO_GLOBAL)
       set(IMPORT_TARGET_GLOBAL )
    else()
        set(IMPORT_TARGET_GLOBAL GLOBAL)
    endif()

    #Add imported library target.
    add_library(${IMPORT_TARGET_NAME} ${IMPORT_LIBRARY_TYPE} IMPORTED ${IMPORT_TARGET_GLOBAL})
    #Set dependency to external target, if EXTERNAL_TARGET is provided.
    if(DEFINED IMPORT_EXTERNAL_TARGET)
        add_dependencies(${IMPORT_TARGET_NAME} ${IMPORT_EXTERNAL_TARGET})
    endif()
    target_include_directories(${IMPORT_TARGET_NAME} INTERFACE ${IMPORT_EXTERNAL_INCLUDES})
    set_target_properties(${IMPORT_TARGET_NAME} PROPERTIES 
                          IMPORTED_LOCATION "${IMPORT_EXTERNAL_LIB_DIR}/${IMPORT_EXTERNAL_LIB_NAME}")
endfunction(add_imported_library)

function(install_imported_library TARGETS LIBRARY_NAME)
    foreach(target ${TARGETS})
        if(NOT TARGET "${target}")
            message(SEND_ERROR "Input: ${target} is not a target.")
            return()
        endif()
    endforeach()
    include(InstallConfig)
    install_config(IGNORED "${LIBRARY_NAME}" "${TARGETS}")
    foreach(target ${TARGETS})
        get_target_property(INSTALL_INCLUDES ${target} INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(INSTALL_IMPORTED_LOCATION ${target} LOCATION)
        if(NOT INSTALL_INCLUDES)
            message(SEND_ERROR "Target: ${target} does not have property INTERFACE_INCLUDE_DIRECTORIES")
            return()
        endif()
        if(NOT INSTALL_IMPORTED_LOCATION)
            message(SEND_ERROR "Target: ${target} does not have an imported location.")
            return()
        endif()
        #Add a trailing slash behind every directory, to prevent structures like include/include etc.
        #Only add a trailing slash to directories not already ending with a slash
        list(TRANSFORM INSTALL_INCLUDES APPEND "/" REGEX ".*[^/]$")
        install(DIRECTORY ${INSTALL_INCLUDES} DESTINATION "${${PROJECT_NAME}_INSTALL_INCLUDE}")
        install(FILES "${INSTALL_IMPORTED_LOCATION}" DESTINATION "${${PROJECT_NAME}_INSTALL_LIB}")
    endforeach()
endfunction(install_imported_library)
