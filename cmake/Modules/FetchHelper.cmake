cmake_minimum_required(VERSION 3.13)
macro(fetch_helper content_name)
    string(TOLOWER "${content_name}" LOWER_CASE_${content_name})
    if(NOT "${DEPENDENCY_DIR}" STREQUAL "")
        set(${content_name}_DOWNLOAD_DIR_COMMAND DOWNLOAD_DIR ${DEPENDENCY_DIR})
    else()
        set(${content_name}_DOWNLOAD_DIR_COMMAND "")
    endif()
    if(NOT "${${content_name}_SOURCE}" STREQUAL "")
        set(${content_name}_DOWNLOAD_COMMAND1 URL ${${content_name}_SOURCE})
        set(${content_name}_DOWNLOAD_COMMAND2 "")
    else()
        set(${content_name}_DOWNLOAD_COMMAND1 GIT_REPOSITORY ${${content_name}_REPOSITORY})
        set(${content_name}_DOWNLOAD_COMMAND2 GIT_TAG ${${content_name}_TAG})
    endif()
    include(FetchContent)
    FetchContent_Declare(${content_name}
        ${${content_name}_DOWNLOAD_COMMAND1}
        ${${content_name}_DOWNLOAD_COMMAND2}
        ${${content_name}_DOWNLOAD_DIR_COMMAND}
    )
    FetchContent_GetProperties(${content_name})
    if(NOT ${LOWER_CASE_${content_name}}_POPULATED)
        FetchContent_Populate(${content_name})
        if(NOT "${ARGV1}" STREQUAL "")
            message(STATUS "Applying patches to ${content_name}...")
            include("Patch${content_name}")
        endif()
        if(NOT "${ARGV2}" STREQUAL "")
            add_subdirectory(
                ${${LOWER_CASE_${content_name}}_SOURCE_DIR} 
                ${${LOWER_CASE_${content_name}}_BINARY_DIR}
                EXCLUDE_FROM_ALL
            )
        else()
            add_subdirectory(
                ${${LOWER_CASE_${content_name}}_SOURCE_DIR} 
                ${${LOWER_CASE_${content_name}}_BINARY_DIR}
            )
        endif()
    endif()
endmacro()
