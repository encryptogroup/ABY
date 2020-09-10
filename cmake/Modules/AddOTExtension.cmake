cmake_minimum_required(VERSION 3.13)

if(NOT TARGET OTExtension::otextension)
    if(NOT OTExtension_LIBRARY_TYPE)
        set(OTExtension_LIBRARY_TYPE ${ABY_LIBRARY_TYPE})
    endif()
    file(GLOB OTExtension_FILE_LIST "${PROJECT_SOURCE_DIR}/extern/OTExtension/*")
    list(LENGTH OTExtension_FILE_LIST OTExtension_NUM_FILES)
    #if OTExtension directory is empty
    if(OTExtension_NUM_FILES EQUAL 0)
        message(STATUS "OTExtension was not found. Fetching OTExtension...")
        include(FetchOTExtension)
    else()
        message(STATUS "OTExtension was found in: ${PROJECT_SOURCE_DIR}/extern/OTExtension")
        set(OTExtension_SOURCE "${PROJECT_SOURCE_DIR}/extern/OTExtension"
            CACHE PATH 
            "Path to OTExtension source."
            FORCE
        )
        include(FetchOTExtension)
    endif()
endif()
