cmake_minimum_required(VERSION 3.13)

if(NOT TARGET ENCRYPTO_utils::encrypto_utils)
    if(NOT ENCRYPTO_utils_LIBRARY_TYPE)
        set(ENCRYPTO_utils_LIBRARY_TYPE ${ABY_LIBRARY_TYPE})
    endif()
    file(GLOB ENCRYPTO_utils_FILE_LIST "${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils/*")
    list(LENGTH ENCRYPTO_utils_FILE_LIST ENCRYPTO_utils_NUM_FILES)
    #if ENCRYPTO_utils directory is empty
    if(ENCRYPTO_utils_NUM_FILES EQUAL 0)
        message(STATUS "ENCRYPTO_utils was not found. Fetching ENCRYPTO_utils...")
        include(FetchENCRYPTO_utils)
    else()
        message(STATUS "ENCRYPTO_utils was found in: ${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils")
        set(ENCRYPTO_utils_SOURCE "${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils"
            CACHE PATH 
            "Path to ENCRYPTO_utils source."
            FORCE
        )
        include(FetchENCRYPTO_utils)
    endif()
endif()
