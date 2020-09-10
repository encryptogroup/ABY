cmake_minimum_required(VERSION 3.13)
include(FetchContent)

if(NOT "${BOOST_SOURCE}" STREQUAL "")
    set(FETCHCONTENT_SOURCE_DIR_BOOST "${BOOST_SOURCE}")
elseif(NOT "${DEPENDENCY_DIR}" STREQUAL "")
    include(FetchContent)
    FetchContent_Declare(Boost
        URL ${BOOST_URL}
        URL_HASH ${BOOST_URL_HASH}
        DOWNLOAD_DIR ${DEPENDENCY_DIR}
    )
else()
    include(FetchContent)
    FetchContent_Declare(Boost
        URL ${BOOST_URL}
        URL_HASH ${BOOST_URL_HASH}
    )
endif()

include(FetchHelper)
fetch_helper(BOOST_CMAKE true)
