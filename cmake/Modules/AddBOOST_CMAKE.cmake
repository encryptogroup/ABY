cmake_minimum_required(VERSION 3.13)

set(BOOST_INSTALL_INCLUDE "${${PROJECT_NAME}_INSTALL_INCLUDE}")
set(USE_ANDROID ANDROID)
file(GLOB BOOST_CMAKE_FILE_LIST "${PROJECT_SOURCE_DIR}/extern/boost-cmake/*")
list(LENGTH BOOST_CMAKE_FILE_LIST BOOST_CMAKE_NUM_FILES)
#if boost-cmake directory is empty
if(BOOST_CMAKE_NUM_FILES EQUAL 0)
    include(FetchBOOST_CMAKE)
else()
    set(BOOST_CMAKE_SOURCE "${PROJECT_SOURCE_DIR}/extern/BOOST_CMAKE" CACHE PATH "Path to boost-cmake source." FORCE)
    include(FetchBOOST_CMAKE)
endif()
