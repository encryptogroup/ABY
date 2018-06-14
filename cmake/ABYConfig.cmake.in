get_filename_component(ABY_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

list(APPEND CMAKE_MODULE_PATH "${ABY_CMAKE_DIR}")

include(CMakeFindDependencyMacro)

find_dependency(OTExtension)
find_dependency(ENCRYPTO_utils)
find_dependency(MIRACL)
find_dependency(GMP)
find_dependency(Threads)

if(NOT TARGET ABY::aby)
    include("${ABY_CMAKE_DIR}/ABYTargets.cmake")
endif()
