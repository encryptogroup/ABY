add_library(aby
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
add_library(ABY::aby ALIAS aby)

target_compile_features(aby PUBLIC cxx_std_17)
#target_compile_options(aby PRIVATE "-Wall" "-Wextra" "-Weffc++")
target_compile_options(aby PRIVATE "-Wall" "-Wextra")

target_include_directories(aby
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
)

# This assumes that libstdc++ is used and should not be required for e.g.
# libc++.  Linking to libstdc++fs is currently required when using the
# std::filesystem library.
# cf. https://gitlab.kitware.com/cmake/cmake/issues/17834
target_link_libraries(aby
	PRIVATE stdc++fs
)

target_link_libraries(aby
    PUBLIC OTExtension::otextension
    PUBLIC ENCRYPTO_utils::encrypto_utils
    PUBLIC GMP::GMP
    PUBLIC Threads::Threads
)


install(TARGETS aby
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        INCLUDES DESTINATION lib
)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
)

export(TARGETS aby NAMESPACE "${PROJECT_NAME}::" FILE "${PROJECT_NAME}Targets.cmake")
install(EXPORT "${PROJECT_NAME}Targets"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "lib/cmake/${PROJECT_NAME}"
)

include(CMakePackageConfigHelpers)

configure_package_config_file("${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    DESTINATION "lib/cmake/${PROJECT_NAME}"
)
