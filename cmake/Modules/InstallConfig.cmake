#install_config(<output variable> <name of dependency> <name of created targets>)
#Configures and installs a config file with the name ${DEPENDENCY_NAME}Config.cmake.in 
#located in ${PROJECT_SOURCE_DIR}/cmake, requiring knowledge about the targets created by the
#config file for correct configuration. 
#This function will set the variables #INSTALL_CONFIG_INCLUDE_PATHS to 
#${${PROJECT_NAME}_INSTALL_INCLUDE and INSTALL_CONFIG_LIB_PATHS to ${${PROJECT_NAME}_INSTALL_LIB}, 
#allowing the config files to be agnostic about the project name they are used in.
#Furthermore, install_config will generate an additional config file for android platforms,
#so that the correct library version is chosen and append additional code to the config file, 
#so that required shared libraries are automatically exported together with the executable
#when using Android Studio.
function(install_config RESULT DEPENDENCY_NAME DEPENDENCY_TARGETS)
    set(CONFIG_FILE_LOCATION "${PROJECT_SOURCE_DIR}/cmake/${DEPENDENCY_NAME}Config.cmake.in")
    if(NOT EXISTS "${CONFIG_FILE_LOCATION}")
        message(SEND_ERROR "The corresponding config file to dependency ${DEPENDENCY_NAME} "
                           "does not exist (absolute file name is assumed to be: "
                           "${PROJECT_SOURCE_DIR}/cmake/${DEPENDENCY_NAME}Config.cmake.in)")
    endif()
    set(CONFIG_FILE_COPY_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/${CONFIG_NAME}Config.cmake.in")
    if(NOT DEPENDENCY_TARGETS)
        message(SEND_ERROR "DEPENDENCY_TARGETS evaluates to false. At least one valid target name "
                           "must be exported by the config file")
    endif()
    if(ANDROID AND ANDROID_ARM_NEON)
        set(CONFIG_NAME "${DEPENDENCY_NAME}/${DEPENDENCY_NAME}-${ANDROID_PLATFORM}-${ANDROID_SYSROOT_ABI}-NEON")
        set(INSTALL_CONFIG_INCLUDE_PATHS "\${CMAKE_CURRENT_LIST_DIR}/../../${${PROJECT_NAME}_INSTALL_INCLUDE}")
        set(INSTALL_CONFIG_LIB_PATHS "\${CMAKE_CURRENT_LIST_DIR}/../../${${PROJECT_NAME}_INSTALL_LIB}")
    elseif(ANDROID AND NOT ANDROID_ARM_NEON)
        set(CONFIG_NAME "${DEPENDENCY_NAME}/${DEPENDENCY_NAME}-${ANDROID_PLATFORM}-${ANDROID_SYSROOT_ABI}")
        set(INSTALL_CONFIG_INCLUDE_PATHS "\${CMAKE_CURRENT_LIST_DIR}/../../${${PROJECT_NAME}_INSTALL_INCLUDE}")
        set(INSTALL_CONFIG_LIB_PATHS "\${CMAKE_CURRENT_LIST_DIR}/../../${${PROJECT_NAME}_INSTALL_LIB}")
    else()
        set(CONFIG_NAME "${DEPENDENCY_NAME}")
        set(INSTALL_CONFIG_INCLUDE_PATHS "\${CMAKE_CURRENT_LIST_DIR}/../${${PROJECT_NAME}_INSTALL_INCLUDE}")
        set(INSTALL_CONFIG_LIB_PATHS "\${CMAKE_CURRENT_LIST_DIR}/../${${PROJECT_NAME}_INSTALL_LIB}")
    endif()
    configure_file("${CONFIG_FILE_LOCATION}" "${CONFIG_FILE_COPY_LOCATION}" COPYONLY)
    if(ANDROID)
        file(READ "${PROJECT_SOURCE_DIR}/cmake/ImportIntoAndroidStudio.cmake.in" IMPORT_INTO_ANDROID_STUDIO)
        file(APPEND "${CONFIG_FILE_COPY_LOCATION}" "${IMPORT_INTO_ANDROID_STUDIO}")
    endif()
    configure_file("${CONFIG_FILE_COPY_LOCATION}"
                   "${CMAKE_CURRENT_BINARY_DIR}/${CONFIG_NAME}Config.cmake"
                   @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${CONFIG_NAME}Config.cmake" DESTINATION "${CONFIG_NAME}")
    #We didn't give our config file the expected install name, so we give ForwardConfig.cmake.in that one
    #ForwardConfig will then be configured to forward the find_package call to the appropriate config file
    if(NOT "${CONFIG_NAME}" STREQUAL "${DEPENDENCY_NAME}")
        configure_file("${PROJECT_SOURCE_DIR}/cmake/ForwardConfig.cmake.in"
                       "${CMAKE_CURRENT_BINARY_DIR}/${DEPENDENCY_NAME}Config.cmake"
                       @ONLY)
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${DEPENDENCY_NAME}Config.cmake" DESTINATION "${DEPENDENCY_NAME}")
     endif()
     #Return relative install location of the "true" config file, i.e. the one that is not ForwardConfig
     set(${RESULT} "${CONFIG_NAME}" PARENT_SCOPE)
endfunction(install_config)
