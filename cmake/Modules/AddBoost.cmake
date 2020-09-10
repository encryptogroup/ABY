cmake_minimum_required(VERSION 3.13)

#Check if all required boost targets already exist.
set(ALL_REQUIRED_BOOST_TARGETS_EXIST TRUE)
set(BOOST_REQUIRED_COMPONENTS)
foreach(boost_target ${BOOST_TARGETS_REQUIRED})
    if(NOT boost_target MATCHES "^Boost::.*")
        message(AUTHOR_WARNING "Given required target: ${boost_target} does not begin with Boost:: and will thus be ignored.")
        break()
    endif()
    string(REGEX REPLACE "^Boost::(.*)" "\\1" COMPONENT_NAME ${boost_target})
    #Do not add boost as a required component
    if(NOT COMPONENT_NAME STREQUAL "boost")
        list(APPEND BOOST_REQUIRED_COMPONENTS ${COMPONENT_NAME})
    endif()
    if(NOT TARGET ${boost_target})
        set(ALL_REQUIRED_BOOST_TARGETS_EXIST FALSE)
    endif()
endforeach()

if(NOT TARGET Boost::boost)
    set(EXPORTED_BOOST_boost FALSE CACHE INTERNAL "Check if target Boost::boost is already in export set.")
endif()

if(NOT ALL_REQUIRED_BOOST_TARGETS_EXIST)
    if(DOWNLOAD_BOOST)
        message(STATUS "Fetching Boost sources. This might take several minutes. "
                       "No progress is shown, please wait...")
    endif()
    if(DOWNLOAD_BOOST OR EXISTS "${BOOST_SOURCE}")
        include(AddBOOST_CMAKE)
        #Since we import from boost-cmake, we need to export the boost libraries with our project.
        set(EXPORT_BOOST_TARGETS TRUE CACHE INTERNAL "Variable to decide whether we export boost dependencies along with project.")
    elseif(ANDROID)
        message(SEND_ERROR "Please provide a valid directory for BOOST_SOURCE (recommended) or automatically download boost libraries by setting DOWNLOAD_BOOST.")
        return()
    else()
        find_package(Boost 1.67 REQUIRED COMPONENTS ${BOOST_REQUIRED_COMPONENTS})
        #We found our libraries through find_package, so we don't export boost alongside our project.
        set(EXPORT_BOOST_TARGETS FALSE CACHE INTERNAL "Variable to decide whether we export boost dependencies along with project.")
    endif()
endif()

#Export boost targets, if option is set to export them.
if(EXPORT_BOOST_TARGETS)
    include(GetDependencies)
    set(BOOST_DEPENDENCIES_TO_EXPORT)
    get_dependencies(BOOST_DEPENDENCIES_TO_EXPORT ${BOOST_TARGETS_REQUIRED})
    #Only export dependencies that start with Boost.
    list(FILTER BOOST_DEPENDENCIES_TO_EXPORT INCLUDE REGEX "^[bB]oost.*")
    #Do not include Boost::boost dependency. It is exported seperately from project
    list(REMOVE_ITEM BOOST_DEPENDENCIES_TO_EXPORT Boost::boost)
    #Allow boost dependencies to be automatically installed when installing all.
    foreach(dependency ${BOOST_DEPENDENCIES_TO_EXPORT})
        #check if target is not interface library, to prevent error.
        get_target_property(target_type ${dependency} TYPE)
        if(target_type AND NOT "${target_type}" STREQUAL "INTERFACE_LIBRARY")
            set_target_properties(${dependency} PROPERTIES EXCLUDE_FROM_ALL 0)
        endif()
    endforeach()
    #Tell current project that these dependencies need to be exported 
    set(${PROJECT_NAME}_DEPENDENCIES_TO_EXPORT ${BOOST_DEPENDENCIES_TO_EXPORT})
    get_target_property(BOOST_INCLUDE_DIRS Boost::boost INTERFACE_INCLUDE_DIRECTORIES)
    #Add a trailing slash behind every directory, to prevent structures like include/include etc.
    #Only add a trailing slash to directories not already ending with a slash
    list(TRANSFORM BOOST_INCLUDE_DIRS APPEND "/boost/" REGEX ".*[^/]$")
    if(NOT EXPORTED_BOOST_boost)
        include(InstallConfig)
        install_config(Boost_INSTALL_LOCATION "Boost" Boost::boost)
        #Install boost headers 
        install(DIRECTORY "${BOOST_INCLUDE_DIRS}"
                DESTINATION "${${PROJECT_NAME}_INSTALL_INCLUDE}/boost/"
                FILES_MATCHING REGEX ".*\\.h(pp|h)?$")
        install(TARGETS Boost::boost
                EXPORT "BoostTargets"
                ARCHIVE DESTINATION "${${PROJECT_NAME}_INSTALL_ARCHIVE}"
                LIBRARY DESTINATION "${${PROJECT_NAME}_INSTALL_LIB}"
                INCLUDES DESTINATION "${${PROJECT_NAME}_INSTALL_INCLUDE}")
        export(TARGETS Boost::boost
               FILE "BoostTargets.cmake")
        install(EXPORT "BoostTargets"
                DESTINATION "${Boost_INSTALL_LOCATION}")
        set(EXPORTED_BOOST_boost TRUE CACHE INTERNAL "Check if target Boost::boost is already in export set.")
    endif()
endif()
