#get_dependencies(<out-var> targets...)
#
#Returns a list of all dependencies of targets... including alias-stripped targets...
#The returned list of dependencies contains no duplicates and dependencies are guaranteed 
#to not be alias targets.
#Arguments that are not valid targets, will be ignored and won't appear in the returned list.
function(get_dependencies RESULT)
    if(${ARGC} EQUAL 1)
        return()
    endif()

    #TARGET is not an alias target after invoking this function
    function(strip_alias TARGET)
        set(target ${${TARGET}})
        get_target_property(alias ${target} ALIASED_TARGET)
        if(NOT alias)
            set(${TARGET} ${target} PARENT_SCOPE)
        else()
            strip_alias(alias)
            set(${TARGET} ${alias} PARENT_SCOPE)
        endif()
    endfunction()

    #Put all alis-stripped targets in DEPENDENCY_LIST
    #DEPENDENCY_LIST will only contain targets 
    set(DEPENDENCY_LIST)
    foreach(target ${ARGN})
        if(TARGET ${target})
            strip_alias(target)
            list(APPEND DEPENDENCY_LIST ${target})
        endif()
    endforeach()

    #Put all dependencies of the targets in DEPENDENCY_LIST
    #in DEPENDENCY_DEPENDENCY_LIST. DEPENDENCY_DEPENDENCY_LIST
    #may contain elements that are not a target 
    set(DEPENDENCY_DEPENDENCY_LIST)
    foreach(target ${DEPENDENCY_LIST})
        get_target_property(dependencies ${target} INTERFACE_LINK_LIBRARIES)
        if(dependencies)
            list(APPEND DEPENDENCY_DEPENDENCY_LIST ${dependencies})
        endif()
    endforeach()

    #We remove all duplicates before recursing.
    list(REMOVE_DUPLICATES DEPENDENCY_DEPENDENCY_LIST)

    #Now we get all dependencies of the dependencies of our targets
    get_dependencies(DEPENDENCY_DEPENDENCY_LIST ${DEPENDENCY_DEPENDENCY_LIST})
    list(APPEND DEPENDENCY_LIST ${DEPENDENCY_DEPENDENCY_LIST})
    #We need to remove all duplicates again, to ensure we fulfill the guarantee to not 
    #return duplicates. Without it we would return duplicates, if two input targets had
    #the same dependency. 
    list(REMOVE_DUPLICATES DEPENDENCY_LIST)
    #return
    set(${RESULT} ${DEPENDENCY_LIST} PARENT_SCOPE)
endfunction()
