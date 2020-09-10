set(ANDROID_NDK CACHE PATH "Path to Android NDK.")
set(ANDROID_NATIVE_API_LEVEL CACHE STRING "Android API level to compile for. Acceptable values are: [0-9]+ or android-[0-9]+")
set(ANDROID_PLATFORM CACHE STRING "Alternative way to set Android API level. Acceptable values are: latest or android-[0-9]+")
set(ANDROID_TOOLCHAIN_FILE CACHE PATH "Android toolchain file.")
set(ANDROID_ABI CACHE STRING "Target CPU of android device, like e.g. \"armeabi-v7a\".")
set_property(CACHE ANDROID_ABI PROPERTY STRINGS
    "armeabi-v7a" 
    "armeabi-v7a with NEON"
    "arm64-v8a"
    "x86"
    "x86_64"
)

#Check if user wants to build for Android
if(NOT "${CMAKE_ANDROID_NDK}" STREQUAL "")
    set(ANDROID_NDK "${CMAKE_ANDROID_NDK}")
endif()
if(NOT "${ANDROID_NDK}" STREQUAL "")
    set(ANDROID ON)
elseif(NOT "${ANDROID_TOOLCHAIN_FILE}" STREQUAL "" AND EXISTS "${ANDROID_TOOLCHAIN_FILE}")
    set(ANDROID ON)
elseif(NOT "${CMAKE_TOOLCHAIN_FILE}" STREQUAL "" AND EXISTS "${CMAKE_TOOLCHAIN_FILE}")
    set(ANDROID ON)
endif()

#Set CMAKE_TOOLCHAIN_FILE and CMAKE_INSTALL_PREFIX for Android builds
if(ANDROID)
    #CMAKE_TOOLCHAIN_FILE was not set, but ANDROID_TOOLCHAIN_FILE was set
    if("${CMAKE_TOOLCHAIN_FILE}" STREQUAL "" AND NOT "${ANDROID_TOOLCHAIN_FILE}" STREQUAL "")
        set(CMAKE_TOOLCHAIN_FILE "${ANDROID_TOOLCHAIN_FILE}")
    #Neither toolchain file was set, use toolchain in NDK
    elseif("${CMAKE_TOOLCHAIN_FILE}" STREQUAL "" AND "${ANDROID_TOOLCHAIN_FILE}" STREQUAL "")
        set(CMAKE_TOOLCHAIN_FILE "${ANDROID_NDK}/build/cmake/android.toolchain.cmake")
        set(ANDROID_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}")
    else()
        set(ANDROID_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}")
    endif()
    if(NOT EXISTS "${CMAKE_TOOLCHAIN_FILE}")
        message(FATAL_ERROR 
            "Could not find file: ${CMAKE_TOOLCHAIN_FILE}. Your NDK might be outdated."
        )
    endif()
endif(ANDROID)
