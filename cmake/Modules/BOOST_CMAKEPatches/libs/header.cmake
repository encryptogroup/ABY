# Define the header-only Boost target
add_library(Boost::boost INTERFACE IMPORTED GLOBAL)
target_include_directories(Boost::boost SYSTEM INTERFACE 
    $<BUILD_INTERFACE:${BOOST_SOURCE}>  
    $<INSTALL_INTERFACE:${BOOST_INSTALL_INCLUDE}>
)

# Disable autolink
target_compile_definitions(Boost::boost INTERFACE BOOST_ALL_NO_LIB=1)
