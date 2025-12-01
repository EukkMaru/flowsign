# SnortSharp Flow Analysis Integration
# Parallel processing engine for CICFlowMeter-compatible flow feature extraction

set(SNORTSHARP_SOURCES
    snort3_snortsharp_bridge.cpp
    parallel_snort_integration.cpp
    snortsharp_integration.cpp
    flow_analyzer.cpp
    flow_rules.cpp
    event_system.cpp
)

set(SNORTSHARP_HEADERS
    snort3_snortsharp_bridge.hpp
    parallel_snort_integration.hpp
    snortsharp_integration.hpp
    flow_analyzer.hpp
    flow_rules.hpp
    event_system.hpp
)

# find libuv for event system
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBUV libuv)
endif()

# create object library for snortsharp
add_library(snortsharp OBJECT
    ${SNORTSHARP_SOURCES}
    ${SNORTSHARP_HEADERS}
)

# set c++17 standard
set_target_properties(snortsharp PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# include directories
target_include_directories(snortsharp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}
    ${PROJECT_BINARY_DIR}/src
    ${PROJECT_BINARY_DIR}/src/framework
)

# link with libuv if available
if(LIBUV_FOUND)
    target_include_directories(snortsharp PRIVATE ${LIBUV_INCLUDE_DIRS})
    target_compile_definitions(snortsharp PRIVATE HAVE_LIBUV)
endif()

# thread support
find_package(Threads REQUIRED)

# ensure api_options.h is generated before compiling snortsharp
add_dependencies(snortsharp api_options)

# export snortsharp object for main snort executable
set(SNORTSHARP_OBJECTS $<TARGET_OBJECTS:snortsharp> PARENT_SCOPE)
