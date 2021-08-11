cmake_minimum_required(VERSION 3.11)
project(Ryu VERSION 0.0.0 LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
#set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -ggdb -O0 -Wno-unused-parameter")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic")


## CPR flags
set(CPR_FORCE_USE_SYSTEM_CURL YES)
set(CPR_USE_SYSTEM_GTEST YES)
set(CPR_BUILD_TESTS NO)

## Link ABSL statically
set(BUILD_SHARED_LIBS FALSE)

##
## Third party libraries
##
include(FetchContent)
FetchContent_Declare(cpr
    GIT_REPOSITORY https://github.com/whoshuu/cpr.git
    GIT_TAG        1.6.2
)
FetchContent_Declare(result
    GIT_REPOSITORY https://github.com/RecursiveG/result.git
    GIT_TAG        8e8680449cc2764c1f6bb1696c348c54c3ef9441
)
FetchContent_Declare(abseil-cpp
    GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
    GIT_TAG        20210324.2
)
FetchContent_Declare(backward-cpp
    GIT_REPOSITORY https://github.com/bombela/backward-cpp.git
    GIT_TAG        v1.5
)
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/ArthurSonzogni/nlohmann_json_cmake_fetchcontent
    GIT_TAG v3.9.1
)
FetchContent_Declare(stduuid
    GIT_REPOSITORY https://github.com/mariusbancila/stduuid.git
    GIT_TAG        v1.0
)
# FetchContent_Declare(hash-library
#     GIT_REPOSITORY https://github.com/stbrumme/hash-library.git
#     GIT_TAG        hash_library_v8
# )
FetchContent_MakeAvailable(cpr)
FetchContent_MakeAvailable(result)
FetchContent_MakeAvailable(abseil-cpp)
FetchContent_MakeAvailable(backward-cpp)
FetchContent_MakeAvailable(json)
#FetchContent_MakeAvailable(hash-library)

FetchContent_Populate(stduuid)
add_library(stduuid INTERFACE)
target_include_directories(stduuid INTERFACE ${stduuid_SOURCE_DIR}/include)
target_link_libraries(stduuid INTERFACE -luuid)

find_package(PkgConfig REQUIRED)
pkg_check_modules(gpgme REQUIRED IMPORTED_TARGET gpgme)

add_executable(openmprdb-cli
    ${CMAKE_CURRENT_SOURCE_DIR}/src/openmprdb-cli.cpp
    ${BACKWARD_ENABLE}
)
target_include_directories(openmprdb-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(openmprdb-cli PRIVATE
    -ldw absl::flags absl::flags_parse absl::str_format
    cpr::cpr PkgConfig::gpgme result nlohmann_json::nlohmann_json
    stduuid
)
