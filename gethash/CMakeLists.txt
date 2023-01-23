cmake_minimum_required(VERSION 3.15)

# set the project name
project(gethash)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# set paths
set(PATH_INCLUDE ${PROJECT_SOURCE_DIR}/include)
set(PATH_SRC ${PROJECT_SOURCE_DIR}/src)
set(PATH_LIB ${PROJECT_SOURCE_DIR}/lib)


# add headers dir
include_directories(${PATH_INCLUDE})
include_directories(${PROJECT_SOURCE_DIR}/external/openssl/include)

# main to exe
add_executable(gethash ${PROJECT_SOURCE_DIR}/main.cpp)

# Dodanie projektu biblioteki OpenSSL jako zależnego projektu
include(ExternalProject)
ExternalProject_Add(openssl_project
    SOURCE_DIR ${PROJECT_SOURCE_DIR}/external/openssl
    CONFIGURE_COMMAND perl ${PROJECT_SOURCE_DIR}/external/openssl/Configure
    BUILD_COMMAND make
    INSTALL_COMMAND ""
)

# Dodanie zależności między projektem a biblioteką
add_dependencies(gethash openssl_project)

# Pobranie ścieżki do pliku biblioteki
ExternalProject_Get_property(openssl_project binary_dir)

include_directories(${binary_dir}/include/)

# Dołączenie biblioteki do projektu
target_link_libraries(gethash ${binary_dir}/libssl.a ${binary_dir}/libcrypto.a)

# add libraries
#target_link_libraries(gethash ${PATH_LIB}/openssl/libcrypto.a)

install(TARGETS gethash
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}
)