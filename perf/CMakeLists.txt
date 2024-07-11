#
# set up build:
#	cmake -S . -B ./build
#
# build tools using cmake:
#	cmake --build ./build
#

cmake_minimum_required(VERSION 3.10)
project(perf-tools)

add_library(perf perflib/perfhelper.c perflib/perfsslhelper.c perflib/threads.c perflib/time.c perflib/getopt.c)

include_directories(PUBLIC $ENV{TARGET_OSSL_INCLUDE_PATH} . )

find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT})

add_executable(evp_fetch evp_fetch.c)
target_include_directories(evp_fetch PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(evp_fetch PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(evp_fetch PUBLIC perf crypto)

add_executable(randbytes randbytes.c)
target_include_directories(randbytes PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(randbytes PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(randbytes PUBLIC perf crypto)

add_executable(handshake handshake.c)
target_include_directories(handshake PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(handshake PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(handshake PUBLIC perf crypto ssl)

add_executable(sslnew sslnew.c)
target_include_directories(sslnew PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(sslnew PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(sslnew PUBLIC perf crypto ssl)

add_executable(newrawkey newrawkey.c)
target_include_directories(newrawkey PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(newrawkey PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(newrawkey PUBLIC perf crypto)

add_executable(rsasign rsasign.c)
target_include_directories(rsasign PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(rsasign PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(rsasign PUBLIC perf crypto)

add_executable(x509storeissuer x509storeissuer.c)
target_include_directories(x509storeissuer PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(x509storeissuer PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(x509storeissuer PUBLIC perf crypto)

add_executable(providerdoall providerdoall.c)
target_include_directories(providerdoall PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(providerdoall PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(providerdoall PUBLIC perf crypto)

add_executable(rwlocks rwlocks.c)
target_include_directories(rwlocks PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(rwlocks PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(rwlocks PUBLIC perf crypto)

add_executable(pkeyread pkeyread.c)
target_include_directories(pkeyread PUBLIC "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_directories(pkeyread PUBLIC $ENV{TARGET_OSSL_LIBRARY_PATH})
target_link_libraries(pkeyread PUBLIC perf crypto)
