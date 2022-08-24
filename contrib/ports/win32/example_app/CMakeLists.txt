include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib/"
    "${LWIP_DIR}/contrib/ports/win32/include"
    "${LWIP_DIR}/contrib/examples/example_app"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/win32/Filelists.cmake)

add_library(lwipcap ${LWIP_DIR}/contrib/examples/example_app/test.c default_netif.c)
target_include_directories(lwipcap PRIVATE ${LWIP_INCLUDE_DIRS})
target_compile_options(lwipcap PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcap PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(lwipcap ${LWIP_SANITIZER_LIBS} lwipallapps lwipcontribexamples lwipcontribapps lwipcontribaddons lwipcontribportwindows lwipcore lwipmbedtls)

#add_executable(makefsdata ${lwipmakefsdata_SRCS})
#target_compile_options(makefsdata PRIVATE ${LWIP_COMPILER_FLAGS})
#target_include_directories(makefsdata PRIVATE ${LWIP_INCLUDE_DIRS})
#target_link_libraries(makefsdata ${LWIP_SANITIZER_LIBS} lwipcore lwipcontribportwindows)
