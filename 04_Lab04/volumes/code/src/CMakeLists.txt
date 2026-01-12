# SPDX-License-Identifier: Unlicense

set(NS_LIBS
    pcap
    util
    pcap_util
    print_arp
    print_ip
    print_icmp
)

macro(ns_add_lib library)
  if(${ARGC} GREATER 1)
    add_library(${library} ${ARGN})
    target_include_directories(${library}
      PUBLIC ${PROJECT_SOURCE_DIR}/include)
    target_compile_options(${library} PRIVATE -Wall -ggdb -Werror)
  else()
    message(FATAL_ERROR "macro ns_add_lib called incorrectly")
  endif()
endmacro(ns_add_lib)

macro(ns_add_exec exec)
  if(${ARGC} GREATER 1)
    add_executable(${exec} ${ARGN})
    target_link_libraries(${exec} PRIVATE ${NS_LIBS})
    target_include_directories(${exec}
     PRIVATE ${PROJECT_SOURCE_DIR}/include)
  else()
    message(FATAL_ERROR "macro ns_add_exec called incorrectly")
  endif()
endmacro(ns_add_exec)

# add the libraries
ns_add_lib(util util.c)
ns_add_lib(pcap_util pcap_util.c)
ns_add_lib(print_arp print_arp.c)
ns_add_lib(print_ip print_ip.c)
ns_add_lib(print_icmp print_icmp.c)

# add the main executable
ns_add_exec(sniff main.c)
