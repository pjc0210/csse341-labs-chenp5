# SPDX-License-Identifier: Unlicense

set(NS_LIBS
    pcap_util
    arp_util
    tcp_util
    # ip_util
    # icmp_util
    util
    pcap
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
if(BUILD_SOLUTIONS)
  # ns_add_lib(ip_util ip_util_solution.c)
  # ns_add_lib(icmp_util icmp_util_solution.c)
  ns_add_lib(tcp_util tcp_util_solution.c)
  ns_add_lib(arp_util arp_util_solution.c)
else(BUILD_SOLUTIONS)
  # ns_add_lib(ip_util ip_util.c)
  # ns_add_lib(icmp_util icmp_util.c)
  ns_add_lib(tcp_util tcp_util.c)
  ns_add_lib(arp_util arp_util.c)
endif(BUILD_SOLUTIONS)

# add the main executable
ns_add_exec(send_arp send_arp.c)
ns_add_exec(poison poison.c)
ns_add_exec(sniff sniff.c)
