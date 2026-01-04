# SPDX-License-Identifier: Unlicense
add_library(util util.c)
add_library(pcap_util pcap_util.c)
add_library(print_arp print_arp.c)

# set up the include directories correctly
target_include_directories(util
  PRIVATE ${PROJECT_SOURCE_DIR}/include
  PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(pcap_util
   PRIVATE ${PROJECT_SOURCE_DIR}/include
   PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(print_arp
   PRIVATE ${PROJECT_SOURCE_DIR}/include
   PUBLIC ${PROJECT_SOURCE_DIR}/src)

target_compile_options(util PRIVATE -Wall -ggdb -Werror)
target_compile_options(pcap_util PRIVATE -Wall -ggdb -Werror)
target_compile_options(print_arp PRIVATE -Wall -ggdb -Werror)

# add the main executable
add_executable(sniff main.c)
target_link_libraries(sniff util pcap_util print_arp pcap)
target_include_directories(sniff
   PRIVATE ${PROJECT_SOURCE_DIR}/include)
