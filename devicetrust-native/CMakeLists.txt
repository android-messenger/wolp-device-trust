# Native RASP checks (S2 §7.1, §7.5). Built into the devicetrust AAR as libwolpdt.so.
cmake_minimum_required(VERSION 3.22.1)
project(wolpdt C)

add_library(wolpdt SHARED src/rasp.c src/sha256.c)
# only JNI_OnLoad is exported; the scan function is registered with RegisterNatives
target_compile_options(wolpdt PRIVATE -fvisibility=hidden -Wall -Wextra -Werror -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2)
target_link_options(wolpdt PRIVATE -Wl,--exclude-libs,ALL -Wl,-z,relro,-z,now)
target_link_libraries(wolpdt log)
