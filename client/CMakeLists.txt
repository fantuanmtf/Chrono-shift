cmake_minimum_required(VERSION 3.20)
project(chrono-client LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================
# C++23 标准 (需要 GCC 13+ / Clang 16+ / MSVC 2022 17.6+)
# ============================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译器版本提示
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13)
    message(FATAL_ERROR "C++23 requires GCC 13+, Now: ${CMAKE_CXX_COMPILER_VERSION}")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16)
    message(FATAL_ERROR "C++23 requires Clang 16+, Now: ${CMAKE_CXX_COMPILER_VERSION}")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 1936)
    message(FATAL_ERROR "C++23 requires MSVC 2022 17.6+ (_MSC_VER >= 1936), Now: ${CMAKE_CXX_COMPILER_VERSION}")
endif()

# 查找 Rust 编译出的静态库
set(RUST_SECURITY_LIB "${CMAKE_CURRENT_SOURCE_DIR}/security/target/release/libchrono_client_security.a")

# ============================================================
# OpenSSL 检测 (HTTPS 支持需要)
# ============================================================
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL Found: ${OpenSSL_VERSION}")
    add_compile_definitions(HTTPS_SUPPORT=1)
else()
    message(WARNING "Unable to find OpenSSL library — HTTPS Support will be disabled")
    message(WARNING "  Please install OpenSSL library:")
    message(WARNING "    - MSYS2: pacman -S mingw-w64-x86_64-openssl")
    message(WARNING "    - vcpkg: vcpkg install openssl")
    message(WARNING "    - Debian Family: sudo apt install libssl-dev")
    message(WARNING "    - Or set the CMAKE_PREFIX_PATH to OpenSSL installation path")
    add_compile_definitions(HTTPS_SUPPORT=0)
endif()

# ============================================================
# 源文件
# ============================================================

# === C++ 源文件 (CLI 架构) ===
# 注意: src/app/*.cpp (GUI) 和 devtools/core/*.cpp (DevToolsEngine + HTTP/IPC)
# 已移除，CLI 模式不需要这些 GUI 集成组件
file(GLOB_RECURSE CLIENT_CPP_SOURCES
    src/util/*.cpp
    src/network/*.cpp
    src/storage/*.cpp
    src/security/*.cpp
    src/ai/*.cpp
    src/plugin/*.cpp
    src/i2p/*.cpp
    src/tor/*.cpp
    src/glue/*.cpp
    src/social/*.cpp
)

# === CLI 工具 C++ 源文件 (C++23 迁移) ===
# 只包含核心 C++ 文件，命令实现在 .c 文件中 (中文无损坏)
file(GLOB CLI_CPP_SOURCES
    devtools/cli/main.cpp
    devtools/cli/net_http.cpp
)

# === CLI 命令初始化 + 新功能 (C++ 文件) ===
list(APPEND CLI_CPP_SOURCES
    devtools/cli/commands/init_commands.cpp
    devtools/cli/commands/cmd_i2p.cpp
    devtools/cli/commands/cmd_tor.cpp
    devtools/cli/commands/cmd_bridge.cpp
    devtools/cli/commands/cmd_social.cpp
)

# === C 源文件 (旧架构，过渡期保留) ===
file(GLOB CLIENT_C_SOURCES
    src/*.c
    src/network/*.c
    devtools/cli/commands/*.c
)

# === 最终源文件列表 ===
set(CLIENT_SOURCES
    ${CLIENT_CPP_SOURCES}
    ${CLI_CPP_SOURCES}
    ${CLIENT_C_SOURCES}
)

add_executable(chrono-client ${CLIENT_SOURCES})

target_include_directories(chrono-client PRIVATE
    include                          # C 头文件 (含 tls_client.h 等)
    src                              # C++ 头文件 (同目录)
    devtools/core                    # DevToolsEngine/HttpApi/IpcHandler 头文件
    devtools/cli                     # devtools_cli.h/devtools_cli.hpp 共享头文件
    devtools/cli/commands            # cmd_*.hpp 命令头文件
)

# C++23 特性检测: std::print / std::println / std::expected / std::flat_map
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
    #include <print>
    int main() { std::println(\"C++23 test\"); return 0; }
" HAS_CPP23_PRINT)
if(NOT HAS_CPP23_PRINT)
    message(WARNING "Compiler doesn't support \"std::println\" — Rollback to \"printf\"")
    add_compile_definitions(NO_CPP23_PRINT=1)
endif()

# 注意: WebView2 和 GUI 组件 (src/app/, devtools/core/) 已移除

if(EXISTS ${RUST_SECURITY_LIB})
    target_compile_definitions(chrono-client PRIVATE RUST_FEATURE_ENABLED)
    target_link_libraries(chrono-client PRIVATE ${RUST_SECURITY_LIB})
endif()

# 平台特定的库链接
if(WIN32)
    target_link_libraries(chrono-client PRIVATE
        ws2_32
        user32
        gdi32
        shell32
        ole32
        uuid
        winhttp
        ntdll
        bcrypt
        userenv
    )
else()
    # Linux/Unix 库
    target_link_libraries(chrono-client PRIVATE
        pthread
        dl
        rt
    )
    # 可选: 添加其他Unix系统库
    if(APPLE)
        target_link_libraries(chrono-client PRIVATE
            "-framework CoreFoundation"
            "-framework Security"
        )
    endif()
endif()

# ASM 混淆函数
if(WIN32)
    set(ASM_OBJ_FILE "${CMAKE_CURRENT_SOURCE_DIR}/security/asm/obfuscate.obj")
else()
    set(ASM_OBJ_FILE "${CMAKE_CURRENT_SOURCE_DIR}/security/asm/obfuscate.o")
endif()

if(EXISTS "${ASM_OBJ_FILE}")
    target_link_libraries(chrono-client PRIVATE "${ASM_OBJ_FILE}")
endif()

# HTTPS 支持 — 需要 OpenSSL
if(OpenSSL_FOUND)
    target_link_libraries(chrono-client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

# CLI 控制台子系统 (纯命令行，无 GUI 窗口)
if(WIN32)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set_target_properties(chrono-client PROPERTIES
            LINK_FLAGS "-Wl,--subsystem,console"
        )
    else()
        set_target_properties(chrono-client PROPERTIES
            LINK_FLAGS "/SUBSYSTEM:CONSOLE"
        )
    endif()
endif()

# ============================================================
# 独立工具: stress-test (压力测试) — TODO: 需要添加 tls_client.c 和终端运行时支持
# ============================================================
# if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/stress_test.cpp")
#     add_executable(stress-test
#         tools/stress_test.cpp
#     )
#     target_include_directories(stress-test PRIVATE
#         include
#         src
#     )
#     target_link_libraries(stress-test PRIVATE
#         ws2_32
#     )
#     if(OpenSSL_FOUND)
#         target_link_libraries(stress-test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
#     endif()
# endif()

# ============================================================
# 自定义目标: 生成自签名开发证书
# ============================================================
set(CERTS_DIR "${CMAKE_SOURCE_DIR}/certs")
set(CERT_FILE "${CERTS_DIR}/cert.pem")
set(KEY_FILE  "${CERTS_DIR}/key.pem")

if(WIN32)
    set(GEN_CERT_SCRIPT "${CMAKE_SOURCE_DIR}/gen_cert.bat")
    set(GEN_CERT_CMD call "${GEN_CERT_SCRIPT}" "${CERTS_DIR}")
else()
    set(GEN_CERT_SCRIPT "${CMAKE_SOURCE_DIR}/gen_cert.sh")
    set(GEN_CERT_CMD "${CMAKE_COMMAND}" -E env bash "${GEN_CERT_SCRIPT}" "${CERTS_DIR}")
endif()

add_custom_target(gen-certs
    COMMAND ${GEN_CERT_CMD}
    COMMENT "Generate self-signature TLS development certificate → ${CERTS_DIR}"
    BYPRODUCTS "${CERT_FILE}" "${KEY_FILE}"
)

add_custom_target(gen-certs-force
    COMMAND ${CMAKE_COMMAND} -E remove "${CERT_FILE}" "${KEY_FILE}"
    COMMAND ${GEN_CERT_CMD}
    COMMENT "Force re-generate self-signature TLS development certificate → ${CERTS_DIR}"
)

# 提醒: gen-certs 不是默认构建的一部分
if(NOT EXISTS "${CERT_FILE}")
    message(STATUS "Notice: Run 'cmake --build . --target gen-certs' to generate a development certificate")
endif()
