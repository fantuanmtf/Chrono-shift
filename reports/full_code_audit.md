# 🔍 Chrono-shift 全量代码审计报告

> **生成时间**: 2026-05-31 05:09:37
> **文件总数**: 289 | **分析文件**: 252 | **问题总数**: 552

> 🔴 严重/高危: **7** | 🟡 中危: **30** | 🔵 低危/建议: **515** | ℹ️ 信息: **0**

---

## 📊 问题分类统计

| 类别 | 数量 |
|------|------|
| 编码/乱码 | 333 |
| 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent | 126 |
| 🟡 注意: unsafe块 - 需要人工审查 | 40 |
| 🔵 建议: unwrap() 可能panic，生产代码建议用?或match | 16 |
| 🟡 警告: curl含变量 - 检查是否过滤特殊字符 | 12 |
| 🟡 警告: malloc - 检查返回值是否为NULL | 8 |
| 🟡 警告: system() - 命令注入风险，检查参数来源 | 6 |
| 🟡 警告: realloc - 失败时原内存泄漏风险 | 4 |
| 🔴 高危: eval() - 代码注入风险 | 2 |
| 🔴 高危: shell eval + 变量 - 代码注入风险 | 2 |
| 🔴 高危: sprintf - 格式化字符串/缓冲区溢出，建议改用snprintf | 1 |
| 🔴 高危: popen - 命令注入风险 | 1 |
| 🔴 高危: exec() - 代码注入风险 | 1 |

---

## 🔴 严重/高危问题


### 📄 `client\src\i2p\I2pdEmbedded.cpp`

- **L230**: 🔴 高危: popen - 命令注入风险
  ```
  FILE* pipe = popen(cmd.c_str(), "r");
  ```


### 📄 `client\src\json_parser.c`

- **L78**: 🔴 高危: sprintf - 格式化字符串/缓冲区溢出，建议改用snprintf
  ```
  p += sprintf(p, "\\u%04x", c);
  ```


### 📄 `scripts\full_code_audit.py`

- **L64**: 🔴 高危: eval() - 代码注入风险
  ```
  (r'\beval\s*\(', '🔴 高危: eval() - 代码注入风险'),
  ```

- **L70**: 🔴 高危: eval() - 代码注入风险
  ```
  (r'\beval\s*\(', '🔴 高危: eval() - 代码注入风险'),
  ```

- **L71**: 🔴 高危: exec() - 代码注入风险
  ```
  (r'\bexec\s*\(', '🔴 高危: exec() - 代码注入风险'),
  ```


### 📄 `tests\api_verification_test.sh`

- **L50**: 🔴 高危: shell eval + 变量 - 代码注入风险
  ```
  local http_code=$(eval ${cmd})
  ```


### 📄 `tests\security_pen_test.sh`

- **L49**: 🔴 高危: shell eval + 变量 - 代码注入风险
  ```
  local http_code=$(eval ${cmd})
  ```

---

## 🟡 中危/警告


### 📄 `client\devtools\cli\commands\cmd_gen_cert.c`

- **L199**: 🟡 警告: system() - 命令注入风险，检查参数来源
  ```
  int ret = system(cmd);
  ```

- **L224**: 🟡 警告: system() - 命令注入风险，检查参数来源
  ```
  int ret = system(cmd);
  ```

- **L253**: 🟡 警告: system() - 命令注入风险，检查参数来源
  ```
  int ret = system(cmd);
  ```


### 📄 `client\devtools\cli\commands\cmd_gen_cert.cpp`

- **L189**: 🟡 警告: system() - 命令注入风险，检查参数来源
  ```
  int ret = std::system(cmd.c_str());
  ```

- **L213**: 🟡 警告: system() - 命令注入风险，检查参数来源
  ```
  int ret = std::system(cmd.c_str());
  ```

- **L237**: 🟡 警告: system() - 命令注入风险，检查参数来源
  ```
  int ret = std::system(cmd.c_str());
  ```


### 📄 `client\devtools\cli\commands\cmd_obfuscate.cpp`

- **L36**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  char* result = static_cast<char*>(std::malloc(len));
  ```

- **L49**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  char* result = static_cast<char*>(std::malloc(std::strlen(payload) + 1));
  ```


### 📄 `client\src\json_parser.c`

- **L21**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  char* out = (char*)malloc(la + lb + lc + 1);
  ```

- **L43**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  char* out = (char*)malloc(len + 1);
  ```

- **L64**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  char* out = (char*)malloc(cap);
  ```

- **L114**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  char* out = (char*)malloc(cap);
  ```

- **L142**: 🟡 警告: realloc - 失败时原内存泄漏风险
  ```
  out = (char*)realloc(out, cap);
  ```

- **L163**: 🟡 警告: realloc - 失败时原内存泄漏风险
  ```
  out = (char*)realloc(out, cap);
  ```

- **L181**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  val->array.items = (JsonValue**)malloc(cap * sizeof(JsonValue*));
  ```

- **L191**: 🟡 警告: realloc - 失败时原内存泄漏风险
  ```
  val->array.items = (JsonValue**)realloc(val->array.items, cap * sizeof(JsonValue*));
  ```

- **L210**: 🟡 警告: malloc - 检查返回值是否为NULL
  ```
  val->object.pairs = (JsonPair*)malloc(cap * sizeof(JsonPair));
  ```

- **L226**: 🟡 警告: realloc - 失败时原内存泄漏风险
  ```
  val->object.pairs = (JsonPair*)realloc(val->object.pairs, cap * sizeof(JsonPair));
  ```


### 📄 `tests\api_verification_test.sh`

- **L42**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  local cmd="curl -s -o \"${REPORT_DIR}/.resp_body\" -w \"%{http_code}\" -X ${method} \"${BASE_URL}${path}\""
  ```

- **L139**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L227**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L266**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L307**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```


### 📄 `tests\security_pen_test.sh`

- **L44**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  local cmd="curl -s -o \"${REPORT_DIR}/.resp_body\" -w \"%{http_code}\" -X ${method} \"${BASE_URL}${path}\""
  ```

- **L241**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L268**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L296**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L452**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L539**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

- **L561**: 🟡 警告: curl含变量 - 检查是否过滤特殊字符
  ```
  HTTP_CODE=$(curl -s -o "${REPORT_DIR}/.resp_body" -w "%{http_code}" \
  ```

---

## 🔵 低危/建议


### 📄 `client\devtools\cli\commands\cmd_connect.cpp`

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_connect.cpp �?连接目标服务器命�?
  ```

- **L16**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * connect 命令 - 设置目标服务�?
  ```

- **L45**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 目标服务�? {}:{} ({})",
  ```


### 📄 `client\devtools\cli\commands\cmd_disconnect.cpp`

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_disconnect.cpp �?断开当前连接命令
  ```

- **L14**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * tls_close (�?core 或外部库提供)
  ```

- **L26**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 关闭 WebSocket 连接 (如果�? */
  ```


### 📄 `client\devtools\cli\commands\cmd_endpoint.cpp`

- **L0**: 🔵 文件含6个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_endpoint.cpp �?API 端点测试命令 (C++23 版本)
  ```

- **L13**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // HTTP 底层函数 �?�?net_http.cpp 通过 extern "C" 提供
  ```

- **L32**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "  path   - API 路径, �?/api/user/profile?id=1");
  ```

- **L34**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "  body   - POST/PUT 请求�?(JSON 字符�?");
  ```


### 📄 `client\devtools\cli\commands\cmd_friend.cpp`

- **L16**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * HTTP 请求 (�?net_http.cpp 提供 extern "C" 兼容�?
  ```

- **L85**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知 friend 子命�? {}", subcmd);
  ```


### 📄 `client\devtools\cli\commands\cmd_json.cpp`

- **L0**: 🔵 文件含21个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_json.cpp �?JSON 解析/格式化命�?
  ```

- **L17**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * �?core 或外部库提供
  ```

- **L40**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * json-parse 命令 - 解析并验�?JSON
  ```

- **L46**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "  解析并验�?JSON 字符串的合法�?);
  ```

- **L57**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    可能的原�?");
  ```

- **L58**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("      - 缺少括号或引�?);
  ```

- **L76**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    �? {}", val->string_val);
  ```

- **L80**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    �? {}", val->number_val);
  ```

- **L84**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    �? {}", val->bool_val ? "true" : "false");
  ```

- **L99**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * json-pretty 命令 - 格式�?JSON
  ```

- **L105**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "  格式化输�?JSON 字符�?);
  ```

- **L110**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 格式化后�?JSON:");
  ```

- **L113**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 先验�?JSON */
  ```

- **L117**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] 警告: JSON 语法可能无效, 尝试直接格式�?);
  ```

- **L130**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "解析并验�?JSON 字符�?,
  ```

- **L139**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "格式化输�?JSON 字符�?,
  ```


### 📄 `client\devtools\cli\commands\cmd_msg.cpp`

- **L0**: 🔵 文件含6个Unicode替换字符(U+FFFD)

- **L16**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * HTTP 请求 (�?net_http.cpp 提供 extern "C" 兼容�?
  ```

- **L35**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  msg send <to_user_id> <text>         - 发送测试消�?);
  ```

- **L82**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 发送消�? to={}, text={}", to_uid, text);
  ```

- **L92**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[+] 消息发送成�?(HTTP {}):", status);
  ```

- **L102**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知 msg 子命�? {}", subcmd);
  ```


### 📄 `client\devtools\cli\commands\cmd_network.cpp`

- **L0**: 🔵 文件含47个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_network.cpp �?网络诊断命令
  ```

- **L7**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 完整�?DNS/TCP/TLS/HTTP 四层连通性诊�?
  ```

- **L56**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * network 命令 - 网络连通性测�?
  ```

- **L62**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  network test <host> <port>     - 网络连通性测�?);
  ```

- **L63**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    测试目标主机�?TCP 连接�?TLS 握手");
  ```

- **L85**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?    网络连通性测�?                                       �?);
  ```

- **L100**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?DNS 解析失败: {}", test_host);
  ```

- **L102**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        错误�? {}", WSAGetLastError());
  ```

- **L109**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?DNS 解析成功: {} -> {} ({:.1f} ms)",
  ```

- **L121**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?创建 socket 失败");
  ```

- **L151**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?TCP 连接失败");
  ```

- **L166**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?TCP 连接超时 (3s)");
  ```

- **L178**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?TCP 连接成功 ({:.1f} ms)", tcp_time);
  ```

- **L181**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* Step 3: TLS 握手 (可�? */
  ```

- **L187**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?TLS 初始化失�? {}", tls_last_error());
  ```

- **L188**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        (�?TCP 连接可用, �?TLS)");
  ```

- **L191**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?TLS 握手失败: {}", tls_last_error());
  ```

- **L197**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?TLS 握手成功 ({:.1f} ms)", tls_time);
  ```

- **L236**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?HTTP GET /api/health -> {} ({:.1f} ms)",
  ```

- **L239**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?HTTP 请求失败: {}", tls_last_error());
  ```

- **L243**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ┌─────────────────────────────────────────────────────────�?);
  ```

- **L244**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?测试摘要                                                �?);
  ```

- **L245**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ├─────────────────────────────────────────────────────────�?);
  ```

- **L246**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?DNS:     �?{:.1f} ms                                    �?, dns_time);
  ```

- **L247**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?TCP:     �?{:.1f} ms                                    �?, tcp_time);
  ```

- **L248**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?TLS:     {}                                              �?, ssl ? "�? : "�?);
  ```

- **L249**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?HTTP:    {}                                              �?, http_ret == 0 ? "�? : "�?);
  ```

- **L250**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  └─────────────────────────────────────────────────────────�?);
  ```

- **L260**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知 network 子命�? {}", subcmd);
  ```

- **L268**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "网络连通性诊�?(DNS/TCP/TLS/HTTP)",
  ```


### 📄 `client\devtools\cli\commands\cmd_obfuscate.cpp`

- **L0**: 🔵 文件含49个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_obfuscate.cpp �?ASM 私有混淆加密调试命令
  ```

- **L6**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 用于快速测�?ASM 混淆加密/解密流程�?
  ```

- **L7**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 需要链�?Rust 安全�?(chrono_client_security) 或使用内置模拟�?
  ```

- **L10**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  *   obfuscate genkey                    - 生成随机 512 位密�?(128 hex 字符)
  ```

- **L11**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  *   obfuscate test                      - 运行自测�?(随机数据 + 随机密钥)
  ```

- **L28**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* ─── 模拟 Rust FFI (编译时未链接 Rust 库时的占�? ─── */
  ```

- **L76**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** Base64 编码 (简易实现，仅用于测�? */
  ```

- **L101**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  obfuscate genkey                    - 生成随机 512 位密�?);
  ```

- **L102**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  obfuscate test                      - 运行自测�?);
  ```

- **L110**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* ── genkey: 生成随机 512 位密�?── */
  ```

- **L117**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?    ASM 私有混淆 �?512 位密钥生�?                      �?);
  ```

- **L128**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* ── test: 运行自测�?── */
  ```

- **L132**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?    ASM 私有混淆 �?自测�?                              �?);
  ```

- **L138**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 测试 1: 基本加密/解密往�?*/
  ```

- **L140**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [测试 1] 基本加密/解密往�?..");
  ```

- **L153**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  if (!obf) { cli::println("        �?加密失败"); fail++; goto test1_end; }
  ```

- **L156**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  if (!deobf) { cli::println("        �?解密失败"); fail++; goto test1_end; }
  ```

- **L161**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  if (!obf) { cli::println("        �?加密失败"); fail++; goto test1_end; }
  ```

- **L164**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  if (!deobf) { cli::println("        �?解密失败"); fail++; goto test1_end; }
  ```

- **L169**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?往返测试通过");
  ```

- **L172**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?往返测试失�? 解密结果与原始数据不�?);
  ```

- **L195**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?加密失败");
  ```

- **L205**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?不同密钥产生不同密文");
  ```

- **L208**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?不同密钥产生了相同密�?);
  ```

- **L213**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 模拟占位模式下不�?key 产生相同结果，跳过此测试 */
  ```

- **L215**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        - 占位模式跳过 (mock 不依�?key)");
  ```

- **L222**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 测试 3: 空数据处�?*/
  ```

- **L224**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [测试 3] 空数据处�?(应返回错�?...");
  ```

- **L237**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?空数据正确返回错�?);
  ```

- **L240**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        �?空数据未返回错误");
  ```

- **L263**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?    ASM 私有混淆 �?加密                                 �?);
  ```

- **L326**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知子命�? {}", subcmd);
  ```

- **L333**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "ASM 私有混淆加密调试 (512 位密�?",
  ```


### 📄 `client\devtools\cli\commands\cmd_ping.cpp`

- **L0**: 🔵 文件含14个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_ping.cpp �?服务器延迟测试命�?(C++23 版本)
  ```

- **L22**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // HTTP 底层函数 �?�?net_http.cpp 通过 extern "C" 提供
  ```

- **L33**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // ping 命令 - 服务器延迟测�?
  ```

- **L42**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] ping 次数限制�?1-20 之间");
  ```

- **L47**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 开�?ping {}:{} ({} �?...",
  ```

- **L84**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 请求间间�?200ms */
  ```

- **L92**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    发�? {}, 成功: {}, 失败: {}", count, succeeded, failed);
  ```

- **L95**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    最�? {:.1f} ms", min_time);
  ```

- **L96**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    最�? {:.1f} ms", max_time);
  ```

- **L105**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "服务器延迟测�?(默认3�?",
  ```


### 📄 `client\devtools\cli\commands\cmd_rate_test.cpp`

- **L0**: 🔵 文件含8个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_rate_test.cpp �?速率测试命令
  ```

- **L27**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * rate-test 命令 - 速率/吞吐率测�?
  ```

- **L41**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 开始速率测试: {} 个并发请�?-> {}:{}",
  ```

- **L67**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [{:3}/{}] �?HTTP {}  {:.1f} ms",
  ```

- **L71**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [{:3}/{}] �?失败: {}",
  ```

- **L82**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    总请�? {}", num_requests);
  ```

- **L88**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    吞吐�?   {:.1f} req/s",
  ```

- **L98**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "速率/吞吐率测�?,
  ```


### 📄 `client\devtools\cli\commands\cmd_storage.cpp`

- **L0**: 🔵 文件含33个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_storage.cpp �?安全存储命令
  ```

- **L28**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 初始化存储路�?*/
  ```

- **L46**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?    本地安全存储 (Secure Storage)                        �?);
  ```

- **L52**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ┌──────────┬────────────────────────────────────────────�?);
  ```

- **L53**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?键名     �?�?                                        �?);
  ```

- **L54**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ├──────────┼────────────────────────────────────────────�?);
  ```

- **L56**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?token    �?{:<42} �?, cli::g_cli_config.session_token);
  ```

- **L58**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?token    �?{:<42} �?, "(�?");
  ```

- **L61**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?user_id  �?{:<42} �?, "1");
  ```

- **L63**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?user_id  �?{:<42} �?, "(�?");
  ```

- **L65**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?device   �?chrono-cli (当前工具)                      �?);
  ```

- **L66**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  └──────────┴────────────────────────────────────────────�?);
  ```

- **L68**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  说明: 生产环境中使�?AES-256-GCM 加密存储");
  ```

- **L85**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] token = (未设�? 请先 session login)");
  ```

- **L88**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] �?'{}' 不存在于本地存储", key);
  ```

- **L89**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 可用�? token, user_id, device");
  ```

- **L95**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知 storage 子命�? {}", subcmd);
  ```


### 📄 `client\devtools\cli\commands\cmd_tls.cpp`

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_tls.cpp �?TLS 连接信息命令
  ```

- **L15**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * tls_client 函数 (�?core 或外部库提供)
  ```

- **L35**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 建立临时 TLS 连接来获取信�?*/
  ```

- **L43**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "[-] 无法连接�?{}:{}: {}",
  ```


### 📄 `client\devtools\cli\commands\cmd_token.cpp`

- **L0**: 🔵 文件含20个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_token.cpp �?JWT 令牌解码命令 (C++23 版本)
  ```

- **L18**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** 解码 JWT 的单个部�?(Base64 -> JSON 打印) */
  ```

- **L26**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // base64_decode 返回 vector<uint8_t>, 追加 null 终止�?
  ```

- **L33**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** token - 解码并分�?JWT */
  ```

- **L44**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::print("    令牌�?2�? ");
  ```

- **L51**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* �?'.' 分割 JWT */
  ```

- **L66**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] 无效�?JWT 格式: 需要至�?2 个部�?(header.payload)");
  ```

- **L78**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 检�?Signature */
  ```

- **L82**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [3] Signature: �?);
  ```

- **L83**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] 警告: 令牌无签�? 可能被篡�?");
  ```

- **L86**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* �?payload 中提取过期时�?*/
  ```

- **L105**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // ctime 包含换行�?
  ```

- **L108**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [-] 令牌已过�?");
  ```

- **L111**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [+] 令牌有效, 剩余 {:.0f} �?, remaining);
  ```

- **L145**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "解码并分�?JWT 令牌",
  ```


### 📄 `client\devtools\cli\commands\cmd_trace.cpp`

- **L0**: 🔵 文件含9个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_trace.cpp �?请求追踪命令
  ```

- **L37**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "  发�?TRACE 请求追踪请求经过的路�?);
  ```

- **L47**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 追踪过程的模拟步�?*/
  ```

- **L52**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 实际发送请求测试路�?*/
  ```

- **L69**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("     => health_handler (健康检�?");
  ```

- **L81**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("     => 未知路由或静态文�?);
  ```

- **L93**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [4/5] HTTP 请求: 未发�?);
  ```

- **L94**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [5/5] 响应处理: 无响�?);
  ```


### 📄 `client\devtools\cli\commands\cmd_user.cpp`

- **L0**: 🔵 文件含7个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_user.cpp �?用户管理命令 (C++23 版本)
  ```

- **L12**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // HTTP 底层函数 �?�?net_http.cpp 通过 extern "C" 提供
  ```

- **L26**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** 执行 HTTP 请求并检查状�?*/
  ```

- **L43**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** user list - 列出所有用�?*/
  ```

- **L155**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  user list                     - 列出所有用�?);
  ```

- **L185**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知 user 子命�? {}", subcmd);
  ```


### 📄 `client\devtools\cli\commands\cmd_watch.cpp`

- **L0**: 🔵 文件含18个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * cmd_watch.cpp �?实时监控服务器状态命�?
  ```

- **L29**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * watch 命令 - 实时监控服务器状�?
  ```

- **L38**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] watch 间隔限制�?1-30 �?);
  ```

- **L48**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] watch 轮次限制�?1-100");
  ```

- **L53**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 开始监�?{}:{} (间隔 {}s, {} �?...",
  ```

- **L56**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    �?Ctrl+C 终止...");
  ```

- **L83**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [{}] �?状态变�? {} -> {}",
  ```

- **L89**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  const char* status_flag = (status >= 200 && status < 300) ? "�? : "�?;
  ```

- **L95**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("        响应: {}", body ? body : "(�?");
  ```

- **L101**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [{}] �?连接失败: {}", time_str, tls_last_error());
  ```

- **L108**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] 警告: 连续 {} 次异�? 服务器可能不稳定!", unstable_count);
  ```

- **L120**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 监控完成 ({} �?", max_rounds);
  ```

- **L127**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  "实时监控服务器状�?,
  ```


### 📄 `client\devtools\cli\commands\cmd_ws.cpp`

- **L0**: 🔵 文件含42个Unicode替换字符(U+FFFD)

- **L3**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 对应 cmd_ws.c �?C++23 重构�?
  ```

- **L4**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * �?SHA-1 实现 (用于 WebSocket 握手)
  ```

- **L21**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // TLS C 函数 (�?tls_client.c 实现)
  ```

- **L148**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] WebSocket 已连�? 先使�?ws close 关闭");
  ```

- **L209**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "[-] TLS 初始化失�? {}", tls_last_error());
  ```

- **L218**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 发送握手请�?*/
  ```

- **L257**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[-] WS Accept Key 不匹�?\n    期望: {}\n    收到: {}",
  ```

- **L275**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "[-] WebSocket 未连�?);
  ```

- **L385**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ws send <json>               - 通过 WS 发送消�?);
  ```

- **L386**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ws recv                      - 接收 WS 消息 (非阻�?");
  ```

- **L388**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ws status                    - 查看 WS 连接状�?);
  ```

- **L408**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] 发�?WS 消息: {}", data);
  ```

- **L412**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[+] WS 消息发送成�?({} 字节)", std::strlen(data));
  ```

- **L432**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] WS 关闭�?);
  ```

- **L435**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] WS �?opcode=0x{:X} ({} 字节)", opcode, rlen);
  ```

- **L448**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[+] WebSocket 连接已关�?);
  ```

- **L452**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("[*] WebSocket 状�?");
  ```

- **L454**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  ? "已连�? : "未连�?);
  ```

- **L455**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("    服务�? {}:{}", cli::g_cli_config.host,
  ```

- **L461**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "[-] WebSocket 未连�?);
  ```

- **L470**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?    WebSocket 监控模式 ({} �?                          �?, rounds);
  ```

- **L481**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?连接中断 (�?{} �?", r);
  ```

- **L490**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [{}] �?Ping (无消�?", ts);
  ```

- **L495**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ┌─────────────────────────────────────────────────────────�?);
  ```

- **L496**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?[{}] WS 消息 #{}                                      �?, ts, msg_count);
  ```

- **L497**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  ├─────────────────────────────────────────────────────────�?);
  ```

- **L499**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?{}", reinterpret_cast<const char*>(buf));
  ```

- **L501**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  �?({} 字节数据)", rlen);
  ```

- **L502**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  └─────────────────────────────────────────────────────────�?);
  ```

- **L512**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  [*] 监控完成: �?{} 条消�?({} �?", msg_count, rounds);
  ```

- **L516**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "未知 ws 子命�? {}", subcmd);
  ```


### 📄 `client\devtools\cli\main.cpp`

- **L0**: 🔵 文件含35个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * main.cpp �?开发者模�?CLI 主入�?(C++23 重构�?
  ```

- **L5**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 支持独立运行与脚本模�?
  ```

- **L8**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 为与现有�?cmd_*.c (C 文件) 共存，此文件定义:
  ```

- **L10**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  *   2) extern "C" 兼容�?(g_command_table, g_config, register_command, find_command)
  ```

- **L12**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 逐步迁移: 每转换一�?cmd_*.c �?cmd_*.cpp，就移除对应�?extern "C" 依赖�?
  ```

- **L41**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // C 兼容�?�?用于现有�?cmd_*.c (C 文件)
  ```

- **L45**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 包含 C 头文件以保持类型一�?
  ```

- **L47**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 这与 C++23 �?chrono::client::cli::CommandHandler (move_only_function) 冲突
  ```

- **L48**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 因此�?extern "C" 函数中直接使�?C 函数指针类型
  ```

- **L61**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * register_command �?C 兼容包装
  ```

- **L62**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * �?C 风格命令表注册，同时同步�?C++ CommandRegistry
  ```

- **L63**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 等价�?C 头文�? void register_command(const char*, const char*, const char*, CommandHandler)
  ```

- **L69**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // C 兼容�?
  ```

- **L80**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 同步�?C++ CommandRegistry
  ```

- **L140**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 同步�?C++ Config
  ```

- **L143**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 从环境变量读�?
  ```

- **L338**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 同步�?C config
  ```

- **L344**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 主入�?
  ```

- **L348**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 初始化配�?
  ```

- **L351**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 初始�?Winsock
  ```

- **L367**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 引入外部命令 (�?cmd_*.c / init_commands.cpp 中注�?
  ```

- **L391**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 脚本模式: 直接执行传入的参�?
  ```

- **L455**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 查找并执行命�?(C++23 API)
  ```


### 📄 `client\devtools\cli\net_http.cpp`

- **L0**: 🔵 文件含20个Unicode替换字符(U+FFFD)

- **L2**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * net_http.cpp �?开发者模�?CLI HTTP 网络�?(C++23 重构�?
  ```

- **L4**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 自包含的 HTTP/HTTPS 客户端实�?
  ```

- **L5**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 支持 TCP 明文�?OpenSSL TLS 加密连接
  ```

- **L10**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  * 2) 提供 C++23 HttpClient RAII 类供�?C++ 代码使用
  ```

- **L106**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** 发送所有数�?*/
  ```

- **L127**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /** 接收所有响应数�?*/
  ```

- **L150**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // parse_response 前向声明 �?HttpClient::request() 中使�?
  ```

- **L156**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // extern "C" 兼容�?�?�?cmd_*.c (C 文件) 调用
  ```

- **L167**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 使用 C++23 内部�?request 逻辑
  ```

- **L216**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 发�?
  ```

- **L274**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 拷贝�?C 风格输出缓冲�?
  ```

- **L302**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // HttpClient::request �?C++23 RAII 实现
  ```

- **L348**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 发�?
  ```


### 📄 `client\devtools\ui\js\devtools.js`

- **L161**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  devtoolsBtn.innerHTML =
  ```

- **L177**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  view.innerHTML = this.buildDevToolsHTML();
  ```

- **L628**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  output.innerHTML = '';
  ```

- **L727**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">🌐</div><p>暂无网络请求记录</p></div>';
  ```

- **L748**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = html;
  ```

- **L770**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;padding:20px;"><span class="devtools-spinner"></span> 加载中...</td></tr>';
  ```

- **L774**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  tbody.innerHTML = '';
  ```

- **L778**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;padding:20px;color:#999;">暂无存储数据</td></tr>';
  ```

- **L784**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  tr.innerHTML = '<td style="font-family:Consolas,monospace;font-size:11px;">' + esc(entry.key) + '</td>' +
  ```

- **L789**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  detail.innerHTML = highlightJSON(entry);
  ```

- **L795**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;padding:20px;color:#ef4444;">加载失败: ' + esc(data.message || '未知错误') + '</td></tr>';
  ```

- **L798**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;padding:20px;color:#ef4444;">请求失败: ' + esc(err.message) + '</td></tr>';
  ```

- **L809**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  jsonView.innerHTML = '<span class="devtools-spinner"></span> 加载中...';
  ```

- **L812**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  jsonView.innerHTML = highlightJSON(data);
  ```

- **L814**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  jsonView.innerHTML = '<span class="error">请求失败: ' + esc(err.message) + '</span>';
  ```

- **L822**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  el.innerHTML = '<span class="devtools-status ' + (connected ? 'online' : 'offline') + '">' +
  ```

- **L830**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  el.innerHTML = '<span class="devtools-status offline"><span class="devtools-status-dot offline"></span> 服务器: 无法连接</span>';
  ```

- **L842**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  infoEl.innerHTML = '<span style="color:#ef4444;font-size:12px;">未登录，无 Token 可解码</span>';
  ```

- **L854**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  infoEl.innerHTML = '<div class="devtools-json-viewer">' + highlightJSON(payload) + '</div>';
  ```

- **L856**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  infoEl.innerHTML = '<span style="font-size:12px;">Token: ' + esc(data.token.substring(0, 40)) + '...</span>';
  ```

- **L859**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  infoEl.innerHTML = '<span style="font-size:12px;color:#999;">无法获取 Token (可能需要先登录)</span>';
  ```

- **L862**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  infoEl.innerHTML = '<span style="font-size:12px;color:#999;">无法连接到后端</span>';
  ```

- **L865**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  infoEl.innerHTML = '<span style="color:#ef4444;font-size:12px;">解析会话数据失败</span>';
  ```

- **L897**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  responseEl.innerHTML = '<span class="devtools-spinner"></span> 发送请求...';
  ```

- **L929**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  responseEl.innerHTML = highlightJSON(parsed);
  ```

- **L931**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  responseEl.innerHTML = esc(text);
  ```

- **L939**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  responseEl.innerHTML = '<span class="error">错误: ' + esc(err.message) + '</span>';
  ```

- **L951**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  statusEl.innerHTML = '<span class="devtools-spinner"></span> 检测中...';
  ```

- **L957**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  statusEl.innerHTML = '状态: <span class="devtools-status ' + (connected ? 'online' : 'offline') + '">' +
  ```

- **L976**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">🔌</div><p>暂无 WebSocket 消息记录</p></div>';
  ```

- **L1023**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">🔌</div><p>暂无 WebSocket 消息记录</p></div>';
  ```

- **L1038**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = html;
  ```

- **L1115**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  listEl.innerHTML = '<div style="text-align:center;padding:20px;"><span class="devtools-spinner"></span> 加载插件列表...</div>';
  ```

- **L1123**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  listEl.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">🧩</div><p>暂无已注册插件</p></div>';
  ```

- **L1138**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  listEl.innerHTML = html;
  ```

- **L1141**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  listEl.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">🧩</div><p>暂无插件数据</p></div>';
  ```

- **L1144**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  listEl.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">🧩</div><p>无法获取插件列表 (后端可能未启动)</p></div>';
  ```

- **L1152**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  extEl.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">📋</div><p>暂无已注册扩展</p></div>';
  ```

- **L1166**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  extEl.innerHTML = extHTML;
  ```

- **L1169**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  extEl.innerHTML = '<div class="devtools-empty"><div class="devtools-empty-icon">📋</div><p>ChronoExtensions 未初始化</p></div>';
  ```

- **L1181**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  manifestEl.innerHTML = '<span style="color:#ef4444;">请输入插件路径</span>';
  ```

- **L1185**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  manifestEl.innerHTML = '<span class="devtools-spinner"></span> 加载中...';
  ```

- **L1190**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  manifestEl.innerHTML = highlightJSON(data.manifest);
  ```

- **L1192**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  manifestEl.innerHTML = '<span style="color:#ef4444;">加载失败: ' + esc(data.message || '未找到 manifest') + '</span>';
  ```

- **L1195**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  manifestEl.innerHTML = '<span style="color:#ef4444;">请求失败，后端可能未运行</span>';
  ```


### 📄 `client\security\rust_core\src\cli\mod.rs`

- **L20**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  stdout.flush().unwrap();
  ```


### 📄 `client\security\rust_core\src\cli\user.rs`

- **L19**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe { MY_UID = Some(name.clone()); }
  ```

- **L23**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe {
  ```

- **L40**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe {
  ```

- **L57**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  "list" => unsafe {
  ```

- **L64**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe { if !FRIENDS.contains(&uid) { FRIENDS.push(uid.clone()); } }
  ```

- **L83**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe {
  ```

- **L89**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  "inbox" => unsafe {
  ```

- **L109**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  stdout.flush().unwrap();
  ```

- **L115**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe {
  ```


### 📄 `client\security\rust_core\src\crypto.rs`

- **L82**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let enc = encrypt_e2e(plain, &key).unwrap();
  ```

- **L83**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let dec = decrypt_e2e(&enc, &key).unwrap();
  ```

- **L98**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let c1 = encrypt_e2e(plain, &k1).unwrap();
  ```

- **L99**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let c2 = encrypt_e2e(plain, &k2).unwrap();
  ```


### 📄 `client\security\rust_core\src\cve.rs`

- **L132**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let r = CveDb::parse_one(j).unwrap();
  ```


### 📄 `client\security\rust_core\src\ffi.rs`

- **L24**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len as usize) };
  ```

- **L25**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let k = unsafe { std::slice::from_raw_parts(key, 32) };
  ```

- **L31**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe { *out_len = result.len() as u32; }
  ```

- **L51**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let enc = unsafe { std::slice::from_raw_parts(encrypted, encrypted_len as usize) };
  ```

- **L52**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let k = unsafe { std::slice::from_raw_parts(key, 32) };
  ```

- **L58**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe { *out_len = result.len() as u32; }
  ```

- **L74**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let b = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
  ```

- **L87**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let aa = unsafe { std::slice::from_raw_parts(a, a_len as usize) };
  ```

- **L88**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let bb = unsafe { std::slice::from_raw_parts(b, b_len as usize) };
  ```

- **L100**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let s = unsafe { CStr::from_ptr(input) }.to_str().unwrap_or("");
  ```

- **L103**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let result = CString::new("ok").unwrap();
  ```

- **L116**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let s = unsafe { CStr::from_ptr(input) }.to_str().unwrap_or("");
  ```

- **L129**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let b = unsafe { std::slice::from_raw_parts(data, len as usize) };
  ```

- **L141**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let p = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or("");
  ```

- **L154**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let p = unsafe { CStr::from_ptr(product) }.to_str().unwrap_or("");
  ```

- **L166**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe { drop(CString::from_raw(ptr)); }
  ```

- **L174**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe { drop(Vec::from_raw_parts(ptr, len as usize, len as usize)); }
  ```

- **L182**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let data = unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) };
  ```


### 📄 `client\security\rust_core\src\network.rs`

- **L93**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  Err(last_err.unwrap())
  ```


### 📄 `client\security\rust_core\src\parser.rs`

- **L87**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let v = parse_json(r#"{"name":"test","value":42}"#).unwrap();
  ```


### 📄 `client\security\rust_core\src\ratchet.rs`

- **L218**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let (dec, _) = bob.decrypt(&enc, idx).unwrap();
  ```

- **L235**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let (dec2, _) = bob.decrypt(&enc2, idx2).unwrap();
  ```


### 📄 `client\security\src\asm_bridge.rs`

- **L43**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let ret = unsafe {
  ```

- **L69**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let ret = unsafe {
  ```


### 📄 `client\security\src\crypto.rs`

- **L39**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let text = match unsafe { CStr::from_ptr(plaintext) }.to_str() {
  ```

- **L43**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let key_str = match unsafe { CStr::from_ptr(pubkey_b64) }.to_str() {
  ```

- **L93**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let ct_str = match unsafe { CStr::from_ptr(ciphertext_b64) }.to_str() {
  ```

- **L97**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let key_str = match unsafe { CStr::from_ptr(privkey_b64) }.to_str() {
  ```

- **L169**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let b64_str = match unsafe { CStr::from_ptr(plaintext_b64) }.to_str() {
  ```

- **L173**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let key_str = match unsafe { CStr::from_ptr(key_hex) }.to_str() {
  ```

- **L220**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let ct_str = match unsafe { CStr::from_ptr(ciphertext_b64) }.to_str() {
  ```

- **L224**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let key_str = match unsafe { CStr::from_ptr(key_hex) }.to_str() {
  ```


### 📄 `client\security\src\lib.rs`

- **L21**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let path = match unsafe { CStr::from_ptr(app_data_path) }.to_str() {
  ```

- **L68**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  unsafe {
  ```


### 📄 `client\security\src\session.rs`

- **L43**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let uid = unsafe { CStr::from_ptr(user_id) }.to_str().unwrap_or("");
  ```

- **L44**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let name = unsafe { CStr::from_ptr(username) }.to_str().unwrap_or("");
  ```

- **L45**: 🟡 注意: unsafe块 - 需要人工审查
  ```
  let t = unsafe { CStr::from_ptr(token) }.to_str().unwrap_or("");
  ```

- **L58**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let mut session = SESSION.lock().unwrap();
  ```

- **L70**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let session = SESSION.lock().unwrap();
  ```

- **L81**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let session = SESSION.lock().unwrap();
  ```

- **L88**: 🔵 建议: unwrap() 可能panic，生产代码建议用?或match
  ```
  let mut session = SESSION.lock().unwrap();
  ```


### 📄 `client\tools\stress_test.cpp`

- **L0**: 🔵 文件含82个Unicode替换字符(U+FFFD)

- **L7**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  *   - 可配�?QPS 目标、线程数、持续时�?
  ```

- **L8**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  *   - 实时统计：QPS、延�?P50/P95/P99)、错误率
  ```

- **L52**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // tls_client.c 编译�?C, 需�?extern "C" 链接
  ```

- **L89**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  {"健康检�?,   "GET",    "/api/health",          nullptr, nullptr},
  ```

- **L97**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  {"发送消�?,   "POST",   "/api/message/send",
  ```

- **L122**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 命令行参�?
  ```

- **L224**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 计时开�?(包含 TCP 连接 + TLS 握手 + 请求收发) */
  ```

- **L227**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* tls_client_init �?worker 线程中首次调用时初始化全局 ctx */
  ```

- **L238**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 发送请�?*/
  ```

- **L269**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // HTTP 明文模式 (用于开�?调试)
  ```

- **L313**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 计时开�?*/
  ```

- **L316**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 发送请�?*/
  ```

- **L361**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 检�?HTTP 状态码 */
  ```

- **L367**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  ret = 1;  /* �?200 但有效响�?*/
  ```

- **L415**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 更新最�?最小延�?*/
  ```

- **L461**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  --port <port>     服务器端�?(默认: 4443)");
  ```

- **L462**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  --threads <n>     并发线程�?(默认: 4, 最�? {})", MAX_THREADS);
  ```

- **L464**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  --duration <s>    测试持续时间 (�? (默认: 30)");
  ```

- **L466**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  --no-ssl          禁用 HTTPS (使用明文 HTTP, 仅用于调�?");
  ```

- **L467**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  --list-scenarios  列出所有测试场�?);
  ```

- **L470**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("默认启用 HTTPS (TLS) �?服务器仅支持加密连接\n");
  ```

- **L479**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("可用的测试场�?");
  ```

- **L484**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("      请求�? {}",
  ```

- **L485**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  SCENARIOS[i].body ? SCENARIOS[i].body : "(�?");
  ```

- **L491**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 统计汇�?
  ```

- **L514**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("【测试配置�?);
  ```

- **L515**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  服务�?      {}:{}", g_config.host, g_config.port);
  ```

- **L522**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  计划时长:    {} �?, g_config.duration_sec);
  ```

- **L525**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 吞吐�?*/
  ```

- **L526**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("【吞吐量�?);
  ```

- **L530**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  成功�?      {:.2f}%",
  ```

- **L533**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  目标达成�?  {:.2f}%\n",
  ```

- **L537**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("【延迟�?);
  ```

- **L539**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  最小延�?    {:.2f} ms", static_cast<double>(min_lat) / 1000.0);
  ```

- **L540**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  最大延�?    {:.2f} ms", static_cast<double>(max_lat) / 1000.0);
  ```

- **L542**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 百分位延�?*/
  ```

- **L556**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 抗冲击评�?*/
  ```

- **L557**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("\n【抗冲击能力评估�?);
  ```

- **L560**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  等级: �?不合�?(错误�?{:.2f}% > 20%)", error_rate);
  ```

- **L563**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  等级: ⚠️ 一�?(错误�?{:.2f}% > 5%)", error_rate);
  ```

- **L564**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  建议: 适当增加服务器资源或进行代码级优�?);
  ```

- **L566**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  等级: �?良好 (错误�?{:.2f}%)", error_rate);
  ```

- **L569**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  等级: 🏆 优秀 (错误�?{:.2f}%)", error_rate);
  ```

- **L570**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  说明: 框架在高负载下表现稳�?);
  ```

- **L576**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  QPS 达成:    �?未达�?(仅达成目标的 {:.1f}%)",
  ```

- **L579**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  QPS 达成:    ⚠️ 部分达标 (达成目标�?{:.1f}%)",
  ```

- **L582**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  QPS 达成:    �?接近目标 (达成目标�?{:.1f}%)",
  ```

- **L585**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  QPS 达成:    🏆 超越目标 (达成目标�?{:.1f}%)",
  ```

- **L591**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 保存报告到文�?*/
  ```

- **L596**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 参数 | �?|\n");
  ```

- **L598**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 服务�?| %s:%d |\n",
  ```

- **L604**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 测试时长 | %.2f �?|\n", elapsed_sec);
  ```

- **L607**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 指标 | �?|\n");
  ```

- **L610**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 成功�?| %.2f%% |\n",
  ```

- **L618**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 错误�?| %.2f%% |\n", error_rate);
  ```

- **L619**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  std::fprintf(fp, "| 抗冲击等�?| %s |\n",
  ```

- **L620**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  error_rate > 20.0 ? "�?不合�? :
  ```

- **L621**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  error_rate > 5.0  ? "⚠️ 一�? :
  ```

- **L622**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  error_rate > 1.0  ? "�?良好" : "🏆 优秀");
  ```

- **L663**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  // 主函�?
  ```

- **L671**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "错误: WinSock 初始化失�?);
  ```

- **L676**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 解析命令行参�?*/
  ```

- **L716**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println(stderr, "错误: 无效的场景索�?{} (可用: 0-{})",
  ```

- **L727**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  服务�?  {}:{}", g_config.host, g_config.port);
  ```

- **L730**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  线程�?  {}", g_config.threads);
  ```

- **L732**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  cli::println("  时长:    {} �?, g_config.duration_sec);
  ```

- **L765**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 等待指定时间 (跨平�?chrono) */
  ```

- **L768**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* 停止所有线�?(jthread::request_stop() 隐式调用) */
  ```

- **L771**: 🔵 乱码: Unicode替换字符 U+FFFD
  ```
  /* workers �?progress_tid 析构时自�?join */
  ```


### 📄 `client\ui\js\app.js`

- **L30**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  function addMsg(type,text){ const d=document.createElement('div'); d.className='msg '+type; d.innerHTML=`<div class="meta">${new Date().toLocaleTimeSt
  ```

- **L32**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  function renderChatList(){ const c=$('#chat-list'); c.innerHTML=Object.keys(messages).map(u=>`<div class="friend-item" data-uid="${u}" onclick="openCh
  ```

- **L33**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  function renderFriends(){ $('#friend-list').innerHTML=friends.map(u=>`<div class="friend-item"><span>${u}</span></div>`).join('')||'<div class="empty"
  ```

- **L34**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  function renderPending(){ $('#pending-list').innerHTML=pending.map(r=>`<div class="pending-item"><span>${r.from_uid}</span><button onclick="API.cmd('f
  ```

- **L35**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  function openChat(uid){ activeChat=uid; $('#messages').innerHTML=''; (messages[uid]||[]).forEach(m=>{ addMsg(m.from===API.uid?'self':'other',m.text); 
  ```


### 📄 `data\ui\js\ai_chat.js`

- **L116**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  aiBtn.innerHTML = '🤖 AI';
  ```

- **L130**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  panel.innerHTML = `
  ```

- **L220**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  typingDiv.innerHTML = '<div class="ai-avatar">🤖</div><div class="ai-bubble"><span class="typing-dots">思考中...</span></div>';
  ```

- **L416**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  msgDiv.innerHTML = `
  ```

- **L441**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = `
  ```


### 📄 `data\ui\js\app.js`

- **L50**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  header.innerHTML = `
  ```

- **L62**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  messagesContainer.innerHTML = '<div class="no-chat-selected"><div class="no-chat-icon">👪</div><p>选择一个群组开始聊天</p></div>';
  ```

- **L125**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  header.innerHTML = '<span class="chat-partner">选择一个联系人开始聊天</span>';
  ```

- **L157**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L192**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  preview.innerHTML = `
  ```


### 📄 `data\ui\js\chat.js`

- **L20**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  header.innerHTML = `
  ```

- **L38**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  messagesContainer.innerHTML = '';
  ```

- **L118**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  messageDiv.innerHTML = `
  ```

- **L127**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  messageDiv.innerHTML = `
  ```


### 📄 `data\ui\js\community.js`

- **L25**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L28**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无社区模板</div>';
  ```

- **L36**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  card.innerHTML = `
  ```


### 📄 `data\ui\js\contacts.js`

- **L34**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L58**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L61**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无联系人</div>';
  ```

- **L83**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L122**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L125**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无联系人，点击右上角添加好友</div>';
  ```

- **L139**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  card.innerHTML = `
  ```

- **L163**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L169**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L195**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">未找到用户</div>';
  ```


### 📄 `data\ui\js\plugin_api.js`

- **L214**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = config.html;
  ```


### 📄 `data\ui\js\qq_emoji.js`

- **L63**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  panel.innerHTML = `
  ```

- **L101**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  grid.innerHTML = '';
  ```

- **L117**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--color-text-tertiary);padding:20px;font-size:var(--font-size-sm);">暂无表情</d
  ```

- **L203**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  emojiBtn.innerHTML = '😊';
  ```


### 📄 `data\ui\js\qq_file.js`

- **L133**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = QQFile.uploadQueue.map(item => `
  ```

- **L151**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L178**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L181**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无文件</div>';
  ```

- **L191**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L234**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  fileBtn.innerHTML = '📎';
  ```


### 📄 `data\ui\js\qq_friends.js`

- **L238**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L243**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  allItem.innerHTML = `
  ```

- **L258**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  recentItem.innerHTML = `
  ```

- **L274**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  pendingItem.innerHTML = `
  ```

- **L288**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L309**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  addGroupItem.innerHTML = '<span class="group-icon">➕</span><span class="group-name">添加分组</span>';
  ```

- **L317**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  blockItem.innerHTML = `
  ```

- **L334**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L339**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">该分组暂无联系人</div>';
  ```

- **L356**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L359**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无最近联系人</div>';
  ```

- **L383**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L422**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L440**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L460**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L463**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无待处理的请求</div>';
  ```

- **L470**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L492**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L495**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">黑名单为空</div>';
  ```

- **L502**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```

- **L533**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L557**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L588**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  menu.innerHTML = `
  ```

- **L621**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  menu.innerHTML = `
  ```

- **L667**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```


### 📄 `data\ui\js\qq_group.js`

- **L87**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  header.innerHTML = `
  ```

- **L121**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  if (offset === 0) container.innerHTML = '';
  ```

- **L144**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  messageDiv.innerHTML = `
  ```

- **L204**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L231**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L273**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '';
  ```

- **L276**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  container.innerHTML = '<div class="loading">暂无群组</div>';
  ```

- **L283**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  item.innerHTML = `
  ```


### 📄 `data\ui\js\qq_status.js`

- **L122**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```

- **L148**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  overlay.innerHTML = `
  ```


### 📄 `data\ui\js\utils.js`

- **L19**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  if (innerHTML) el.innerHTML = innerHTML;
  ```


### 📄 `data\ui\oauth_callback.html`

- **L68**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  document.querySelector('.container').innerHTML = '<p>授权成功，请返回应用继续操作</p>';
  ```

- **L70**: 🟡 注意: innerHTML赋值 - XSS注入风险，建议用textContent
  ```
  document.querySelector('.container').innerHTML = '<p>授权失败：缺少参数</p>';
  ```


### 📄 `scripts\full_code_audit.py`

- **L94**: 🔵 乱码: 疑似GBK/UTF-8混合编码乱码
  ```
  ('锟斤拷', '🔵 乱码: 疑似GBK/UTF-8混合编码乱码'),
  ```

- **L95**: 🔵 乱码: 疑似GBK/UTF-8混合编码乱码
  ```
  ('銆', '🔵 乱码: 疑似GBK/UTF-8混合编码乱码'),
  ```

- **L96**: 🔵 乱码: 疑似GBK/UTF-8混合编码乱码
  ```
  ('脗', '🔵 乱码: 疑似GBK/UTF-8混合编码乱码'),
  ```

- **L97**: 🔵 乱码: 疑似GBK/UTF-8混合编码乱码
  ```
  ('頎', '🔵 乱码: 疑似GBK/UTF-8混合编码乱码'),
  ```

---

## ℹ️ 信息/代码标记

✅ 无特别标记。

---

## 📋 审计总结

- 共扫描 **252** 个源文件
- 发现问题 **552** 个
  - 🔴 严重/高危: **7** 个
  - 🟡 中危: **30** 个
  - 🔵 低危/建议: **515** 个
  - ℹ️ 信息: **0** 个

### ⚡ 需要优先处理的高危项:
- `client\src\json_parser.c:78` → 🔴 高危: sprintf - 格式化字符串/缓冲区溢出，建议改用snprintf
- `client\src\i2p\I2pdEmbedded.cpp:230` → 🔴 高危: popen - 命令注入风险
- `scripts\full_code_audit.py:64` → 🔴 高危: eval() - 代码注入风险
- `scripts\full_code_audit.py:70` → 🔴 高危: eval() - 代码注入风险
- `scripts\full_code_audit.py:71` → 🔴 高危: exec() - 代码注入风险
- `tests\api_verification_test.sh:50` → 🔴 高危: shell eval + 变量 - 代码注入风险
- `tests\security_pen_test.sh:49` → 🔴 高危: shell eval + 变量 - 代码注入风险

> ⚠️ 本报告由自动化脚本生成，可能存在误报。请人工复核所有标记项。
> 🔧 审计脚本: `scripts/full_code_audit.py`
> 📅 生成于: 2026-05-31T05:09:37.726921