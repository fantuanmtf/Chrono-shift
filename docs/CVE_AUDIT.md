# Chrono-shift CVE 交叉审计报告

> 生成: 2026-05-21 01:16:03 | 扫描: 347,868 CVEs | 匹配: 13,880 | 依赖: 17

## 源码引用检测

递归扫描 `C:/Users/haiyan/Chrono-shift` 源码目录, 检测到以下依赖被代码实际引用:

| 依赖库 | 源码文件数 | CVE 匹配数 |
|---|---|---|
| Boost | 64 | 116 |
| GCC | 15 | 7 |
| Git | 24 | 2366 |
| MinGW | 23 | 66 |
| NASM | 16 | 16 |
| Node.js | 59 | 869 |
| OpenPGP | 3 | 18 |
| OpenSSL | 104 | 311 |
| Python | 11 | 226 |
| Rust | 76 | 281 |
| SQLite | 5 | 79 |
| Tor | 235 | 9098 |
| WebSocket | 46 | 48 |
| WinHTTP | 6 | 58 |
| i2pd | 167 | 55 |
| libcurl | 12 | 192 |
| zlib | 9 | 74 |

## 摘要

| 指标 | 数值 |
|---|---|
| CVE 总数 | 347,868 |
| 匹配漏洞 | 13,880 |
| CRITICAL | 802 |
| HIGH | 3388 |

## 依赖库详情

### Tor v0.4.9.6 | 源码引用: 235 处 | CVE: 9098

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2017-20230 | CRITICAL | 10.0 | CWE-121 | Storable versions before 3.05 for Perl has a stack overflow.

The retrieve_hook function s |
| CVE-2019-5617 | CRITICAL | 10.0 | CWE-284 | Computing For Good's Basic Laboratory Information System (also known as C4G BLIS) version  |
| CVE-2019-5644 | CRITICAL | 10.0 | CWE-284 | Computing For Good's Basic Laboratory Information System (also known as C4G BLIS) version  |
| CVE-2020-6207 | CRITICAL | 10.0 | - | SAP Solution Manager (User Experience Monitoring), version- 7.2, due to Missing Authentica |
| CVE-2021-1388 | CRITICAL | 10.0 | CWE-269 | A vulnerability in an API endpoint of Cisco ACI Multi-Site Orchestrator (MSO) installed on |
| CVE-2021-27460 | CRITICAL | 10.0 | CWE-502 | Rockwell Automation FactoryTalk AssetCentre v10.00 and earlier components contain .NET rem |
| CVE-2021-27462 | CRITICAL | 10.0 | CWE-502 | A deserialization vulnerability exists in how the AosService.rem service in Rockwell Autom |
| CVE-2021-27464 | CRITICAL | 10.0 | CWE-89 | The ArchiveService.rem service in Rockwell Automation FactoryTalk AssetCentre v10.00 and e |
| CVE-2021-27466 | CRITICAL | 10.0 | CWE-502 | A deserialization vulnerability exists in how the ArchiveService.rem service in Rockwell A |
| CVE-2021-27468 | CRITICAL | 10.0 | CWE-89 | The AosService.rem service in Rockwell Automation FactoryTalk AssetCentre v10.00 and earli |
| CVE-2021-27470 | CRITICAL | 10.0 | CWE-502 | A deserialization vulnerability exists in how the LogService.rem service in Rockwell Autom |
| CVE-2021-27472 | CRITICAL | 10.0 | CWE-89 | A vulnerability exists in the RunSearch function of SearchService service in Rockwell Auto |
| CVE-2021-27474 | CRITICAL | 10.0 | CWE-676 | Rockwell Automation FactoryTalk AssetCentre v10.00 and earlier does not properly restrict  |
| CVE-2021-27476 | CRITICAL | 10.0 | CWE-78 | A vulnerability exists in the SaveConfigFile function of the RACompare Service, which may  |
| CVE-2021-33841 | CRITICAL | 10.0 | CWE-78 | SGE-PLC1000 device, in its 0.9.2b firmware version, does not handle some requests correctl |

### Git vN/A | 源码引用: 24 处 | CVE: 2366

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2018-3972 | CRITICAL | 10.0 | - | An exploitable code execution vulnerability exists in the Levin deserialization functional |
| CVE-2021-22205 | CRITICAL | 10.0 | - | An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. Gi |
| CVE-2022-0735 | CRITICAL | 10.0 | - | An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.10 be |
| CVE-2022-22995 | CRITICAL | 10.0 | CWE-59 | The combination of primitives offered by SMB and AFP in their default configuration allows |
| CVE-2022-36331 | CRITICAL | 10.0 | CWE-290 | Western Digital My Cloud, My Cloud Home, My Cloud Home Duo, and SanDisk ibi devices were v |
| CVE-2023-22814 | CRITICAL | 10.0 | CWE-290 | An authentication bypass issue via spoofing was discovered in the token-based authenticati |
| CVE-2023-2138 | CRITICAL | 10.0 | CWE-798 | Use of Hard-coded Credentials in GitHub repository nuxtlabs/github-module prior to 1.6.2. |
| CVE-2023-2825 | CRITICAL | 10.0 | - | An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthentic |
| CVE-2023-6248 | CRITICAL | 10.0 | CWE-287,CWE-319 | The Syrus4 IoT gateway utilizes an unsecured MQTT server to download and execute arbitrary |
| CVE-2023-7028 | CRITICAL | 10.0 | CWE-640 | An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16. |
| CVE-2024-49242 | CRITICAL | 10.0 | CWE-434 | Unrestricted Upload of File with Dangerous Type vulnerability in Shafiq Digital Lottery di |
| CVE-2024-4985 | CRITICAL | 10.0 | CWE-303 | An authentication bypass vulnerability was present in the GitHub Enterprise Server (GHES)  |
| CVE-2024-54261 | CRITICAL | 10.0 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulne |
| CVE-2024-6886 | CRITICAL | 10.0 | CWE-79 | Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting' |
| CVE-2021-22192 | CRITICAL | 9.9 | - | An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.2 all |

### Node.js vN/A | 源码引用: 59 处 | CVE: 869

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2023-26045 | CRITICAL | 10.0 | CWE-22 | NodeBB is Node.js based forum software. Starting in version 2.5.0 and prior to version 2.8 |
| CVE-2024-21576 | CRITICAL | 10.0 | CWE-94 | ComfyUI-Bmad-Nodes is vulnerable to Code Injection. The issue stems from a validation bypa |
| CVE-2024-21577 | CRITICAL | 10.0 | CWE-94 | ComfyUI-Ace-Nodes is vulnerable to Code Injection. The ACE_ExpressionEval node contains an |
| CVE-2024-32962 | CRITICAL | 10.0 | CWE-347 | xml-crypto is an xml digital signature and encryption library for Node.js. In affected ver |
| CVE-2024-37143 | CRITICAL | 10.0 | CWE-59 | Dell PowerFlex appliance versions prior to IC 46.381.00 and IC 46.376.00, Dell PowerFlex r |
| CVE-2025-54419 | CRITICAL | 10.0 | CWE-287,CWE-347 | A SAML library not dependent on any frameworks that runs in Node. In version 5.0.1, Node-S |
| CVE-2020-15149 | CRITICAL | 9.9 | CWE-269 | NodeBB before version 1.14.3 has a bug introduced in version 1.12.2 in the validation logi |
| CVE-2026-22844 | CRITICAL | 9.9 | CWE-78 | A Command Injection vulnerability in Zoom Node Multimedia Routers (MMRs) before version 5. |
| CVE-2020-28445 | CRITICAL | 9.8 | - | This affects all versions of package npm-help. The injection point is located in line 13 i |
| CVE-2020-7720 | CRITICAL | 9.8 | - | The package node-forge before 0.10.0 is vulnerable to Prototype Pollution via the util.set |
| CVE-2020-7721 | CRITICAL | 9.8 | - | All versions of package node-oojs are vulnerable to Prototype Pollution via the setPath fu |
| CVE-2020-7722 | CRITICAL | 9.8 | - | All versions of package nodee-utils are vulnerable to Prototype Pollution via the deepSet  |
| CVE-2020-7785 | CRITICAL | 9.8 | - | This affects all versions of package node-ps. The injection point is located in line 72 in |
| CVE-2021-43786 | CRITICAL | 9.8 | CWE-287 | Nodebb is an open source Node.js based forum software. In affected versions incorrect logi |
| CVE-2022-23812 | CRITICAL | 9.8 | - | This affects the package node-ipc from 10.1.1 and before 10.1.3. This package contains mal |

### OpenSSL v3.6.2 | 源码引用: 104 处 | CVE: 311

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2023-52181 | CRITICAL | 10.0 | CWE-502 | Deserialization of Untrusted Data vulnerability in Presslabs Theme per user.This issue aff |
| CVE-2024-5991 | CRITICAL | 10.0 | CWE-125 | In function MatchDomainName(), input param str is treated as a NULL terminated string desp |
| CVE-2022-1292 | CRITICAL | 9.8 | - | The c_rehash script does not properly sanitise shell metacharacters to prevent command inj |
| CVE-2022-2068 | CRITICAL | 9.8 | - | In addition to the c_rehash shell command injection identified in CVE-2022-1292, further c |
| CVE-2024-10924 | CRITICAL | 9.8 | CWE-288 | The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulner |
| CVE-2024-1039 | CRITICAL | 9.8 | CWE-798 | Gessler GmbH WEB-MASTER has a restoration account that uses weak hard coded credentials an |
| CVE-2024-52440 | CRITICAL | 9.8 | CWE-502 | Deserialization of Untrusted Data vulnerability in xpresslane Xpresslane Fast Checkout xpr |
| CVE-2024-56220 | CRITICAL | 9.8 | CWE-266 | Incorrect Privilege Assignment vulnerability in sslplugins SSL Wireless SMS Notification s |
| CVE-2026-32890 | CRITICAL | 9.7 | CWE-79,CWE-200 | Anchorr is a Discord bot for requesting movies and TV shows and receiving notifications wh |
| CVE-2025-11625 | CRITICAL | 9.4 | CWE-287 | Improper host authentication vulnerability in wolfSSH version 1.4.20 and earlier clients t |
| CVE-2025-14942 | CRITICAL | 9.4 | CWE-287 | wolfSSH’s key exchange state machine can be manipulated to leak the client’s password in t |
| CVE-2024-56284 | CRITICAL | 9.3 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulne |
| CVE-2025-15346 | CRITICAL | 9.3 | CWE-306,CWE-287 | A vulnerability in the handling of verify_mode = CERT_REQUIRED in the wolfssl Python packa |
| CVE-2025-52936 | CRITICAL | 9.3 | CWE-59 | Improper Link Resolution Before File Access ('Link Following') vulnerability in yrutschle  |
| CVE-2026-5194 | CRITICAL | 9.3 | CWE-295 | Missing hash/digest size and OID checks allow digests smaller than allowed when verifying  |

### Rust v1.95.0 | 源码引用: 76 处 | CVE: 281

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2024-24576 | CRITICAL | 10.0 | CWE-78,CWE-88 | Rust is a programming language. The Rust Security Response WG was notified that the Rust s |
| CVE-2026-1731 | CRITICAL | 9.9 | CWE-78 | BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PR |
| CVE-2020-36726 | CRITICAL | 9.8 | CWE-502 | The Ultimate Reviews plugin for WordPress is vulnerable to PHP Object Injection in version |
| CVE-2024-10871 | CRITICAL | 9.8 | CWE-98 | The Category Ajax Filter plugin for WordPress is vulnerable to Local File Inclusion in all |
| CVE-2024-12356 | CRITICAL | 9.8 | CWE-77 | A critical vulnerability has been discovered in Privileged Remote Access (PRA) and Remote  |
| CVE-2024-3495 | CRITICAL | 9.8 | CWE-89 | The Country State City Dropdown CF7 plugin for WordPress is vulnerable to SQL Injection vi |
| CVE-2025-2005 | CRITICAL | 9.8 | CWE-434 | The Front End Users plugin for WordPress is vulnerable to arbitrary file uploads due to mi |
| CVE-2025-3603 | CRITICAL | 9.8 | CWE-620 | The Flynax Bridge plugin for WordPress is vulnerable to privilege escalation via account t |
| CVE-2025-3604 | CRITICAL | 9.8 | CWE-862 | The Flynax Bridge plugin for WordPress is vulnerable to privilege escalation via account t |
| CVE-2025-68926 | CRITICAL | 9.8 | CWE-798,CWE-287 | RustFS is a distributed object storage system built in Rust. In versions prior to 1.0.0-al |
| CVE-2024-37051 | CRITICAL | 9.3 | CWE-522 | GitHub access token could be exposed to third-party sites in JetBrains IDEs after version  |
| CVE-2024-44004 | CRITICAL | 9.3 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulne |
| CVE-2025-28942 | CRITICAL | 9.3 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulne |
| CVE-2025-34414 | CRITICAL | 9.3 | CWE-502,CWE-306 | Entrust Instant Financial Issuance (IFI) On Premise software (formerly referred to as Card |
| CVE-2026-23746 | CRITICAL | 9.3 | CWE-306,CWE-502 | Entrust Instant Financial Issuance (IFI) On Premise software (formerly referred to as Card |

### Python v3.x | 源码引用: 11 处 | CVE: 226

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2024-21669 | CRITICAL | 9.9 | CWE-347 | Hyperledger Aries Cloud Agent Python (ACA-Py) is a foundation for building decentralized i |
| CVE-2019-10160 | CRITICAL | 9.8 | CWE-172 | A security regression of CVE-2019-9636 was discovered in python since commit d537ab0ff9767 |
| CVE-2024-34359 | CRITICAL | 9.7 | CWE-76 | llama-cpp-python is the Python bindings for llama.cpp. `llama-cpp-python` depends on class |
| CVE-2025-3115 | CRITICAL | 9.4 | - | Injection Vulnerabilities: Attackers can inject malicious code, potentially gaining contro |
| CVE-2025-4517 | CRITICAL | 9.4 | CWE-22 | Allows arbitrary filesystem writes outside the extraction directory during extraction with |
| CVE-2026-35022 | CRITICAL | 9.3 | CWE-78 | Anthropic Claude Code CLI and Claude Agent SDK contain an OS command injection vulnerabili |
| CVE-2022-39227 | CRITICAL | 9.1 | CWE-290 | python-jwt is a module for generating and verifying JSON Web Tokens. Versions prior to 3.3 |
| CVE-2025-43859 | CRITICAL | 9.1 | CWE-444 | h11 is a Python implementation of HTTP/1.1. Prior to version 0.16.0, a leniency in h11's p |
| CVE-2026-6100 | CRITICAL | 9.1 | CWE-416,CWE-787 | Use-after-free (UAF) was possible in the `lzma.LZMADecompressor`, `bz2.BZ2Decompressor`, a |
| CVE-2023-36415 | HIGH | 8.8 | CWE-77 |  |
| CVE-2024-49050 | HIGH | 8.8 | CWE-501 |  |
| CVE-2025-27607 | HIGH | 8.8 | CWE-829 | Python JSON Logger is a JSON Formatter for Python Logging. Between 30 December 2024 and 4  |
| CVE-2026-3298 | HIGH | 8.8 | CWE-787 | The method "sock_recvfrom_into()" of "asyncio.ProacterEventLoop" (Windows only) was missin |
| CVE-2024-12254 | HIGH | 8.7 | CWE-400,CWE-770 | Starting in Python 3.12.0, the asyncio._SelectorSocketTransport.writelines()
 method would |
| CVE-2024-47532 | HIGH | 8.7 | CWE-200 | RestrictedPython is a restricted execution environment for Python to run untrusted code. A |

### libcurl v8.9.0 | 源码引用: 12 处 | CVE: 192

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2017-8816 | CRITICAL | 9.8 | - | The NTLM authentication feature in curl and libcurl before 7.57.0 on 32-bit platforms allo |
| CVE-2017-8817 | CRITICAL | 9.8 | - | The FTP wildcard function in curl and libcurl before 7.57.0 allows remote attackers to cau |
| CVE-2019-5481 | CRITICAL | 9.8 | CWE-415 | Double-free vulnerability in the FTP-kerberos code in cURL 7.52.0 to 7.65.3. |
| CVE-2019-5482 | CRITICAL | 9.8 | CWE-122 | Heap buffer overflow in the TFTP protocol handler in cURL 7.19.4 to 7.65.3. |
| CVE-2022-32207 | CRITICAL | 9.8 | CWE-840 | When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the opera |
| CVE-2022-32221 | CRITICAL | 9.8 | CWE-200 | When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_RE |
| CVE-2023-27533 | CRITICAL | 9.8 | CWE-75 | A vulnerability in input validation exists in curl <8.0 during communication using the TEL |
| CVE-2021-22945 | CRITICAL | 9.1 | CWE-415 | When sending data to an MQTT server, libcurl <= 7.73.0 and 7.78.0 could in some circumstan |
| CVE-2023-23914 | CRITICAL | 9.1 | CWE-319 | A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 th |
| CVE-2023-27534 | HIGH | 8.8 | CWE-22 | A path traversal vulnerability exists in curl <8.0.0 SFTP implementation causes the tilde  |
| CVE-2023-38545 | HIGH | 8.8 | - | This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy
handshake.

When cur |
| CVE-2024-27322 | HIGH | 8.8 | CWE-502 | Deserialization of untrusted data can occur in the R statistical programming language, on  |
| CVE-2025-36004 | HIGH | 8.8 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user to gain elevated privileges due to an unqu |
| CVE-2025-36367 | HIGH | 8.8 | CWE-862 | IBM i 7.6, 7.5, 7.4, 7.3, and 7.2 is vulnerable to privilege escalation caused by an inval |
| CVE-2019-25695 | HIGH | 8.6 | CWE-787 | R 3.4.4 contains a local buffer overflow vulnerability that allows attackers to execute ar |

### Boost v1.87.0 | 源码引用: 64 处 | CVE: 116

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2019-25217 | CRITICAL | 9.8 | CWE-862 | The SiteGround Optimizer plugin for WordPress is vulnerable to authorization bypass leadin |
| CVE-2021-34646 | CRITICAL | 9.8 | CWE-290 | Versions up to, and including, 5.4.3, of the Booster for WooCommerce WordPress plugin are  |
| CVE-2022-1300 | CRITICAL | 9.8 | CWE-306 | Multiple Version of TRUMPF TruTops products expose a service function without necessary au |
| CVE-2022-2052 | CRITICAL | 9.8 | CWE-284 | Multiple Trumpf Products in multiple versions use default privileged Windows users and pas |
| CVE-2024-49332 | CRITICAL | 9.8 | CWE-502 | Deserialization of Untrusted Data vulnerability in giveawayboost Giveaway Boost giveaway-b |
| CVE-2025-13377 | CRITICAL | 9.6 | CWE-22 | The 10Web Booster – Website speed optimization, Cache & Page Speed optimizer plugin for Wo |
| CVE-2025-34082 | CRITICAL | 9.3 | CWE-78 | A command injection vulnerability exists in IGEL OS versions prior to 11.04.270 within the |
| CVE-2024-6584 | CRITICAL | 9.1 | - | The 'wp_ajax_boost_proxy_ig' action allows administrators to make GET requests to arbitrar |
| CVE-2018-25300 | HIGH | 8.8 | CWE-89 | XATABoost CMS 1.0.0 contains a union-based SQL injection vulnerability that allows unauthe |
| CVE-2022-4017 | HIGH | 8.8 | - | The Booster for WooCommerce WordPress plugin before 6.0.1, Booster Plus for WooCommerce Wo |
| CVE-2024-1986 | HIGH | 8.8 | CWE-434 | The Booster Elite for WooCommerce plugin for WordPress is vulnerable to arbitrary file upl |
| CVE-2024-7325 | HIGH | 8.5 | CWE-427 | A vulnerability was found in IObit Driver Booster 11.0.0.0. It has been rated as critical. |
| CVE-2022-3763 | HIGH | 8.1 | - | The Booster for WooCommerce WordPress plugin before 5.6.7, Booster Plus for WooCommerce Wo |
| CVE-2024-13342 | HIGH | 8.1 | CWE-434 | The Booster for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads d |
| CVE-2024-13744 | HIGH | 8.1 | CWE-434 | The Booster for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads d |

### SQLite v3.x | 源码引用: 5 处 | CVE: 79

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2023-32697 | HIGH | 8.8 | CWE-94 | SQLite JDBC is a library for accessing and creating SQLite database files in Java. Sqlite- |
| CVE-2025-36004 | HIGH | 8.8 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user to gain elevated privileges due to an unqu |
| CVE-2025-36367 | HIGH | 8.8 | CWE-862 | IBM i 7.6, 7.5, 7.4, 7.3, and 7.2 is vulnerable to privilege escalation caused by an inval |
| CVE-2023-30990 | HIGH | 8.6 | CWE-94 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a remote attacker to execute CL commands as QUSER |
| CVE-2024-55898 | HIGH | 8.5 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user with the capability to compile or restore  |
| CVE-2025-33103 | HIGH | 8.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 product IBM TCP/IP Connectivity Utilities for i contains |
| CVE-2023-30988 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-30989 | HIGH | 8.4 | CWE-269 | IBM Performance Tools for i 7.2, 7.3, 7.4, and 7.5 contains a local privilege escalation v |
| CVE-2023-38721 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-42006 | HIGH | 8.4 | - | IBM Administration Runtime Expert for i 7.2, 7.3, 7.4, and 7.5 could allow a local user to |
| CVE-2024-22346 | HIGH | 8.4 | CWE-427 | Db2 for IBM i 7.2, 7.3, 7.4, and 7.5 infrastructure could allow a local user to gain eleva |
| CVE-2024-25050 | HIGH | 8.4 | CWE-427 | IBM i 7.2, 7.3, 7.4, 7.5 and IBM Rational Development Studio for i 7.2, 7.3, 7.4, 7.5 netw |
| CVE-2019-5018 | HIGH | 8.1 | CWE-416 | An exploitable use after free vulnerability exists in the window function functionality of |
| CVE-2022-43441 | HIGH | 8.1 | CWE-915 | A code execution vulnerability exists in the Statement Bindings functionality of Ghost Fou |
| CVE-2024-31890 | HIGH | 7.8 | CWE-250 | IBM i 7.3, 7.4, and 7.5 product IBM TCP/IP Connectivity Utilities for i contains a local p |

### zlib v1.3.2 | 源码引用: 9 处 | CVE: 74

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2026-3381 | CRITICAL | 9.8 | CWE-1395 | Compress::Raw::Zlib versions through 2.219 for Perl use potentially insecure versions of z |
| CVE-2025-36004 | HIGH | 8.8 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user to gain elevated privileges due to an unqu |
| CVE-2025-36367 | HIGH | 8.8 | CWE-862 | IBM i 7.6, 7.5, 7.4, 7.3, and 7.2 is vulnerable to privilege escalation caused by an inval |
| CVE-2023-30990 | HIGH | 8.6 | CWE-94 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a remote attacker to execute CL commands as QUSER |
| CVE-2024-55898 | HIGH | 8.5 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user with the capability to compile or restore  |
| CVE-2025-33103 | HIGH | 8.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 product IBM TCP/IP Connectivity Utilities for i contains |
| CVE-2023-30988 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-30989 | HIGH | 8.4 | CWE-269 | IBM Performance Tools for i 7.2, 7.3, 7.4, and 7.5 contains a local privilege escalation v |
| CVE-2023-38721 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-42006 | HIGH | 8.4 | - | IBM Administration Runtime Expert for i 7.2, 7.3, 7.4, and 7.5 could allow a local user to |
| CVE-2024-22346 | HIGH | 8.4 | CWE-427 | Db2 for IBM i 7.2, 7.3, 7.4, and 7.5 infrastructure could allow a local user to gain eleva |
| CVE-2024-25050 | HIGH | 8.4 | CWE-427 | IBM i 7.2, 7.3, 7.4, 7.5 and IBM Rational Development Studio for i 7.2, 7.3, 7.4, 7.5 netw |
| CVE-2017-7435 | HIGH | 8.1 | - | In libzypp before 20170803 it was possible to add unsigned YUM repositories without warnin |
| CVE-2017-7436 | HIGH | 8.1 | - | In libzypp before 20170803 it was possible to retrieve unsigned packages without a warning |
| CVE-2018-7685 | HIGH | 7.8 | CWE-358 | The decoupled download and installation steps in libzypp before 17.5.0 could lead to a cor |

### MinGW v15.2.0 | 源码引用: 23 处 | CVE: 66

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2023-27350 | CRITICAL | 9.8 | CWE-284 | This vulnerability allows remote attackers to bypass authentication on affected installati |
| CVE-2018-25316 | CRITICAL | 9.3 | CWE-290 | Tenda W308R v2 V5.07.48 contains a cookie session weakness vulnerability that allows unaut |
| CVE-2025-36004 | HIGH | 8.8 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user to gain elevated privileges due to an unqu |
| CVE-2025-36367 | HIGH | 8.8 | CWE-862 | IBM i 7.6, 7.5, 7.4, 7.3, and 7.2 is vulnerable to privilege escalation caused by an inval |
| CVE-2023-30990 | HIGH | 8.6 | CWE-94 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a remote attacker to execute CL commands as QUSER |
| CVE-2024-55898 | HIGH | 8.5 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user with the capability to compile or restore  |
| CVE-2025-33103 | HIGH | 8.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 product IBM TCP/IP Connectivity Utilities for i contains |
| CVE-2023-30988 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-30989 | HIGH | 8.4 | CWE-269 | IBM Performance Tools for i 7.2, 7.3, 7.4, and 7.5 contains a local privilege escalation v |
| CVE-2023-38721 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-42006 | HIGH | 8.4 | - | IBM Administration Runtime Expert for i 7.2, 7.3, 7.4, and 7.5 could allow a local user to |
| CVE-2024-22346 | HIGH | 8.4 | CWE-427 | Db2 for IBM i 7.2, 7.3, 7.4, and 7.5 infrastructure could allow a local user to gain eleva |
| CVE-2024-25050 | HIGH | 8.4 | CWE-427 | IBM i 7.2, 7.3, 7.4, 7.5 and IBM Rational Development Studio for i 7.2, 7.3, 7.4, 7.5 netw |
| CVE-2023-27351 | HIGH | 8.2 | CWE-287 | This vulnerability allows remote attackers to bypass authentication on affected installati |
| CVE-2024-31890 | HIGH | 7.8 | CWE-250 | IBM i 7.3, 7.4, and 7.5 product IBM TCP/IP Connectivity Utilities for i contains a local p |

### WinHTTP vN/A | 源码引用: 6 处 | CVE: 58

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2018-25316 | CRITICAL | 9.3 | CWE-290 | Tenda W308R v2 V5.07.48 contains a cookie session weakness vulnerability that allows unaut |
| CVE-2025-36004 | HIGH | 8.8 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user to gain elevated privileges due to an unqu |
| CVE-2025-36367 | HIGH | 8.8 | CWE-862 | IBM i 7.6, 7.5, 7.4, 7.3, and 7.2 is vulnerable to privilege escalation caused by an inval |
| CVE-2023-30990 | HIGH | 8.6 | CWE-94 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a remote attacker to execute CL commands as QUSER |
| CVE-2024-55898 | HIGH | 8.5 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user with the capability to compile or restore  |
| CVE-2025-33103 | HIGH | 8.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 product IBM TCP/IP Connectivity Utilities for i contains |
| CVE-2023-30988 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-30989 | HIGH | 8.4 | CWE-269 | IBM Performance Tools for i 7.2, 7.3, 7.4, and 7.5 contains a local privilege escalation v |
| CVE-2023-38721 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-42006 | HIGH | 8.4 | - | IBM Administration Runtime Expert for i 7.2, 7.3, 7.4, and 7.5 could allow a local user to |
| CVE-2024-22346 | HIGH | 8.4 | CWE-427 | Db2 for IBM i 7.2, 7.3, 7.4, and 7.5 infrastructure could allow a local user to gain eleva |
| CVE-2024-25050 | HIGH | 8.4 | CWE-427 | IBM i 7.2, 7.3, 7.4, 7.5 and IBM Rational Development Studio for i 7.2, 7.3, 7.4, 7.5 netw |
| CVE-2024-31890 | HIGH | 7.8 | CWE-250 | IBM i 7.3, 7.4, and 7.5 product IBM TCP/IP Connectivity Utilities for i contains a local p |
| CVE-2024-31879 | HIGH | 7.5 | CWE-502 | IBM i 7.2, 7.3, and 7.4 could allow a remote attacker to execute arbitrary code leading to |
| CVE-2025-33109 | HIGH | 7.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 is vulnerable to a privilege escalation caused by an inv |

### i2pd v2.56.0 | 源码引用: 167 处 | CVE: 55

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2025-36004 | HIGH | 8.8 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user to gain elevated privileges due to an unqu |
| CVE-2025-36367 | HIGH | 8.8 | CWE-862 | IBM i 7.6, 7.5, 7.4, 7.3, and 7.2 is vulnerable to privilege escalation caused by an inval |
| CVE-2023-30990 | HIGH | 8.6 | CWE-94 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a remote attacker to execute CL commands as QUSER |
| CVE-2024-55898 | HIGH | 8.5 | CWE-427 | IBM i 7.2, 7.3, 7.4, and 7.5 could allow a user with the capability to compile or restore  |
| CVE-2025-33103 | HIGH | 8.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 product IBM TCP/IP Connectivity Utilities for i contains |
| CVE-2023-30988 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-30989 | HIGH | 8.4 | CWE-269 | IBM Performance Tools for i 7.2, 7.3, 7.4, and 7.5 contains a local privilege escalation v |
| CVE-2023-38721 | HIGH | 8.4 | CWE-269 | The IBM i 7.2, 7.3, 7.4, and 7.5 product Facsimile Support for i contains a local privileg |
| CVE-2023-42006 | HIGH | 8.4 | - | IBM Administration Runtime Expert for i 7.2, 7.3, 7.4, and 7.5 could allow a local user to |
| CVE-2024-22346 | HIGH | 8.4 | CWE-427 | Db2 for IBM i 7.2, 7.3, 7.4, and 7.5 infrastructure could allow a local user to gain eleva |
| CVE-2024-25050 | HIGH | 8.4 | CWE-427 | IBM i 7.2, 7.3, 7.4, 7.5 and IBM Rational Development Studio for i 7.2, 7.3, 7.4, 7.5 netw |
| CVE-2024-31890 | HIGH | 7.8 | CWE-250 | IBM i 7.3, 7.4, and 7.5 product IBM TCP/IP Connectivity Utilities for i contains a local p |
| CVE-2024-31879 | HIGH | 7.5 | CWE-502 | IBM i 7.2, 7.3, and 7.4 could allow a remote attacker to execute arbitrary code leading to |
| CVE-2025-33109 | HIGH | 7.5 | CWE-250 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 is vulnerable to a privilege escalation caused by an inv |
| CVE-2025-33122 | HIGH | 7.5 | CWE-427 | IBM i 7.2, 7.3, 7.4, 7.5, and 7.6 could allow a user to gain elevated privileges due to an |

### WebSocket vN/A | 源码引用: 46 处 | CVE: 48

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2025-1866 | CRITICAL | 10.0 | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in w |
| CVE-2018-25316 | CRITICAL | 9.3 | CWE-290 | Tenda W308R v2 V5.07.48 contains a cookie session weakness vulnerability that allows unaut |
| CVE-2020-11050 | CRITICAL | 9.0 | CWE-297 | In Java-WebSocket less than or equal to 1.4.1, there is an Improper Validation of Certific |
| CVE-2025-34087 | CRITICAL | 9.0 | CWE-78 | An authenticated command injection vulnerability exists in Pi-hole versions up to 3.3. Whe |
| CVE-2026-33765 | HIGH | 8.9 | CWE-78 | Pi-hole Admin Interface is a web interface for managing Pi-hole, a network-level ad and in |
| CVE-2025-55061 | HIGH | 8.8 | CWE-434 | CWE-434 Unrestricted Upload of File with Dangerous Type |
| CVE-2025-6791 | HIGH | 8.8 | CWE-89 | In the monitoring event logs page, it is possible to alter the http request to insert a re |
| CVE-2025-4647 | HIGH | 8.4 | CWE-79 | Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting' |
| CVE-2025-4648 | HIGH | 8.4 | CWE-434 | The content of a SVG file, received as input 

in Centreon web, was not properly checked.  |
| CVE-2025-14213 | HIGH | 8.3 | CWE-78,CWE-20 | Cato Networks’ Socket versions prior to 25 contain a command injection vulnerability that  |
| CVE-2025-59151 | HIGH | 8.2 | CWE-93,CWE-113 | Pi-hole Admin Interface is a web interface for managing Pi-hole, a network-level advertise |
| CVE-2020-15133 | HIGH | 8.0 | CWE-295 | In faye-websocket before version 0.11.0, there is a lack of certification validation in TL |
| CVE-2022-35922 | HIGH | 7.5 | CWE-400 | Rust-WebSocket is a WebSocket (RFC6455) library written in Rust. In versions prior to 0.26 |
| CVE-2022-39386 | HIGH | 7.5 | CWE-248 | @fastify/websocket provides WebSocket support for Fastify. Any application using @fastify/ |
| CVE-2023-37544 | HIGH | 7.5 | CWE-287 | Improper Authentication vulnerability in Apache Pulsar WebSocket Proxy allows an attacker  |

### OpenPGP vN/A | 源码引用: 3 处 | CVE: 18

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2025-47934 | HIGH | 8.7 | CWE-347 | OpenPGP.js is a JavaScript implementation of the OpenPGP protocol. Startinf in version 5.0 |
| CVE-2021-47761 | HIGH | 8.5 | CWE-276 | MilleGPG5 5.7.2 contains a local privilege escalation vulnerability that allows authentica |
| CVE-2021-47774 | HIGH | 8.4 | CWE-787 | Kingdia CD Extractor 3.0.2 contains a buffer overflow vulnerability in the registration na |
| CVE-2026-24882 | HIGH | 8.4 | CWE-121 | In GnuPG before 2.5.17, a stack-based buffer overflow exists in tpm2daemon during handling |
| CVE-2026-24881 | HIGH | 8.1 | CWE-121 | In GnuPG before 2.5.17, a crafted CMS (S/MIME) EnvelopedData message carrying an oversized |
| CVE-2025-68973 | HIGH | 7.8 | CWE-675 | In GnuPG before 2.4.9, armor_filter in g10/armor.c has two increments of an index variable |
| CVE-2026-41989 | MEDIUM | 6.7 | CWE-787 | Libgcrypt before 1.12.2 sometimes allows a heap-based buffer overflow and denial of servic |
| CVE-2017-7526 | MEDIUM | 6.1 | CWE-200 | libgcrypt before version 1.7.8 is vulnerable to a cache side-channel attack resulting into |
| CVE-2025-68972 | MEDIUM | 5.9 | CWE-347 | In GnuPG through 2.4.8, if a signed message has \f at the end of a plaintext line, an adve |
| CVE-2019-14855 | MEDIUM | 5.3 | CWE-326 | A flaw was found in the way certificate signatures could be forged using collisions found  |
| CVE-2024-3919 | MEDIUM | 4.6 | - | The OpenPGP Form Encryption for WordPress plugin before 1.5.1 does not validate and escape |
| CVE-2023-41037 | MEDIUM | 4.3 | CWE-347 | OpenPGP.js is a JavaScript implementation of the OpenPGP protocol. In affected versions Op |
| CVE-2026-41990 | MEDIUM | 4.0 | CWE-787 | Libgcrypt before 1.12.2 mishandles Dilithium signing. Writes to a static array lack a boun |
| CVE-2026-24883 | LOW | 3.7 | CWE-476 | In GnuPG before 2.5.17, a long signature packet length causes parse_signature to return su |
| CVE-2022-3219 | LOW | 3.3 | - | GnuPG can be made to spin on a relatively small input by (for example) crafting a public k |

### NASM v2.16 | 源码引用: 16 处 | CVE: 16

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2024-22267 | CRITICAL | 9.3 | - | VMware Workstation and Fusion contain a use-after-free vulnerability in the vbluetooth dev |
| CVE-2022-23005 | HIGH | 8.7 | CWE-1224,CWE-1233 | Western Digital has identified a weakness in the UFS standard that could result in a secur |
| CVE-2026-6067 | HIGH | 7.5 | - | A heap buffer overflow vulnerability exists in the Netwide Assembler (NASM) due to a lack  |
| CVE-2026-6069 | HIGH | 7.5 | - | NASM’s disasm() function contains a stack based buffer overflow when formatting disassembl |
| CVE-2025-31441 | HIGH | 7.1 | CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulne |
| CVE-2026-6068 | MEDIUM | 6.5 | - | NASM contains a heap use after free vulnerability in response file (-@) processing where a |
| CVE-2024-10320 | MEDIUM | 6.4 | CWE-79 | The Cookielay plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the pl |
| CVE-2024-8622 | MEDIUM | 6.1 | CWE-79 | The amCharts: Charts and Maps plugin for WordPress is vulnerable to Reflected Cross-Site S |
| CVE-2025-8842 | MEDIUM | 4.8 | CWE-416,CWE-119 | A vulnerability has been found in NASM Netwide Assember 2.17rc0. Affected by this issue is |
| CVE-2025-8843 | MEDIUM | 4.8 | CWE-122,CWE-119 | A vulnerability was found in NASM Netwide Assember 2.17rc0. This affects the function mach |
| CVE-2025-8844 | MEDIUM | 4.8 | CWE-476,CWE-404 | A vulnerability was determined in NASM Netwide Assember 2.17rc0. This vulnerability affect |
| CVE-2025-8845 | MEDIUM | 4.8 | CWE-121,CWE-119 | A vulnerability was identified in NASM Netwide Assember 2.17rc0. This issue affects the fu |
| CVE-2025-8846 | MEDIUM | 4.8 | CWE-121,CWE-119 | A vulnerability has been found in NASM Netwide Assember 2.17rc0. Affected is the function  |
| CVE-2021-4251 | LOW | 3.5 | CWE-707 | A vulnerability classified as problematic was found in as. This vulnerability affects the  |
| CVE-2012-2148 | NONE | 0.0 | - | An issue exists in the property replacements feature in any descriptor in JBoxx AS 7.1.1 i |

### GCC v15.2.0 | 源码引用: 15 处 | CVE: 7

| CVE ID | 严重度 | CVSS | CWE | 描述 |
|---|---|---|---|---|
| CVE-2025-53814 | HIGH | 7.8 | CWE-416 | A use-after-free vulnerability exists in the XML parser functionality of GCC Productions I |
| CVE-2025-53855 | HIGH | 7.8 | CWE-787 | An out-of-bounds write vulnerability exists in the XML parser functionality of GCC Product |
| CVE-2026-7065 | MEDIUM | 6.9 | CWE-918 | A vulnerability has been found in BidingCC BuildingAI up to 26.0.1. Impacted is the functi |
| CVE-2025-47442 | MEDIUM | 6.5 | CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulne |
| CVE-2023-4039 | MEDIUM | 4.8 | CWE-693 | **DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains 
that targe |
| CVE-2002-2439 | NONE | 0.0 | - | Integer overflow in the new[] operator in gcc before 4.8.0 allows attackers to have unspec |
| CVE-2021-3826 | NONE | 0.0 | CWE-119 | Heap/stack buffer overflow in the dlang_lname function in d-demangle.c in libiberty allows |

## CWE 分类

| CWE | 描述 | 数量 |
|---|---|---|
| CWE-79 | XSS | 2486 |
| CWE-89 | SQL注入 | 763 |
| CWE-862 | 权限缺失 | 745 |
| CWE-352 | CSRF | 480 |
| CWE-22 | 路径遍历 | 440 |
| CWE-74 | 注入 | 338 |
| CWE-125 | 越界读 | 286 |
| CWE-20 | 输入验证 | 217 |
| CWE-787 | 越界写 | 195 |
| CWE-78 | 命令注入 | 151 |
| CWE-502 | 反序列化 | 145 |
| CWE-416 | 释放后使用 | 108 |
| CWE-122 | 堆溢出 | 86 |
| CWE-295 | 证书 | 76 |
| CWE-532 | 敏感泄露 | 51 |
| CWE-476 | 空指针 | 44 |
| CWE-190 | 整数溢出 | 33 |
| CWE-327 | 弱加密 | 16 |
| CWE-345 | 认证缺失 | 14 |
| CWE-674 | 无界递归 | 9 |
| CWE-338 | 弱随机 | 8 |

## 年份分布

| 2009 | 1 |  |
| 2014 | 1 |  |
| 2015 | 2 |  |
| 2016 | 8 |  |
| 2017 | 333 | █████████████████████████████████ |
| 2018 | 896 | ██████████████████████████████████████████████████ |
| 2019 | 455 | █████████████████████████████████████████████ |
| 2020 | 648 | ██████████████████████████████████████████████████ |
| 2021 | 883 | ██████████████████████████████████████████████████ |
| 2022 | 1139 | ██████████████████████████████████████████████████ |
| 2023 | 1882 | ██████████████████████████████████████████████████ |
| 2024 | 3113 | ██████████████████████████████████████████████████ |
| 2025 | 3090 | ██████████████████████████████████████████████████ |
| 2026 | 1429 | ██████████████████████████████████████████████████ |

---
*由 scripts/cve_audit.py 生成 | 全量扫描 1999-2026*
