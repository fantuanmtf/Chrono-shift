#include "CrossPlatformHttp.h"
#include <cstring>
#include <cstdio>
#include <vector>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HTTPS_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#endif

namespace chrono {
namespace client {
namespace network {

bool CrossPlatformHttp::parse_url(const std::string& url, std::string& host,
                                  std::string& path, uint16_t& port, bool& is_secure) {
    is_secure = url.find("https://") == 0;
    std::string rest = is_secure ? url.substr(8) : url;
    if (!is_secure && url.find("http://") == 0) {
        rest = url.substr(7);
    }

    auto slash_pos = rest.find('/');
    auto colon_pos = rest.find(':');

    if (colon_pos != std::string::npos && (colon_pos < slash_pos || slash_pos == std::string::npos)) {
        host = rest.substr(0, colon_pos);
        auto port_str = slash_pos != std::string::npos
                      ? rest.substr(colon_pos + 1, slash_pos - colon_pos - 1)
                      : rest.substr(colon_pos + 1);
        port = static_cast<uint16_t>(std::stoi(port_str));
    } else {
        host = slash_pos != std::string::npos ? rest.substr(0, slash_pos) : rest;
        port = is_secure ? 443 : 80;
    }

    path = slash_pos != std::string::npos ? rest.substr(slash_pos) : "/";
    return true;
}

#ifdef _WIN32

CrossPlatformHttp::Response CrossPlatformHttp::post(const std::string& url, const std::string& body,
                                                   const std::unordered_map<std::string, std::string>& headers) {
    Response resp;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

    std::string host, path;
    uint16_t port;
    bool is_secure;
    parse_url(url, host, path, port, is_secure);

    hSession = WinHttpOpen(L"Chrono-shift/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          nullptr, nullptr, 0);
    if (!hSession) return resp;

    std::wstring whost(host.begin(), host.end());
    hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return resp;
    }

    std::wstring wpath(path.begin(), path.end());
    hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
                                  nullptr, nullptr, nullptr,
                                  is_secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    for (const auto& [key, value] : headers) {
        std::wstring wheader(key.begin(), key.end());
        wheader += L": ";
        wheader += std::wstring(value.begin(), value.end());
        WinHttpAddRequestHeaders(hRequest, wheader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    if (!WinHttpSendRequest(hRequest, nullptr, 0,
                            const_cast<char*>(body.data()),
                            static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    DWORD bytes_available = 0;
    std::vector<char> buffer;
    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
        buffer.resize(buffer.size() + bytes_available + 1);
        DWORD bytes_read = 0;
        WinHttpReadData(hRequest, buffer.data() + buffer.size() - bytes_available - 1,
                        bytes_available, &bytes_read);
        buffer[buffer.size() - bytes_available - 1 + bytes_read] = '\0';
    }

    resp.body = buffer.data();

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return resp;
}

CrossPlatformHttp::Response CrossPlatformHttp::get(const std::string& url,
                                                  const std::unordered_map<std::string, std::string>& headers) {
    Response resp;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

    std::string host, path;
    uint16_t port;
    bool is_secure;
    parse_url(url, host, path, port, is_secure);

    hSession = WinHttpOpen(L"Chrono-shift/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          nullptr, nullptr, 0);
    if (!hSession) return resp;

    std::wstring whost(host.begin(), host.end());
    hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return resp;
    }

    std::wstring wpath(path.begin(), path.end());
    hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                  nullptr, nullptr, nullptr,
                                  is_secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    for (const auto& [key, value] : headers) {
        std::wstring wheader(key.begin(), key.end());
        wheader += L": ";
        wheader += std::wstring(value.begin(), value.end());
        WinHttpAddRequestHeaders(hRequest, wheader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    if (!WinHttpSendRequest(hRequest, nullptr, 0, nullptr, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    DWORD bytes_available = 0;
    std::vector<char> buffer;
    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
        buffer.resize(buffer.size() + bytes_available + 1);
        DWORD bytes_read = 0;
        WinHttpReadData(hRequest, buffer.data() + buffer.size() - bytes_available - 1,
                        bytes_available, &bytes_read);
        buffer[buffer.size() - bytes_available - 1 + bytes_read] = '\0';
    }

    resp.body = buffer.data();

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return resp;
}

#else

static int create_socket(const std::string& host, uint16_t port) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (ret != 0) return -1;

    int sock = -1;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

static std::string http_send_recv(int sock, const std::string& request) {
    if (send(sock, request.data(), request.size(), 0) < 0) return "";

    std::vector<char> buffer(8192);
    std::string response;
    ssize_t n;
    while ((n = recv(sock, buffer.data(), buffer.size(), 0)) > 0) {
        response.append(buffer.data(), n);
    }
    return response;
}

#ifdef HTTPS_SUPPORT
static SSL_CTX* create_ssl_ctx() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return nullptr;

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    return ctx;
}
#endif

CrossPlatformHttp::Response CrossPlatformHttp::post(const std::string& url, const std::string& body,
                                                   const std::unordered_map<std::string, std::string>& headers) {
    Response resp;

    std::string host, path;
    uint16_t port;
    bool is_secure;
    parse_url(url, host, path, port, is_secure);

    int sock = create_socket(host, port);
    if (sock < 0) return resp;

#ifdef HTTPS_SUPPORT
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    if (is_secure) {
        ctx = create_ssl_ctx();
        if (!ctx) {
            close(sock);
            return resp;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }
    }
#endif

    std::stringstream ss;
    ss << "POST " << path << " HTTP/1.1\r\n";
    ss << "Host: " << host << "\r\n";
    ss << "Content-Length: " << body.size() << "\r\n";
    ss << "Content-Type: application/json\r\n";
    for (const auto& [key, value] : headers) {
        ss << key << ": " << value << "\r\n";
    }
    ss << "\r\n";
    ss << body;

    std::string request = ss.str();

#ifdef HTTPS_SUPPORT
    std::string response;
    if (ssl) {
        if (SSL_write(ssl, request.data(), request.size()) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }
        char buf[8192];
        int n;
        while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            response.append(buf, n);
        }
    } else {
        response = http_send_recv(sock, request);
    }
#else
    std::string response = http_send_recv(sock, request);
#endif

#ifdef HTTPS_SUPPORT
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
#endif
    close(sock);

    auto body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        resp.body = response.substr(body_start + 4);
        auto status_line_end = response.find("\r\n");
        if (status_line_end != std::string::npos) {
            std::string status_line = response.substr(0, status_line_end);
            auto sp = status_line.find(' ');
            if (sp != std::string::npos) {
                sp++;
                resp.status_code = std::stoi(status_line.substr(sp));
            }
        }
    }

    return resp;
}

CrossPlatformHttp::Response CrossPlatformHttp::get(const std::string& url,
                                                  const std::unordered_map<std::string, std::string>& headers) {
    Response resp;

    std::string host, path;
    uint16_t port;
    bool is_secure;
    parse_url(url, host, path, port, is_secure);

    int sock = create_socket(host, port);
    if (sock < 0) return resp;

#ifdef HTTPS_SUPPORT
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    if (is_secure) {
        ctx = create_ssl_ctx();
        if (!ctx) {
            close(sock);
            return resp;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }
    }
#endif

    std::stringstream ss;
    ss << "GET " << path << " HTTP/1.1\r\n";
    ss << "Host: " << host << "\r\n";
    for (const auto& [key, value] : headers) {
        ss << key << ": " << value << "\r\n";
    }
    ss << "\r\n";

    std::string request = ss.str();

#ifdef HTTPS_SUPPORT
    std::string response;
    if (ssl) {
        if (SSL_write(ssl, request.data(), request.size()) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }
        char buf[8192];
        int n;
        while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            response.append(buf, n);
        }
    } else {
        response = http_send_recv(sock, request);
    }
#else
    std::string response = http_send_recv(sock, request);
#endif

#ifdef HTTPS_SUPPORT
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
#endif
    close(sock);

    auto body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        resp.body = response.substr(body_start + 4);
        auto status_line_end = response.find("\r\n");
        if (status_line_end != std::string::npos) {
            std::string status_line = response.substr(0, status_line_end);
            auto sp = status_line.find(' ');
            if (sp != std::string::npos) {
                sp++;
                resp.status_code = std::stoi(status_line.substr(sp));
            }
        }
    }

    return resp;
}

#endif

} // namespace network
} // namespace client
} // namespace chrono