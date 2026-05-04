#ifndef CHRONO_CROSS_PLATFORM_HTTP_H
#define CHRONO_CROSS_PLATFORM_HTTP_H

#include <cstdint>
#include <string>
#include <unordered_map>

namespace chrono {
namespace client {
namespace network {

class CrossPlatformHttp {
public:
    struct Response {
        int status_code = 0;
        std::string body;
        std::unordered_map<std::string, std::string> headers;
    };

    static Response post(const std::string& url, const std::string& body,
                        const std::unordered_map<std::string, std::string>& headers = {});

    static Response get(const std::string& url,
                       const std::unordered_map<std::string, std::string>& headers = {});

private:
    static bool parse_url(const std::string& url, std::string& host,
                         std::string& path, uint16_t& port, bool& is_secure);
};

} // namespace network
} // namespace client
} // namespace chrono

#endif // CHRONO_CROSS_PLATFORM_HTTP_H