/**
 * Chrono-shift 自定义 AI Provider 实现
 * C++17
 */
#include "CustomProvider.h"

#include <sstream>
#include <unordered_map>

#include "../network/CrossPlatformHttp.h"

namespace chrono {
namespace client {
namespace ai {

// 工厂函数实现
std::unique_ptr<AIProvider> CreateCustomProvider(const AIConfig& config) {
    return std::make_unique<CustomProvider>(config);
}

CustomProvider::CustomProvider(const AIConfig& config) {
    set_config(config);
}

void CustomProvider::set_config(const AIConfig& config) {
    config_ = config;
    api_endpoint_ = config.api_endpoint;
    api_key_ = config.api_key;
    model_ = config.model_name;
    max_tokens_ = config.max_tokens;
    temperature_ = config.temperature;
}

bool CustomProvider::is_available() const {
    return !api_endpoint_.empty();
}

bool CustomProvider::test_connection() {
    if (!is_available()) return false;
    try {
        auto result = http_post(api_endpoint_, "{\"test\":true}", "");
        return !result.empty();
    } catch (...) {
        return false;
    }
}

std::string CustomProvider::chat(
    const std::vector<ChatMessage>& messages,
    std::function<void(const std::string&)> callback) {

    // 构建简单的 JSON 请求体
    std::ostringstream oss;
    oss << "{\"messages\":[";
    for (size_t i = 0; i < messages.size(); i++) {
        if (i > 0) oss << ",";
        oss << "{\"role\":\"" << messages[i].role
            << "\",\"content\":\"" << messages[i].content << "\"}";
    }
    oss << "],\"model\":\"" << model_ << "\"}";

    std::string auth_header;
    if (!api_key_.empty()) {
        auth_header = "Authorization: Bearer " + api_key_;
    }

    auto response = http_post(api_endpoint_, oss.str(), auth_header);

    if (callback) {
        callback(response);
    }

    return response;
}

std::string CustomProvider::generate(
    const std::string& prompt,
    const std::string& params) {

    std::vector<ChatMessage> messages = {
        {"user", prompt}
    };
    return chat(messages);
}

std::string CustomProvider::http_post(
    const std::string& endpoint,
    const std::string& body,
    const std::string& auth_header) {

    using namespace chrono::client::network;
    
    std::unordered_map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";
    
    if (!auth_header.empty()) {
        auto bearer_pos = auth_header.find("Bearer ");
        if (bearer_pos != std::string::npos) {
            headers["Authorization"] = auth_header.substr(bearer_pos);
        } else {
            headers["Authorization"] = auth_header;
        }
    }

    auto response = CrossPlatformHttp::post(endpoint, body, headers);
    return response.body;
}

} // namespace ai
} // namespace client
} // namespace chrono
