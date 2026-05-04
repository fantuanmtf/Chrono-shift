/**
 * Chrono-shift OpenAI Provider 实现
 * C++17
 *
 * 使用 WinHTTP 发送请求到 OpenAI 兼容 API
 * 支持: OpenAI, DeepSeek, xAI Grok, Ollama (本地)
 */
#include "OpenAIProvider.h"

#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>

#include "../network/CrossPlatformHttp.h"

namespace chrono {
namespace client {
namespace ai {

// 工厂函数实现
std::unique_ptr<AIProvider> CreateOpenAIProvider(const AIConfig& config) {
    return std::make_unique<OpenAIProvider>(config);
}

OpenAIProvider::OpenAIProvider(const AIConfig& config) {
    set_config(config);
}

void OpenAIProvider::set_config(const AIConfig& config) {
    config_ = config;
    api_endpoint_ = config.api_endpoint;
    api_key_ = config.api_key;
    model_ = config.model_name;
    max_tokens_ = config.max_tokens;
    temperature_ = config.temperature;
}

bool OpenAIProvider::is_available() const {
    if (api_endpoint_.empty()) return false;
    // Ollama 本地模型不需要 API key
    if (config_.provider_type == AIProviderType::kOllama) {
        return true;
    }
    return !api_key_.empty();
}

bool OpenAIProvider::test_connection() {
    if (!is_available()) return false;

    // 发送一个简单的请求测试连接
    std::vector<ChatMessage> test_msg = {
        {"user", "ping"}
    };
    try {
        auto result = chat(test_msg);
        return !result.empty();
    } catch (...) {
        return false;
    }
}

std::string OpenAIProvider::chat(
    const std::vector<ChatMessage>& messages,
    std::function<void(const std::string&)> callback) {

    auto body = build_chat_request(messages);
    auto response = http_post(body);
    auto result = parse_chat_response(response);

    if (callback) {
        callback(result);
    }

    return result;
}

std::string OpenAIProvider::generate(
    const std::string& prompt,
    const std::string& params) {

    std::vector<ChatMessage> messages = {
        {"user", prompt}
    };
    return chat(messages);
}

std::string OpenAIProvider::build_chat_request(
    const std::vector<ChatMessage>& messages) {

    std::ostringstream oss;
    oss << "{";
    oss << "\"model\":\"" << model_ << "\",";
    oss << "\"messages\":[";
    for (size_t i = 0; i < messages.size(); i++) {
        if (i > 0) oss << ",";
        oss << "{";
        oss << "\"role\":\"" << messages[i].role << "\",";
        // 转义 content 中的特殊字符
        std::string escaped = messages[i].content;
        auto escape_pos = std::string::npos;
        // 简单转义双引号和反斜杠
        std::string result;
        for (char c : escaped) {
            if (c == '"') result += "\\\"";
            else if (c == '\\') result += "\\\\";
            else if (c == '\n') result += "\\n";
            else if (c == '\r') result += "\\r";
            else if (c == '\t') result += "\\t";
            else result += c;
        }
        oss << "\"content\":\"" << result << "\"";
        oss << "}";
    }
    oss << "],";
    oss << "\"max_tokens\":" << max_tokens_ << ",";
    oss << "\"temperature\":" << temperature_;
    oss << "}";
    return oss.str();
}

std::string OpenAIProvider::parse_chat_response(const std::string& body) {
    // 简化 JSON 解析 - 提取 "content" 字段
    auto content_key = "\"content\":\"";
    auto pos = body.find(content_key);
    if (pos == std::string::npos) {
        // 尝试查找 error 消息
        auto err_pos = body.find("\"error\"");
        if (err_pos != std::string::npos) {
            return "[API Error] " + body.substr(err_pos, 200);
        }
        return "";
    }

    pos += strlen(content_key);
    std::string result;
    bool escape = false;
    for (; pos < body.size(); pos++) {
        if (escape) {
            if (body[pos] == 'n') result += '\n';
            else if (body[pos] == 'r') result += '\r';
            else if (body[pos] == 't') result += '\t';
            else if (body[pos] == '"') result += '"';
            else if (body[pos] == '\\') result += '\\';
            else result += body[pos];
            escape = false;
        } else if (body[pos] == '\\') {
            escape = true;
        } else if (body[pos] == '"') {
            break;
        } else {
            result += body[pos];
        }
    }
    return result;
}

std::string OpenAIProvider::http_post(const std::string& body) {
    using namespace chrono::client::network;
    
    std::unordered_map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";
    
    if (!api_key_.empty()) {
        headers["Authorization"] = "Bearer " + api_key_;
    }

    auto response = CrossPlatformHttp::post(api_endpoint_, body, headers);
    return response.body;
}

} // namespace ai
} // namespace client
} // namespace chrono
