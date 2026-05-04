/**
 * Chrono-shift Google Gemini Provider 实现
 * C++17
 *
 * 使用跨平台 HTTP 客户端发送请求到 Google Gemini API
 * API 格式: https://ai.google.dev/api
 */
#include "GeminiProvider.h"

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
std::unique_ptr<AIProvider> CreateGeminiProvider(const AIConfig& config) {
    return std::make_unique<GeminiProvider>(config);
}

GeminiProvider::GeminiProvider(const AIConfig& config) {
    set_config(config);
}

void GeminiProvider::set_config(const AIConfig& config) {
    config_ = config;
    api_endpoint_ = config.api_endpoint;
    api_key_ = config.api_key;
    model_ = config.model_name;
    max_tokens_ = config.max_tokens;
    temperature_ = config.temperature;
}

bool GeminiProvider::is_available() const {
    return !api_endpoint_.empty() && !api_key_.empty() && !model_.empty();
}

bool GeminiProvider::test_connection() {
    if (!is_available()) return false;

    try {
        // 测试连接: 调用 list models 端点
        std::string base = api_endpoint_;
        // 移除尾部斜杠
        while (!base.empty() && base.back() == '/') base.pop_back();
        std::string url = base + "/v1beta/models?key=" + api_key_;

        std::string response = http_post(url, "");

        // 如果返回包含 models 列表，说明连接成功
        return response.find("\"models\"") != std::string::npos;
    } catch (...) {
        return false;
    }
}

std::string GeminiProvider::chat(
    const std::vector<ChatMessage>& messages,
    std::function<void(const std::string&)> callback) {

    auto body = build_gemini_request(messages);

    // 构建完整的 Gemini API URL
    std::string base = api_endpoint_;
    while (!base.empty() && base.back() == '/') base.pop_back();
    std::string url = base + "/v1beta/models/" + model_ + ":generateContent?key=" + api_key_;

    auto response = http_post(url, body);
    auto result = parse_gemini_response(response);

    if (callback) {
        callback(result);
    }

    return result;
}

std::string GeminiProvider::generate(
    const std::string& prompt,
    const std::string& params) {

    std::vector<ChatMessage> messages = {
        {"user", prompt}
    };
    return chat(messages);
}

std::string GeminiProvider::build_gemini_request(
    const std::vector<ChatMessage>& messages) {

    std::ostringstream oss;

    // 分离 system 消息和其他消息
    std::string system_content;
    std::vector<ChatMessage> content_messages;

    for (const auto& msg : messages) {
        if (msg.role == "system") {
            system_content = msg.content;
        } else {
            content_messages.push_back(msg);
        }
    }

    oss << "{";

    // system_instruction (可选)
    if (!system_content.empty()) {
        oss << "\"system_instruction\":{";
        oss << "\"parts\":[{\"text\":\"";
        // 转义特殊字符
        for (char c : system_content) {
            if (c == '"') oss << "\\\"";
            else if (c == '\\') oss << "\\\\";
            else if (c == '\n') oss << "\\n";
            else if (c == '\r') oss << "\\r";
            else if (c == '\t') oss << "\\t";
            else oss << c;
        }
        oss << "\"}]},";
    }

    // contents
    oss << "\"contents\":[";
    for (size_t i = 0; i < content_messages.size(); i++) {
        if (i > 0) oss << ",";
        oss << "{";
        // Gemini 使用 "model" 替代 "assistant"
        std::string role = content_messages[i].role;
        if (role == "assistant") role = "model";
        oss << "\"role\":\"" << role << "\",";
        oss << "\"parts\":[{\"text\":\"";
        // 转义 content
        for (char c : content_messages[i].content) {
            if (c == '"') oss << "\\\"";
            else if (c == '\\') oss << "\\\\";
            else if (c == '\n') oss << "\\n";
            else if (c == '\r') oss << "\\r";
            else if (c == '\t') oss << "\\t";
            else oss << c;
        }
        oss << "\"}]";
        oss << "}";
    }
    oss << "],";

    // generationConfig
    oss << "\"generationConfig\":{";
    oss << "\"maxOutputTokens\":" << max_tokens_ << ",";
    oss << "\"temperature\":" << temperature_;
    oss << "}";

    oss << "}";
    return oss.str();
}

std::string GeminiProvider::parse_gemini_response(const std::string& body) {
    // 提取 candidates[0].content.parts[0].text
    // 简化解析: 查找 "text":" 后的内容

    // 检查 error
    auto err_pos = body.find("\"error\"");
    if (err_pos != std::string::npos) {
        // 查找 error.message
        auto msg_pos = body.find("\"message\":\"", err_pos);
        if (msg_pos != std::string::npos) {
            msg_pos += 11; // len of "\"message\":\""
            std::string err_msg;
            for (; msg_pos < body.size(); msg_pos++) {
                if (body[msg_pos] == '"') break;
                err_msg += body[msg_pos];
            }
            return "[Gemini Error] " + err_msg;
        }
        return "[Gemini Error] 未知错误";
    }

    // 查找 candidates[0].content.parts[0].text
    auto text_key = "\"text\":\"";
    auto pos = body.find(text_key);
    if (pos == std::string::npos) {
        return "";
    }

    pos += strlen(text_key);
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

std::string GeminiProvider::http_post(const std::string& url, const std::string& body) {
    using namespace chrono::client::network;
    
    std::unordered_map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";

    if (body.empty()) {
        auto response = CrossPlatformHttp::get(url, headers);
        return response.body;
    } else {
        auto response = CrossPlatformHttp::post(url, body, headers);
        return response.body;
    }
}

} // namespace ai
} // namespace client
} // namespace chrono
