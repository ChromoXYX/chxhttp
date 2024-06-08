#pragma once

#include <string_view>
#include <map>

struct media_type {
    std::string_view type;
    std::string_view sub_type;
    std::map<std::string_view, std::string_view> parameters;

    media_type() = default;
    media_type(const media_type&) = default;
    media_type(media_type&&) = default;

    bool from_string(std::string_view sv);
};
