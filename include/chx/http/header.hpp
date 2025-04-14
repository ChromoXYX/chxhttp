#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

namespace chx::http {
class fields_type {
    using __container_type = std::vector<std::pair<std::string, std::string>>;
    __container_type __M_v;

    static bool __ncase_cmp(std::string_view a,
                            std::string_view b) noexcept(true) {
        if (a.size() == b.size()) {
            return ::strncasecmp(a.data(), b.data(), a.size()) == 0;
        } else {
            return false;
        }
    }

  public:
    using value_type = typename __container_type::value_type;
    using iterator_type = typename __container_type::iterator;
    using const_iterator_type = typename __container_type::const_iterator;

    fields_type() noexcept(true) = default;
    fields_type(const fields_type&) = default;
    fields_type(fields_type&&) noexcept(true) = default;
    fields_type(std::initializer_list<value_type> list)
        : __M_v(std::move(list)) {}

    fields_type& operator=(const fields_type&) = default;
    fields_type& operator=(fields_type&&) noexcept(true) = default;

    constexpr iterator_type begin() noexcept(true) { return __M_v.begin(); }
    constexpr const_iterator_type begin() const noexcept(true) {
        return __M_v.begin();
    }
    constexpr iterator_type end() noexcept(true) { return __M_v.end(); }
    constexpr const_iterator_type end() const noexcept(true) {
        return __M_v.end();
    }
    constexpr std::size_t size() const noexcept(true) { return __M_v.size(); }
    constexpr bool empty() const noexcept(true) { return __M_v.empty(); }
    constexpr value_type& back() noexcept(true) { return __M_v.back(); }
    constexpr const value_type& back() const noexcept(true) {
        return __M_v.back();
    }

    std::size_t byte_n() const noexcept(true) {
        std::size_t __r = 0;
        for (const auto& [k, v] : *this) {
            if (!k.empty() && !v.empty()) {
                __r += 4 + k.size() + v.size();
            }
        }
        return __r;
    }

    constexpr iterator_type find(std::string_view key) noexcept(true) {
        return std::find_if(
            __M_v.begin(), __M_v.end(),
            [key](const auto& i) -> bool { return __ncase_cmp(key, i.first); });
    }
    constexpr const_iterator_type find(std::string_view key) const
        noexcept(true) {
        return std::find_if(
            __M_v.begin(), __M_v.end(),
            [key](const auto& i) -> bool { return __ncase_cmp(key, i.first); });
    }
    constexpr bool contains(std::string_view key) const noexcept(true) {
        return find(key) != __M_v.end();
    }
    constexpr bool exactly_contains(std::string_view key,
                                    std::string_view value) const
        noexcept(true) {
        if (auto ite = find(key); ite != end()) {
            return ite->second == value;
        } else {
            return false;
        }
    }

    template <typename Key, typename Value>
    value_type& insert_field(Key&& key, Value&& value) {
        return __M_v.emplace_back(std::forward<Key>(key),
                                  std::forward<Value>(value));
    }
    template <typename Key, typename Value>
    value_type& add_field(Key&& key, Value&& value) {
        auto ite = find(key);
        if (ite != __M_v.end()) {
            if (ite->second.empty()) {
                ite->second = std::forward<Value>(value);
            } else {
                ite->second.append(", ").append(value);
            }
            return *ite;
        } else {
            return insert_field(std::forward<Key>(key),
                                std::forward<Value>(value));
        }
    }
    template <typename Key, typename Value>
    value_type& set_field(Key&& key, Value&& value) {
        auto ite = find(key);
        if (ite != __M_v.end()) {
            ite->second = std::forward<Value>(value);
            return *ite;
        } else {
            return insert_field(std::forward<Key>(key),
                                std::forward<Value>(value));
        }
    }
    template <typename Key> std::string& operator[](Key&& key) {
        auto ite = find(key);
        if (ite != __M_v.end()) {
            return ite->second;
        } else {
            return emplace_back(std::forward<Key>(key)).second;
        }
    }
    template <typename Key> value_type& emplace_back(Key&& key) {
        return __M_v.emplace_back(std::forward<Key>(key), std::string{});
    }

    std::string to_string() const {
        std::string __ret;
        __ret.resize(byte_n());
        auto ite = __ret.begin();
        constexpr char b1[] = ": ", b2[] = "\r\n";
        for (const auto& [k, v] : __M_v) {
            if (!k.empty() && !v.empty()) {
                ite = std::copy(
                    std::begin(b2), std::end(b2) - 1,
                    std::copy(v.begin(), v.end(),
                              std::copy(std::begin(b1), std::end(b1) - 1,
                                        std::copy(k.begin(), k.end(), ite))));
            }
        }
        return std::move(__ret);
    }

    void clear() noexcept(true) { __M_v.clear(); }
};
}  // namespace chx::http
