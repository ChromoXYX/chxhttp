#pragma once

#include <chx/net/error_code.hpp>

namespace chx::http {
enum class status_code : unsigned short {
    Continue = 100,
    Switching_Protocols = 101,
    OK = 200,
    Created = 201,
    Accepted = 202,
    Non_Authoritative_Information = 203,
    No_Content = 204,
    Reset_Content = 205,
    Partial_Content = 206,
    Multiple_Choices = 300,
    Moved_Permanently = 301,
    Found = 302,
    See_Other = 303,
    Not_Modified = 304,
    Use_Proxy = 305,
    Temporary_Redirect = 307,
    Permanent_Redirect = 308,
    Bad_Request = 400,
    Unauthorized = 401,
    Payment_Required = 402,
    Forbidden = 403,
    Not_Found = 404,
    Method_Not_Allowed = 405,
    Not_Acceptable = 406,
    Proxy_Authentication_Required = 407,
    Request_Timeout = 408,
    Conflict = 409,
    Gone = 410,
    Length_Required = 411,
    Precondition_Failed = 412,
    Content_Too_Large = 413,
    URI_Too_Long = 414,
    Unsupported_Media_Type = 415,
    Range_Not_Satisfiable = 416,
    Expectation_Failed = 417,
    Misdirected_Request = 421,
    Unprocessable_Content = 422,
    Upgrade_Required = 426,
    Internal_Server_Error = 500,
    Not_Implemented = 501,
    Bad_Gateway = 502,
    Service_Unavailable = 503,
    Gateway_Timeout = 504,
    HTTP_Version_Not_Supported = 505
};

constexpr std::string_view status_code_name(status_code code) {
    switch (code) {
    case status_code::Continue:
        return "Continue";
    case status_code::Switching_Protocols:
        return "Switching Protocols";
    case status_code::OK:
        return "OK";
    case status_code::Created:
        return "Created";
    case status_code::Accepted:
        return "Accepted";
    case status_code::Non_Authoritative_Information:
        return "Non Authoritative Information";
    case status_code::No_Content:
        return "No Content";
    case status_code::Reset_Content:
        return "Reset Content";
    case status_code::Partial_Content:
        return "Partial Content";
    case status_code::Multiple_Choices:
        return "Multiple Choices";
    case status_code::Moved_Permanently:
        return "Moved Permanently";
    case status_code::Found:
        return "Found";
    case status_code::See_Other:
        return "See Other";
    case status_code::Not_Modified:
        return "Not Modified";
    case status_code::Use_Proxy:
        return "Use Proxy";
    case status_code::Temporary_Redirect:
        return "Temporary Redirect";
    case status_code::Permanent_Redirect:
        return "Permanent Redirect";
    case status_code::Bad_Request:
        return "Bad Request";
    case status_code::Unauthorized:
        return "Unauthorized";
    case status_code::Payment_Required:
        return "Payment Required";
    case status_code::Forbidden:
        return "Forbidden";
    case status_code::Not_Found:
        return "Not Found";
    case status_code::Method_Not_Allowed:
        return "Method Not Allowed";
    case status_code::Not_Acceptable:
        return "Not Acceptable";
    case status_code::Proxy_Authentication_Required:
        return "Proxy Authentication Required";
    case status_code::Request_Timeout:
        return "Request Timeout";
    case status_code::Conflict:
        return "Conflict";
    case status_code::Gone:
        return "Gone";
    case status_code::Length_Required:
        return "Length Required";
    case status_code::Precondition_Failed:
        return "Precondition Failed";
    case status_code::Content_Too_Large:
        return "Content Too Large";
    case status_code::URI_Too_Long:
        return "URI Too Long";
    case status_code::Unsupported_Media_Type:
        return "Unsupported Media Type";
    case status_code::Range_Not_Satisfiable:
        return "Range Not Satisfiable";
    case status_code::Expectation_Failed:
        return "Expectation Failed";
    case status_code::Misdirected_Request:
        return "Misdirected Request";
    case status_code::Unprocessable_Content:
        return "Unprocessable Content";
    case status_code::Upgrade_Required:
        return "Upgrade Required";
    case status_code::Internal_Server_Error:
        return "Internal Server Error";
    case status_code::Not_Implemented:
        return "Not Implemented";
    case status_code::Bad_Gateway:
        return "Bad Gateway";
    case status_code::Service_Unavailable:
        return "Service Unavailable";
    case status_code::Gateway_Timeout:
        return "Gateway Timeout";
    case status_code::HTTP_Version_Not_Supported:
        return "HTTP Version Not Supported";
    default: {
        __CHXNET_THROW(EINVAL);
    }
    }
}
}  // namespace chx::http
