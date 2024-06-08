#include "./boost_spirit_parser.hpp"
#include "./media_type.hpp"

BOOST_FUSION_ADAPT_STRUCT(media_type, type, sub_type, parameters);
namespace parse {
const auto parameter_name = svp[token];
const auto parameter_value = svp[token] | quoted_string;

const x3::rule<struct parameter, std::pair<std::string_view, std::string_view>>
    parameter;
const auto parameter_def = parameter_name >> '=' >> parameter_value;
BOOST_SPIRIT_DEFINE(parameter);

const x3::rule<struct parameters, std::map<std::string_view, std::string_view>>
    parameters;
const auto parameters_def = *(x3::omit[OWS >> ';' >> OWS] >> -parameter);
BOOST_SPIRIT_DEFINE(parameters);

const auto type = token;
const auto subtype = token;

x3::rule<struct mt, media_type> mt;
const auto mt_def = svp[type] >> '/' >> svp[subtype] >> parameters;
BOOST_SPIRIT_DEFINE(mt);
}  // namespace parse

bool media_type::from_string(std::string_view sv) {
    auto begin = sv.begin(), end = sv.end();
    bool r = x3::parse(begin, end, parse::mt, *this);
    return begin == end && r;
}
