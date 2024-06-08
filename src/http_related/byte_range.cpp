#include "./byte_range.hpp"
#include "./boost_spirit_parser.hpp"

namespace parser {
// const auto range_unit = token;
constexpr auto first_pos = x3::ulong_;
constexpr auto last_pos = x3::ulong_;

const x3::rule<struct int_range, std::pair<std::size_t, std::size_t>> int_range;
constexpr auto int_range_def = first_pos >> '-' >> -last_pos;
BOOST_SPIRIT_DEFINE(int_range);
// constexpr auto suffix_range = x3::attr(std::size_t{}) >> '-' >> x3::ulong_;
const x3::rule<struct suffix_range, std::pair<std::size_t, std::size_t>>
    suffix_range;
constexpr auto suffix_range_def = x3::attr(std::size_t{}) >> '-' >> x3::ulong_;
BOOST_SPIRIT_DEFINE(suffix_range);

const auto range_spec = int_range | suffix_range;
const auto range_set = range_spec >>
                       *(x3::omit[OWS >> ',' >> OWS] >> range_spec);
const auto ranges_specifier = "bytes=" >> range_set;
}  // namespace parser

bool parse_byte_range(std::string_view view,
                      std::vector<std::pair<std::size_t, std::size_t>>& ret) {
    auto p = view.begin(), q = view.end();
    return x3::parse(p, q, parser::ranges_specifier, ret) && (p == q);
}