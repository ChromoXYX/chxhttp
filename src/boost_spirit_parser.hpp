#pragma once

#include <boost/spirit/home/x3.hpp>
#include <boost/fusion/adapted/std_pair.hpp>

namespace x3 = boost::spirit::x3;

namespace boost::spirit::x3::traits {
template <typename Char, typename Trait>
struct is_range<std::basic_string_view<Char, Trait>> : boost::mpl::true_ {};
}  // namespace boost::spirit::x3::traits

template <typename Subject> struct raw_directive : x3::raw_directive<Subject> {
    using x3::raw_directive<Subject>::raw_directive;

    template <typename Iterator, typename Context, typename RContext,
              typename Attribute>
    bool parse(Iterator& first, Iterator const& last, Context const& context,
               RContext& rcontext, Attribute& attr) const {
        x3::skip_over(first, last, context);
        Iterator saved = first;
        if (this->subject.parse(first, last, context, rcontext, x3::unused)) {
            attr = {saved, typename Attribute::size_type(first - saved)};
            return true;
        }
        return false;
    }
};

struct raw_gen {
    template <typename Subject>
    constexpr raw_directive<
        typename x3::extension::as_parser<Subject>::value_type>
    operator[](Subject subject) const {
        return {x3::as_parser(std::move(subject))};
    }
};

constexpr inline auto svp = raw_gen{};

const auto tchar = x3::char_("!#$%&'*+-.^_`|~") | x3::digit | x3::alpha;
const auto token = +tchar;
constexpr auto HTAB = x3::char_(0x09);
constexpr auto SP = x3::char_(0x20);
constexpr auto OWS = *(SP | HTAB);

constexpr auto qdtext = *(x3::print - x3::char_('\"'));
constexpr auto quoted_string = '\"' >> svp[qdtext] >> '\"';