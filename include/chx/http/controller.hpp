#pragma once

/*
controller design
1. every controller instance should serve in session level (a http/1.1
connection or a http/2 stream)
2. a controller will be called twice at least: header_complete, [data_block] and
message_complete
3. controller will be called in the same context as caller
4. chxhttp allows pipelining in http/1.1, or rather actually doesn't care about it.
*/

#include "./async_http.hpp"
#include "./h2/async_http2.hpp"

namespace chx::http {
template <typename Impl> class controller : protected Impl {
    // to hide on(...)
    template <typename Stream, typename Session, typename CntlType>
    friend struct detail::operation;
    template <typename Stream, typename Session, typename HPackImpl,
              typename FixedTimerRef, typename CntlType>
    friend struct h2::detail::h2_impl;

    // h1.1
    

  public:
    using impl_type = Impl;
};
}  // namespace chx::http