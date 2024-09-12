#pragma once

#include "./error_codes.hpp"
#include "./events.hpp"
#include "../header.hpp"
#include "../request.hpp"
#include "../response.hpp"
#include "./detail/h2_stream.hpp"
#include "./detail/frame.hpp"

#include <chx/log.hpp>

namespace chx::http::h2 {
template <typename SessionFactory> class connection : private SessionFactory {
    enum HttpStage { HeaderStage, DataStage };
    template <typename Session> struct session_wrapper : Session {
        HttpStage stage = HeaderStage;
        request_type request;
    };

  public:
    using session_type = session_wrapper<std::invoke_result_t<SessionFactory>>;

  private:
    using frame = detail::frame<session_type>;
    using FrameType = detail::FrameType;
    using h2_stream = detail::h2_stream<session_type>;
    using StreamStates = detail::StreamStates;

  public:
    connection(SessionFactory&& session_factory)
        : SessionFactory(std::move(session_factory)) {}

    /*
    only END_HEADERS (header_complete) can switch stage to DataStage
    only recv HEADERS frame at HeaderStage
    only recv DATA frame at DataStage
    only on_message_complete when at DataStage and
    strm.state==HalfClosedRemote
    */

    template <typename Cntl>
    ErrorCodes operator()(ev::frame_start, Cntl& cntl, const frame& frame) {
        if (frame.type == FrameType::DATA) {
            assert(frame.strm);
            return frame.strm->session().stage == DataStage
                       ? ErrorCodes::NO_ERROR
                       : ErrorCodes::PROTOCOL_ERROR;
        } else if (frame.type == FrameType::HEADERS ||
                   frame.type == FrameType::CONTINUATION) {
            assert(frame.strm);
            return frame.strm->session().stage == HeaderStage
                       ? ErrorCodes::NO_ERROR
                       : ErrorCodes::PROTOCOL_ERROR;
        } else {
            return ErrorCodes::NO_ERROR;
        }
    }

    template <typename Oper>
    ErrorCodes operator()(ev::frame_complete, Oper& oper, const frame& frame) {
        if (frame.type == FrameType::DATA) {
            assert(frame.strm);
            h2_stream& strm = *frame.strm;
            session_type& ses = strm.session();
            if (strm.state == StreamStates::HalfClosedRemote) {
                assert(ses.stage == DataStage);
                on<ev::message_complete>(ses, ses.request,
                                         response_impl(&oper, frame.strm));
            }
            return ErrorCodes::NO_ERROR;
        } else if (frame.type == FrameType::HEADERS ||
                   frame.type == FrameType::CONTINUATION) {
            assert(frame.strm);
            h2_stream& strm = *frame.strm;
            session_type& ses = strm.session();
            if (ses.stage == DataStage  // all headers complete
                &&
                strm.state == StreamStates::HalfClosedRemote  // and END_STREAM
            ) {
                on<ev::message_complete>(ses, ses.request,
                                         response_impl(&oper, frame.strm));
            }
            return ErrorCodes::NO_ERROR;
        } else {
            return ErrorCodes::NO_ERROR;
        }
    }

    template <typename Oper>
    ErrorCodes operator()(ev::header_complete, Oper& oper, const frame& frame,
                          fields_type&& fields) {
        assert(frame.strm);
        session_type& ses = frame.strm->session();
        ses.stage = DataStage;

        request_type& req = ses.request;
        if (auto ite = fields.find(":path"); ite != fields.end()) {
            req.request_target = ite->second;
        } else {
            return ErrorCodes::PROTOCOL_ERROR;
        }
        if (auto ite = fields.find(":method"); ite != fields.end()) {
            const std::string& m = ite->second;
            if (m == "GET") {
                req.method = method_type::GET;
            } else if (m == "HEAD") {
                req.method = method_type::HEAD;
            } else if (m == "POST") {
                req.method = method_type::POST;
            } else if (m == "PUT") {
                req.method = method_type::PUT;
            } else if (m == "DELETE") {
                req.method = method_type::DELETE;
            } else if (m == "OPTIONS") {
                req.method = method_type::OPTIONS;
            } else if (m == "TRACE") {
                req.method = method_type::TRACE;
            } else {
                return ErrorCodes::PROTOCOL_ERROR;
            }
        } else {
            return ErrorCodes::PROTOCOL_ERROR;
        }
        req.fields = std::move(fields);
        on<ev::header_complete>(ses, const_cast<const request_type&>(req),
                                response_impl(&oper, frame.strm));
        return ErrorCodes::NO_ERROR;
    }

    template <typename Oper>
    ErrorCodes operator()(ev::data_block, Oper& oper, const frame& frame,
                          const unsigned char* begin,
                          const unsigned char* end) {
        assert(frame.strm);
        session_type& ses = frame.strm->session();
        on<ev::data_block>(ses, const_cast<const request_type&>(ses.request),
                           response_impl(&oper, frame.strm), (const char*)begin,
                           (const char*)end);
        return ErrorCodes::NO_ERROR;
    }

    session_type create_session() {
        return session_type(SessionFactory::operator()());
    }

  private:
    template <typename Event, typename T, typename... Args>
    void on(T&& t, Args&&... args) {
        if constexpr (std::is_invocable_v<T&&, Event, Args&&...>) {
            return std::forward<T>(t)(Event(), std::forward<Args>(args)...);
        }
    }

    template <typename Oper> class response_impl : public response {
        friend connection;

        response_impl(Oper* p, const net::detail::weak_ptr<h2_stream>& strm)
            : oper(p), strm_ptr(strm) {}

        Oper* const oper;
        net::detail::weak_ptr<h2_stream> strm_ptr;

      public:
        virtual std::unique_ptr<response> copy() const override {
            return std::unique_ptr<response_impl>(new response_impl(*this));
        }
        virtual bool get_guard() const noexcept(true) override {
            return !oper->io_cntl.goaway_sent() && strm_ptr;
        }

        virtual void end(status_code code, fields_type&& fields) {
            resp(code, std::move(fields));
        }
        virtual void end(status_code code, fields_type&& fields,
                         std::string_view payload) {
            resp(code, std::move(fields), std::move(payload));
        }
        virtual void end(status_code code, fields_type&& fields,
                         std::string payload) {
            resp(code, std::move(fields), std::move(payload));
        }
        virtual void end(status_code code, fields_type&& fields,
                         std::vector<unsigned char> payload) {
            resp(code, std::move(fields), std::move(payload));
        }
        virtual void end(status_code code, fields_type&& fields,
                         net::mapped_file mapped, std::size_t len,
                         std::size_t offset = 0) {
            resp(code, std::move(fields),
                 net::carrier{std::move(mapped), offset, len});
        }

        const net::ip::tcp::socket& socket() const noexcept(true) override {
            return oper->__M_stream;
        }

        void co_spawn(net::future<>&& future) const {
            if (get_guard()) {
                auto& cntl = this->oper->cntl();
                net::co_spawn(
                    cntl.get_associated_io_context(),
                    [](net::future<> f) -> net::task {
                        co_return co_await f;
                    }(std::move(future)),
                    cntl.next_then([oper = oper](const std::error_code& e) {
                        oper->complete_with_goaway(e);
                    }));
            }
        }

      private:
        template <typename... Payloads>
        void resp(status_code code, fields_type&& fields,
                  Payloads&&... payloads) {
            if (get_guard()) {
                h2_stream& strm = *strm_ptr;
                detail::stream_id_t strm_id = strm.self_pos->first;
                if constexpr (sizeof...(Payloads) == 0) {
                    ErrorCodes r = oper->create_HEADER_frame(
                        detail::Flags::END_STREAM, strm, code, fields);
                    if (r == ErrorCodes::NO_ERROR) {
                        oper->do_send();
                    } else {
                        __CHXNET_THROW_EC(make_ec(r));
                    }
                } else {
                    ErrorCodes r =
                        oper->create_HEADER_frame(0, strm, code, fields);
                    if (r != ErrorCodes::NO_ERROR) {
                        __CHXNET_THROW_EC(make_ec(r));
                    }
                    assert(strm_ptr);
                    oper->create_DATA_frame(
                        detail::Flags::END_STREAM, strm,
                        std::forward<Payloads>(payloads)...);
                    oper->do_send();
                }
                oper->largest_strm_id_processed =
                    std::max(oper->largest_strm_id_processed, strm_id);
            }
        }
    };
};
}  // namespace chx::http::h2