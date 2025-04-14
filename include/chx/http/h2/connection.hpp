#pragma once

#include "./error_codes.hpp"
#include "./events.hpp"
#include "../header.hpp"
#include "../request.hpp"
#include "../response.hpp"
#include "./detail/h2_stream.hpp"
#include "./detail/frame.hpp"

#include <chx/net/detail/scope_exit.hpp>
#include <chx/log.hpp>

namespace chx::http::h2 {
template <typename SessionFactory> class connection : private SessionFactory {
    enum HttpStage { HeaderStage, DataStage, CompleteStage };
    template <typename Session> struct session_wrapper : Session {
        HttpStage stage = HeaderStage;
        request_type request;

        std::size_t pause_vote = 0;
        std::queue<std::vector<unsigned char>> buffered;

        bool is_resuming = false;
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
        if (!frame.strm) {
            return ErrorCodes::NO_ERROR;
        }
        if (frame.type == FrameType::DATA) {
            return frame.strm->session().stage == DataStage
                       ? ErrorCodes::NO_ERROR
                       : ErrorCodes::PROTOCOL_ERROR;
        } else if (frame.type == FrameType::HEADERS ||
                   frame.type == FrameType::CONTINUATION) {
            return frame.strm->session().stage == HeaderStage
                       ? ErrorCodes::NO_ERROR
                       : ErrorCodes::PROTOCOL_ERROR;
        } else {
            return ErrorCodes::NO_ERROR;
        }
    }

    template <typename Oper>
    ErrorCodes operator()(ev::frame_complete, Oper& oper, const frame& frame) {
        if (!frame.strm) {
            return ErrorCodes::NO_ERROR;
        }
        if (frame.type == FrameType::DATA) {
            h2_stream& strm = *frame.strm;
            session_type& ses = strm.session();
            if (strm.state == StreamStates::HalfClosedRemote) {
                assert(ses.stage == DataStage);
                if (!ses.pause_vote) {
                    on<ev::message_complete>(ses, ses.request,
                                             response_impl(&oper, frame.strm));
                } else {
                    ses.stage = CompleteStage;
                }
            }
            return ErrorCodes::NO_ERROR;
        } else if (frame.type == FrameType::HEADERS ||
                   frame.type == FrameType::CONTINUATION) {
            h2_stream& strm = *frame.strm;
            session_type& ses = strm.session();
            if (ses.stage == DataStage  // all headers complete
                &&
                strm.state == StreamStates::HalfClosedRemote  // and END_STREAM
            ) {
                if (!ses.pause_vote) {
                    on<ev::message_complete>(ses, ses.request,
                                             response_impl(&oper, frame.strm));
                } else {
                    ses.stage = CompleteStage;
                }
            }
            return ErrorCodes::NO_ERROR;
        } else {
            return ErrorCodes::NO_ERROR;
        }
    }

    template <typename Oper>
    ErrorCodes operator()(ev::header_complete, Oper& oper, const frame& frame,
                          fields_type&& fields) {
        if (!frame.strm) {
            return ErrorCodes::NO_ERROR;
        }
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
        on<ev::header_complete>(ses, req, response_impl(&oper, frame.strm));
        return ErrorCodes::NO_ERROR;
    }

    template <typename Oper>
    ErrorCodes operator()(ev::data_block, Oper& oper, const frame& frame,
                          const unsigned char* begin,
                          const unsigned char* end) {
        if (!frame.strm) {
            return ErrorCodes::NO_ERROR;
        }
        session_type& ses = frame.strm->session();
        if (!ses.pause_vote) {
            on<ev::data_block>(ses, ses.request,
                               response_impl(&oper, frame.strm), begin, end);
        } else {
            ses.buffered.push(std::vector(begin, end));
        }
        return ErrorCodes::NO_ERROR;
    }

    session_type create_session() {
        return session_type(SessionFactory::operator()());
    }

  private:
    template <typename Event, typename T, typename... Args>
    static void on(T&& t, Args&&... args) {
        if constexpr (std::is_invocable_v<T&&, Event, Args&&...>) {
            return std::forward<T>(t)(Event(), std::forward<Args>(args)...);
        }
    }

    template <typename Oper> class response_impl : public response_type {
        friend connection;

        response_impl(Oper* p, const net::detail::weak_ptr<h2_stream>& s)
            : oper(p->weak_from_this()), strm(s) {}

        net::detail::weak_ptr<Oper> oper;
        net::detail::weak_ptr<h2_stream> strm;

      public:
        response_impl(const response_impl&) = default;

        virtual ~response_impl() = default;

        virtual std::unique_ptr<response_type> make_unique() const override {
            return std::make_unique<response_impl>(*this);
        }
        virtual std::shared_ptr<response_type> make_shared() const override {
            return std::make_shared<response_impl>(*this);
        }

        virtual bool get_guard() const noexcept(true) override {
            return oper && !oper->io_cntl.goaway_sent() && strm;
        }

        const net::ip::tcp::socket* socket() const noexcept(true) override {
            return oper ? &oper->__M_stream : nullptr;
        }

      private:
        virtual net::io_context& do_get_associated_io_context() const override {
            if (do_expired()) {
                throw session_closed{};
            }
            return oper->cntl().get_associated_io_context();
        }

        virtual void do_terminate() override {
            if (oper) {
                oper->terminate_now();
            }
        }
        virtual void do_pause() override {
            if (strm) {
                ++strm->pause_vote;
            }
        }
        virtual void do_resume() override {
            if (strm && !--strm->pause_vote && !strm->is_resuming) {
                net::detail::scope_exit guard([strm = strm]() {
                    if (strm) {
                        strm->is_resuming = false;
                    }
                });
                strm->is_resuming = true;
                while (strm && !strm->pause_vote && !strm->buffered.empty()) {
                    session_type& ses = strm->session();
                    std::vector<unsigned char> b =
                        std::move(ses.buffered.front());
                    ses.buffered.pop();
                    on<ev::data_block>(ses, ses.request, response_impl(*this),
                                       b.data(), b.data() + b.size());
                }
                if (strm && !strm->pause_vote &&
                    oper->conn_settings.initial_window_size >
                        strm->client_wnd) {
                    assert(oper->create_WINDOW_UPDATE_frame_stream(
                               *strm, oper->conn_settings.initial_window_size -
                                          strm->client_wnd) ==
                           ErrorCodes::NO_ERROR);
                    oper->do_send();
                }
                if (strm && !strm->pause_vote && strm->stage == CompleteStage) {
                    session_type& ses = strm->session();
                    on<ev::message_complete>(ses, ses.request,
                                             response_impl(*this));
                }
            }
        }

        virtual bool do_streaming_would_block() noexcept(true) { return false; }
        // return 0 or positive for bytes pushed
        virtual std::size_t do_streaming_flush_header(status_code code,
                                                      fields_type&& fields) {
            ErrorCodes r = oper->create_HEADER_frame(0, *strm, code, fields);
            if (r == ErrorCodes::NO_ERROR) {
                oper->do_send();
            } else {
                __CHXNET_THROW_EC(make_ec(r));
            }
            return 0;
        }
        virtual std::size_t
        do_streaming_flush(std::vector<unsigned char>&& buffer) {
            guard();
            oper->create_DATA_frame(0, *strm,
                                    net::offset_carrier(std::move(buffer), 0));
            return 0;
        }
        virtual void do_streaming_commit() {
            guard();
            oper->create_DATA_frame(
                detail::Flags::END_STREAM, *strm,
                net::offset_carrier(net::const_buffer{}, 0));
        }

        virtual void do_end(status_code code, fields_type&& fields) {
            return resp(code, std::move(fields));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::const_buffer view) {
            return resp(code, std::move(fields),
                        net::offset_carrier(std::move(view), 0));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::string payload) {
            return resp(code, std::move(fields),
                        net::offset_carrier(std::move(payload), 0));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::vector<unsigned char> payload) {
            return resp(code, std::move(fields),
                        net::offset_carrier(std::move(payload), 0));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::vector<std::vector<unsigned char>> payload) {
            assert(false);
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::mapped_file mapped) {
            return do_end(code, std::move(fields),
                          net::carrier(std::move(mapped), 0, mapped.size()));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::carrier<net::mapped_file> mapped) {
            return resp(code, std::move(fields), std::move(mapped));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::vcarrier&& vc) {
            return resp(code, std::move(fields),
                        net::offset_carrier(std::move(vc), 0));
        }

        template <typename... Payloads>
        void resp(status_code code, fields_type&& fields,
                  Payloads&&... payloads) {
            if (get_guard()) {
                h2_stream& strm = *this->strm;
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
                    assert(this->strm);
                    oper->create_DATA_frame(
                        detail::Flags::END_STREAM, strm,
                        std::forward<Payloads>(payloads)...);
                    oper->do_send();
                }
                oper->largest_strm_id_processed =
                    std::max(oper->largest_strm_id_processed, strm_id);
            }
        }

        virtual bool do_expired() const noexcept(true) { return !strm; }
    };
};
}  // namespace chx::http::h2