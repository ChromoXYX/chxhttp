#include "./log.hpp"

#include <chx/net.hpp>
#include <queue>
#include <thread>

static std::atomic_int sink = ATOMIC_VAR_INIT(STDERR_FILENO);

struct ring {
    std::queue<std::string> collect;

    alignas(64) std::mutex mu;
    alignas(64) std::atomic_flag flag = ATOMIC_FLAG_INIT;
    std::atomic_flag quit = ATOMIC_FLAG_INIT;

    void push(std::string&& str) {
        {
            std::lock_guard lg(mu);
            collect.emplace(std::move(str));
            flag.test_and_set(std::memory_order_relaxed);
        }
        flag.notify_all();
    }
    std::queue<std::string> pop() {
        flag.wait(false);
        std::queue<std::string> r;
        {
            std::lock_guard lg(mu);
            r = std::move(collect);
            flag.clear(std::memory_order_relaxed);
        }
        return std::move(r);
    }

    static std::jthread worker;
} static ring;

std::jthread ring::worker([]() {
    sigset_t sig = {};
    sigaddset(&sig, SIGINT);
    pthread_sigmask(SIG_BLOCK, &sig, nullptr);
    while (!::ring.quit.test()) {
        auto&& q = ::ring.pop();
        while (!q.empty()) {
            // fwrite(q.front().c_str(), 1, q.front().size(), stderr);
            ssize_t r = write(sink.load(std::memory_order_acquire),
                              q.front().c_str(), q.front().size());
            q.pop();
        }
    }
});

void log_backend(std::string&& s) { ring.push(std::move(s)); }
void terminate_log_backend() noexcept(true) {
    ring.quit.test_and_set();
    ring.flag.test_and_set();
    ring.flag.notify_all();
}

void set_log_sink(int fd) noexcept(true) {
    int old = sink.exchange(fd, std::memory_order_acquire);
    if (old >= 3) {
        ::close(old);
    }
}
int get_log_sink() noexcept(true) {
    return sink.load(std::memory_order_acquire);
}
