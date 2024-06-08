#include "./log.hpp"
#include "./global_conf.hpp"

#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>
#include <glob.h>

namespace net = chx::net;

constexpr static boost::json::parse_options json_opt{
    .allow_comments = true, .allow_trailing_commas = true};

struct pushd {
    std::filesystem::path before;
    pushd(const std::filesystem::path& after)
        : before(std::filesystem::current_path()) {
        std::filesystem::current_path(after);
    }
    ~pushd() { std::filesystem::current_path(before); }
};

static void listen_list_append_item(global_conf::server_conf& conf,
                                    const boost::json::value& item) {
    if (item.is_number()) {
        conf.listen_list.emplace_back(net::ip::tcp::v4(), item.as_int64());
    } else if (item.is_string()) {
        const auto& str = item.as_string();
        if (str.empty()) {
            throw std::runtime_error("Invalid listen address");
        }
        std::size_t idx = str.find_last_of(":");
        if (idx == str.npos) {
            throw std::runtime_error("Invalid listen address");
        }
        std::string ip_view;
        if (str[0] == '[') {
            if (idx <= 2) {
                throw std::runtime_error("Invalid listen address");
            }
            ip_view = str.subview(1, idx - 2);
        } else {
            ip_view = str.subview(0, idx);
        }
        unsigned short port = 0;
        std::from_chars_result ret =
            std::from_chars(str.begin() + idx + 1, str.end(), port);
        if (ret.ec == std::errc::result_out_of_range ||
            ret.ec == std::errc::invalid_argument) {
            throw std::runtime_error("Invalid listen address");
        }
        if (ret.ptr != str.end()) {
            throw std::runtime_error("Invalid listen address");
        }
        conf.listen_list.emplace_back(net::ip::address::from_string(ip_view),
                                      port);
    } else {
        auto& item_obj = item.as_object();
        conf.listen_list.emplace_back(
            net::ip::address::from_string(
                item_obj.at("address").as_string().subview()),
            item_obj.at("port").as_int64());
    }
}

static void listen_list_append(global_conf::server_conf& conf,
                               const boost::json::value& l) {
    if (l.is_array()) {
        for (const auto& item : l.as_array()) {
            listen_list_append_item(conf, item);
        }
    } else {
        listen_list_append_item(conf, l);
    }
}

static void srv_list_append(const boost::json::value& srv_node) {
    const auto& srv_obj = srv_node.as_object();
    auto& srv_conf = global_conf.server_list.emplace_back();

    if (srv_obj.contains("http_version")) {
        srv_conf.http_version = srv_obj.at("http_version").as_int64();
    }
    if (srv_conf.http_version != 1 || srv_conf.http_version != 2) {
        throw std::runtime_error("Invalid http version");
    }
    listen_list_append(srv_conf, srv_obj.at("listen"));
    if (srv_obj.contains("server_name")) {
        auto& srv_name_node = srv_obj.at("server_name");
        if (srv_name_node.is_string()) {
            srv_conf.server_name.emplace_back(srv_name_node.as_string());
        } else {
            for (const auto& srv_name : srv_name_node.as_array()) {
                srv_conf.server_name.emplace_back(srv_name.as_string());
            }
        }
    }
    if (srv_obj.contains("root")) {
        srv_conf.root_dir = srv_obj.at("root").as_string();
    }
    if (srv_obj.contains("index")) {
        auto& index = srv_obj.at("index");
        if (index.is_array()) {
            for (auto& i : index.as_array()) {
                srv_conf.index_list.emplace_back(i.as_string());
            }
        } else {
            srv_conf.index_list.emplace_back(index.as_string());
        }
    }
    if (srv_obj.contains("ssl")) {
        auto& ssl_obj = srv_obj.at("ssl").as_object();
        srv_conf.ssl_conf.enable = true;
        srv_conf.ssl_conf.certificate = ssl_obj.at("certificate").as_string();
        srv_conf.ssl_conf.certificate_key =
            ssl_obj.at("certificate_key").as_string();
    } else if (srv_conf.http_version == 2) {
        throw std::runtime_error("http/2 need tls");
    }
}

static void json_safe_insert(boost::json::object& target,
                             const boost::json::object& source) {
    for (const auto& [k, v] : source) {
        if (auto ite = target.find(k);
            ite != target.end() && ite->value().is_array()) {
            if (v.is_array()) {
                const auto& va = v.as_array();
                auto& ta = ite->value().as_array();
                ta.insert(ta.end(), va.begin(), va.end());
            } else {
                ite->value().as_array().emplace_back(v);
            }
        } else {
            target.insert_or_assign(k, v);
        }
    }
}

static std::vector<std::string> scan_files(std::string_view pattern) {
    glob64_t st = {};
    int _r = glob64(
        pattern.data(), GLOB_PERIOD | GLOB_NOMAGIC,
        [](const char* filename, int e) -> int {
            log_warn(
                CHXLOG_STR("glob64 cannot open configure file %s, error: %s\n"),
                std::string_view{filename}, std::string_view{strerror(e)});
            return -1;
        },
        &st);
    if (_r == 0) {
        std::vector<std::string> ret;
        for (std::size_t i = 0; i < st.gl_pathc; ++i) {
            ret.emplace_back(std::filesystem::canonical(st.gl_pathv[i]));
        }
        globfree64(&st);
        return std::move(ret);
    } else {
        globfree64(&st);
        switch (_r) {
        case GLOB_ABORTED: {
            throw std::runtime_error("glob64 failed to scan configure files");
        }
        case GLOB_NOSPACE: {
            throw std::bad_alloc();
        }
        case GLOB_NOMATCH: {
            return {};
        }
        default: {
            throw std::runtime_error(
                "glob64 failed to scan configure files due to unknown error");
        }
        }
    }
}

static void json_dfs(boost::json::value& node, std::filesystem::path filepath) {
    pushd __pushd(filepath.parent_path());
    if (node.is_object()) {
        auto& obj = node.as_object();
        if (obj.contains("include")) {
            const auto inc_node = obj.at("include");
            obj.erase("include");
            auto imported_node =
                boost::json::value(boost::json::object_kind_t{});
            std::vector<std::string> import_targets;
            if (inc_node.is_string()) {
                import_targets = scan_files(inc_node.as_string());
            } else {
                auto& inc_arr = inc_node.as_array();
                const auto& working_dir = std::filesystem::current_path();
                for (auto& i : inc_arr) {
                    auto&& v = scan_files(i.as_string());
                    import_targets.insert(import_targets.end(),
                                          std::move_iterator(v.begin()),
                                          std::move_iterator(v.end()));
                }
            }
            import_targets.erase(
                std::unique(import_targets.begin(), import_targets.end()),
                import_targets.end());
            for (const auto& path : import_targets) {
                auto ifs = std::ifstream(path);
                auto __nn = boost::json::parse(ifs, {}, json_opt);
                json_dfs(__nn, path);
                const auto& __nno = __nn.as_object();
                imported_node.as_object().insert(__nno.begin(), __nno.end());
            }

            json_safe_insert(obj, imported_node.as_object());
        }
    }
    if (node.is_object()) {
        for (auto& [k, v] : node.as_object()) {
            json_dfs(v, filepath);
        }
    } else if (node.is_array()) {
        for (auto& item : node.as_array()) {
            json_dfs(item, filepath);
        }
    }
}

static void readin_and_process(const std::string& filename) {
    std::filesystem::path path = std::filesystem::canonical(filename);
    log_info(CHXLOG_STR("Reading configure file at %s\n"), path.c_str());

    std::ifstream ifs(path);
    auto rootv = boost::json::parse(ifs, {}, json_opt);
    json_dfs(rootv, path);

    const auto& rootn = rootv.as_object();
    const auto& srv_node = rootn.at("server");
    if (srv_node.is_object()) {
        for (const auto& [k, v] : srv_node.as_object()) {
            srv_list_append(v);
        }
    } else {
        for (const auto& v : srv_node.as_array()) {
            srv_list_append(v);
        }
    }
}

static void get_os_info() {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1) {
        throw std::runtime_error(chx::log::format(
            CHXLOG_STR("failed to get pagesize: %s"), strerror(errno)));
    }
    global_conf.os.page_size = page_size;
}

void application_init(int argc, char** argv) {
    namespace po = boost::program_options;
    po::options_description desc("chxhttp");
    desc.add_options()(
        "config,c",
        po::value<std::string>()->default_value("/etc/chxhttp/config.json"),
        "Set path to config file")("help,h", "Print help information");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.contains("help")) {
        std::cout << desc << "\n";
        terminate_log_backend();
        std::exit(0);
    }
    readin_and_process(vm.at("config").as<std::string>());

    get_os_info();
}
