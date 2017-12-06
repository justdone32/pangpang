#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>

#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/event_compat.h>
#include <event2/event_struct.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/http_compat.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/thread.h>
#include <utility>
#include <list>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <iostream>
#include <functional>
#include <map>
#include <unordered_map>


#include "inc/request.hpp"
#include "inc/response.hpp"
#include "inc/servlet.hpp"
#include "inc/mustache.hpp"
#include "lib/module_class.hpp"
#include "lib/lrucache.hpp"
#include "lib/redis.hpp"
#include "lib/json11.hpp"
#include "lib/param.hpp"
#include "lib/MPFDParser-1.1.1/Parser.h"
#include "lib/datetime.hpp"
#include "lib/cregex.hpp"
#include "lib/gzip.hpp"





#define PANGPANG                "pangpang/0.8.2"
#define CONFIG_FILE             "conf/pangpang.json"
#define PATTERN_FILE            "conf/pattern.conf"
#define PID_FILE                "logs/pangpang.pid"
#define LOGS_ACCESS_FILE        "logs/access.log"
#define LOGS_ERROR_FILE         "logs/error.log"
#define SESSION_ID_NAME         "SESSIONID"

struct cache_ele_t {
    int status = 200;
    time_t t;
    std::string content_type, content;
};

struct route_ele_t {
    std::shared_ptr<hi::cregex> cregex;
    std::shared_ptr<hi::module_class<hi::servlet>> module;
    std::shared_ptr<hi::cache::lru_cache<std::string, cache_ele_t>> cache;
    size_t expires;
    bool session, gzip;
};

typedef void (*CB_FUNC)(struct evhttp_request *, void *);
static CB_FUNC CB = 0;
struct event_config *EV_CONFIG = 0;
static struct event_base *BASE = 0;
static struct evhttp *SERVER = 0;
static SSL_CTX *CTX = 0;
static EC_KEY *ECDH = 0;

static bool DAEMON = false,
        ENABLE_SSL = false,
        ENABLE_STATIC_SERVER = false,
        ENABLE_LIST_DIRECTORY = false,
        ENABLE_SESSION = false,
        ENABLE_GZIP = true,
        ENABLE_MULTIPROCESS = true,
        CPU_AFFINITY = true;

static int PORT = 9000, TIMEOUT = 60,
        REDIS_PORT = 6379,
        GZIP_LEVEL = Z_DEFAULT_COMPRESSION;
static std::string HOST = "127.0.0.1",
        REDIS_HOST = "127.0.0.1",
        ROOT = "html",
        DEFAULT_CONTENT_TYPE = "text/html",
        CERT_CERTIFICATE_FILE,
        CERT_PRIVATE_KEY_FILE,
        TEMP_DIRECTORY = "temp";

static size_t MAX_HEADERS_SIZE = 8192,
        MAX_BODY_SIZE = 1048567,
        SESSION_EXPIRES = 600,
        GZIP_MIN_SIZE = 1024,
        GZIP_MAX_SIZE = 2048,
        PROCESS_SIZE = 0,
        UPDATE_INTERVAL = 3600;

static std::vector<pid_t> PIDS;

static std::list<std::shared_ptr<route_ele_t>> PLUGIN;
static std::unordered_map<std::string, std::string> MIME;
static std::shared_ptr<hi::redis> REDIS;

static bool initailize_config(const std::string& path);
static void signal_normal_cb(int sig);
static void generic_request_handler(struct evhttp_request *req, void *arg);


static void *my_zeroing_malloc(size_t howmuch);
static void ssl_setup();
static struct bufferevent* bevcb(struct event_base *base, void *arg);
static int server_setup_certs(SSL_CTX *ctx,
        const char *certificate_chain,
        const char *private_key);
static int initailize_ssl(SSL_CTX *ctx, EC_KEY *ecdh, struct evhttp *server, const char *certificate_chain,
        const char *private_key);

static bool is_file(const std::string& s);
static bool is_dir(const std::string& s);
static std::string list_dir(const std::string& dir);
static void read_file(const std::string& path, std::string& out);
static const std::string& content_type(const std::string& path);
static std::string md5(const std::string& str);
static std::string random_string(const std::string& s);
static void forker(size_t nprocesses, struct event_base* base);
static void worker();
static void stoper();
static size_t get_cpu_count();
static int process_bind_cpu(pid_t pid, int cpu);

int main(int argc, char** argv) {
    if (!initailize_config(CONFIG_FILE)) {
        exit(EXIT_FAILURE);
    }

    if (DAEMON && daemon(1, 0)) {
        exit(EXIT_FAILURE);
    }

    {
        std::ofstream pid_file(PID_FILE);
        pid_file << getpid();
    }

    EV_CONFIG = event_config_new();
    event_config_set_flag(EV_CONFIG, EVENT_BASE_FLAG_NOLOCK);
    event_config_set_flag(EV_CONFIG, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);


    BASE = event_base_new_with_config(EV_CONFIG);


    SERVER = evhttp_new(BASE);


    if (ENABLE_SSL) {
        if (!initailize_ssl(CTX, ECDH, SERVER, CERT_CERTIFICATE_FILE.c_str(), CERT_PRIVATE_KEY_FILE.c_str())) {
            goto stop_server;
        }
    }



    evhttp_bind_socket(SERVER, HOST.c_str(), PORT);

    CB = generic_request_handler;

    evhttp_set_gencb(SERVER, CB, NULL);
    evhttp_set_default_content_type(SERVER, DEFAULT_CONTENT_TYPE.c_str());
    evhttp_set_timeout(SERVER, TIMEOUT);
    evhttp_set_max_headers_size(SERVER, MAX_HEADERS_SIZE);
    evhttp_set_max_body_size(SERVER, MAX_BODY_SIZE);


    signal(SIGHUP, signal_normal_cb);
    signal(SIGTERM, signal_normal_cb);
    signal(SIGINT, signal_normal_cb);
    signal(SIGQUIT, signal_normal_cb);
    signal(SIGKILL, signal_normal_cb);


    if (ENABLE_MULTIPROCESS) {

        if (PROCESS_SIZE == 0) {
            PROCESS_SIZE = get_cpu_count() - 1;
        }
        forker(PROCESS_SIZE, BASE);
    }


    worker();

stop_server:
    stoper();

    return 0;
}

static bool initailize_config(const std::string& path) {
    if (is_file(CONFIG_FILE) && is_file(PATTERN_FILE)) {
        std::string json_content;
        read_file(path, json_content);
        if (!json_content.empty()) {
            std::string err;
            json11::Json conf = json11::Json::parse(json_content, err);
            if (err.empty()) {
                DAEMON = conf["daemon"].bool_value();
                ENABLE_MULTIPROCESS = conf["multiprocess"]["enable"].bool_value();
                if (ENABLE_MULTIPROCESS) {
                    int process_len = conf["multiprocess"]["size"].int_value();
                    if (process_len >= 0) {
                        PROCESS_SIZE = static_cast<size_t> (process_len);
                    } else {
                        PROCESS_SIZE = 0;
                    }
                    CPU_AFFINITY = conf["multiprocess"]["cpu_affinity"].bool_value();
                }
                HOST = conf["host"].string_value();
                PORT = conf["port"].int_value();
                ENABLE_SSL = conf["ssl"]["enable"].bool_value();
                CERT_CERTIFICATE_FILE = conf["ssl"]["cert"].string_value();
                CERT_PRIVATE_KEY_FILE = conf["ssl"]["key"].string_value();
                TEMP_DIRECTORY = conf["temp_directory"].string_value();
                MAX_HEADERS_SIZE = static_cast<size_t> (conf["max_headers_size"].number_value());
                MAX_BODY_SIZE = static_cast<size_t> (conf["max_body_size"].number_value());
                TIMEOUT = conf["timeout"].int_value();
                UPDATE_INTERVAL = static_cast<size_t> (conf["update_interval"].number_value());

                std::ifstream is(PATTERN_FILE);
                std::string line;
                std::unordered_map<std::string, std::string> pattern;
                while (std::getline(is, line)) {
                    if (line.front() != ';' && !line.empty()) {
                        hi::parser_param(line, pattern);
                    }
                }
                for (auto& item : conf["route"].array_items()) {
                    std::string pattern_name = item["pattern"].string_value(), pattern_value;
                    if (pattern.find(pattern_name) != pattern.end()) {
                        pattern_value = pattern[pattern_name];
                        auto tmp = std::make_shared<route_ele_t>();
                        tmp->cregex = std::move(std::make_shared<hi::cregex>(pattern_value, false));
                        tmp->module = std::move(std::make_shared<hi::module_class < hi::servlet >> (item["module"].string_value()));
                        if (item["cache"]["enable"].bool_value()) {
                            tmp->cache = std::move(std::make_shared<hi::cache::lru_cache < std::string, cache_ele_t >> (static_cast<size_t> (item["cache"]["size"].number_value())));
                            tmp->expires = static_cast<size_t> (item["cache"]["expires"].number_value());
                        }
                        tmp->session = item["session"].bool_value();
                        tmp->gzip = item["gzip"].bool_value();
                        PLUGIN.push_back(std::move(tmp));
                    }
                }
                ENABLE_STATIC_SERVER = conf["static_server"]["enable"].bool_value();
                if (ENABLE_STATIC_SERVER) {
                    ROOT = conf["static_server"]["root"].string_value();
                    DEFAULT_CONTENT_TYPE = conf["static_server"]["default_content_type"].string_value();
                    for (auto &item : conf["static_server"]["mime"].array_items()) {
                        MIME[item["extension"].string_value()] = item["content_type"].string_value();
                    }
                    ENABLE_LIST_DIRECTORY = conf["static_server"]["list_directory"].bool_value();
                }
                ENABLE_SESSION = conf["session"]["enable"].bool_value();
                if (ENABLE_SESSION) {
                    REDIS_HOST = conf["session"]["host"].string_value();
                    REDIS_PORT = conf["session"]["port"].int_value();
                    REDIS = std::move(std::make_shared<hi::redis>());
                    REDIS->connect(REDIS_HOST, REDIS_PORT);
                    if (!REDIS->is_connected()) {
                        ENABLE_SESSION = false;
                    }
                }
                ENABLE_GZIP = conf["gzip"]["enable"].bool_value();
                if (ENABLE_GZIP) {
                    GZIP_MIN_SIZE = static_cast<size_t> (conf["gzip"]["min_size"].number_value());
                    GZIP_MAX_SIZE = static_cast<size_t> (conf["gzip"]["max_size"].number_value());
                    GZIP_LEVEL = conf["gzip"]["level"].int_value();
                    if (GZIP_LEVEL < Z_DEFAULT_COMPRESSION || GZIP_LEVEL > Z_BEST_COMPRESSION) {
                        GZIP_LEVEL = Z_DEFAULT_COMPRESSION;
                    }
                }
                return true;
            }
        }
    }
    return false;
}

static void *my_zeroing_malloc(size_t howmuch) {
    return calloc(1, howmuch);
}

static void ssl_setup() {
    signal(SIGPIPE, SIG_IGN);
    CRYPTO_set_mem_functions(my_zeroing_malloc, realloc, free);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static struct bufferevent* bevcb(struct event_base *base, void *arg) {
    struct bufferevent* r;
    SSL_CTX *ctx = (SSL_CTX *) arg;

    r = bufferevent_openssl_socket_new(base,
            -1,
            SSL_new(ctx),
            BUFFEREVENT_SSL_ACCEPTING,
            BEV_OPT_CLOSE_ON_FREE);
    return r;
}

static int server_setup_certs(SSL_CTX *ctx,
        const char *certificate_chain,
        const char *private_key) {
    if (1 != SSL_CTX_use_certificate_chain_file(ctx, certificate_chain)) {
        return 0;
    }

    if (1 != SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM)) {
        return 0;
    }

    if (1 != SSL_CTX_check_private_key(ctx)) {
        return 0;
    }
    return 1;
}

static int initailize_ssl(SSL_CTX *ctx, EC_KEY *ecdh, struct evhttp *server, const char *certificate_chain,
        const char *private_key) {
    ssl_setup();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        return 0;
    }
    SSL_CTX_set_options(ctx,
            SSL_OP_SINGLE_DH_USE |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_NO_SSLv2);
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        SSL_CTX_free(ctx);
        return 0;
    }
    if (1 != SSL_CTX_set_tmp_ecdh(ctx, ecdh)) {
        SSL_CTX_free(ctx);
        EC_KEY_free(ecdh);
        return 0;
    }

    if (!server_setup_certs(ctx, certificate_chain, private_key)) {
        SSL_CTX_free(ctx);
        EC_KEY_free(ecdh);
        return 0;
    }
    evhttp_set_bevcb(server, bevcb, ctx);
    return 1;
}

static void signal_normal_cb(int sig) {
    struct timeval delay = {1, 0};
    switch (sig) {
        case SIGTERM:
        case SIGHUP:
        case SIGQUIT:
        case SIGINT:
        case SIGKILL:
            if (BASE&&!event_base_loopexit(BASE, &delay)) {
            }
            break;
    }
}

static void generic_request_handler(struct evhttp_request *ev_req, void *arg) {
    struct evbuffer *ev_res = evhttp_request_get_output_buffer(ev_req);
    struct evkeyvalq *ev_output_headers = evhttp_request_get_output_headers(ev_req),
            *ev_input_headers = evhttp_request_get_input_headers(ev_req);
    const struct evhttp_uri *ev_uri = evhttp_request_get_evhttp_uri(ev_req);

    hi::request req;
    hi::response res;

    req.uri = evhttp_uri_get_path(ev_uri);

    auto item_iterator = std::find_if(PLUGIN.begin(), PLUGIN.end(), [&](std::shared_ptr<route_ele_t>& i) {
        return i->cregex->match(req.uri);
    });
    if (item_iterator != PLUGIN.end()) {
        auto item = *item_iterator;
        std::string md5_key;
        if (item->cache) {
            md5_key = md5(evhttp_request_get_uri(ev_req));
            if (item->cache->exists(md5_key)) {
                const cache_ele_t& cache_ele = item->cache->get(md5_key);
                const char* if_modified_since = evhttp_find_header(ev_input_headers, "If-Modified-Since");
                if (if_modified_since) {
                    time_t if_modified_since_time = hi::parse_http_time((u_char*) if_modified_since, strlen(if_modified_since));
                    if (if_modified_since_time == cache_ele.t) {
                        evhttp_send_reply(ev_req, 304, "Not Modified", ev_res);
                        return;
                    }
                }

                time_t now = time(NULL);
                if (difftime(now, cache_ele.t) >= item->expires) {
                    item->cache->erase(md5_key);
                } else {
                    const char *gzip_header = evhttp_find_header(ev_input_headers, "Accept-Encoding"),
                            *content = cache_ele.content.c_str();
                    size_t content_len = cache_ele.content.size();
                    if (gzip::is_compressed(content, content_len)) {
                        if (gzip_header) {
                            res.headers.insert(std::make_pair("Content-Encoding", "gzip"));
                            res.content = cache_ele.content;
                        } else {
                            res.content = gzip::decompress(content, content_len);
                        }
                    } else {
                        if (gzip_header && ENABLE_GZIP && item->gzip && content_len >= GZIP_MIN_SIZE && content_len <= GZIP_MAX_SIZE) {
                            res.content = gzip::compress(content, content_len, GZIP_LEVEL);
                            res.headers.insert(std::make_pair("Content-Encoding", "gzip"));
                        } else {
                            res.content = cache_ele.content;
                        }
                    }

                    res.status = cache_ele.status;
                    res.headers.find("Content-Type")->second = cache_ele.content_type;
                    res.status = cache_ele.status;

                    for (auto&header : res.headers) {
                        evhttp_add_header(ev_output_headers, header.first.c_str(), header.second.c_str());
                    }
                    goto done;
                }
            }
        }
        auto instance = std::move(item->module->make_obj());
        if (instance) {
            req.client = ev_req->remote_host;
            const char* param = evhttp_uri_get_query(ev_uri);
            if (param) {
                req.param = param;
                struct evkeyvalq param_list;
                evhttp_parse_query_str(param, &param_list);
                for (struct evkeyval* p = param_list.tqh_first; p; p = p->next.tqe_next) {
                    req.form.insert(std::make_pair(p->key, p->value));
                }
                evhttp_clear_headers(&param_list);
            }

            const char* user_agent = evhttp_find_header(ev_req->input_headers, "User-Agent");
            req.user_agent = user_agent ? user_agent : "xxx";

            enum evhttp_cmd_type req_method = evhttp_request_get_command(ev_req);
            switch (req_method) {
                case EVHTTP_REQ_GET:req.method = "GET";
                    break;
                case EVHTTP_REQ_POST:req.method = "POST";
                    break;
                case EVHTTP_REQ_HEAD:req.method = "HEAD";
                    break;
                case EVHTTP_REQ_DELETE:req.method = "DELETE";
                    break;
                case EVHTTP_REQ_PUT:req.method = "PUT";
                    break;
                case EVHTTP_REQ_OPTIONS:req.method = "OPTIONS";
                    break;
                case EVHTTP_REQ_TRACE:req.method = "TRACE";
                    break;
                case EVHTTP_REQ_CONNECT:req.method = "CONNECT";
                    break;
                case EVHTTP_REQ_PATCH:req.method = "PATCH";
                    break;
                default:req.method = "unknown";
                    break;
            }

            for (struct evkeyval *header = ev_input_headers->tqh_first; header; header = header->next.tqe_next) {
                req.headers[header->key] = header->value;
            }

            const char* cookie = evhttp_find_header(ev_input_headers, "Cookie");
            if (cookie)hi::parser_param(cookie, req.cookies, '&', '=');

            const char* input_content_type = evhttp_find_header(ev_input_headers, "Content-Type");
            if (input_content_type && req_method == EVHTTP_REQ_POST) {
                struct evbuffer *buf = evhttp_request_get_input_buffer(ev_req);
                size_t buf_size = evbuffer_get_length(buf);
                char buf_data[buf_size + 1];
                size_t n = evbuffer_remove(buf, buf_data, buf_size);
                if (n > 0 && strcmp("application/x-www-form-urlencoded", input_content_type) == 0) {
                    struct evkeyvalq param_list;
                    evhttp_parse_query_str(buf_data, &param_list);
                    for (struct evkeyval* p = param_list.tqh_first; p; p = p->next.tqe_next) {
                        req.form.insert(std::make_pair(p->key, p->value));
                    }
                    evhttp_clear_headers(&param_list);
                } else if (n > 0 && strstr(input_content_type, "multipart/form-data")&&(is_dir(TEMP_DIRECTORY)
                        || mkdir(TEMP_DIRECTORY.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0)) {
                    try {
                        std::shared_ptr<MPFD::Parser> POSTParser(new MPFD::Parser());
                        POSTParser->SetTempDirForFileUpload(TEMP_DIRECTORY);
                        POSTParser->SetUploadedFilesStorage(MPFD::Parser::StoreUploadedFilesInFilesystem);
                        POSTParser->SetMaxCollectedDataLength(MAX_BODY_SIZE);
                        POSTParser->SetContentType(input_content_type);
                        POSTParser->AcceptSomeData(buf_data, n);
                        auto fields = POSTParser->GetFieldsMap();
                        for (auto &item : fields) {
                            if (item.second->GetType() == MPFD::Field::TextType) {
                                req.form.insert(std::make_pair(item.first, item.second->GetTextTypeContent()));
                            } else {
                                std::string upload_file_name = item.second->GetFileName(), ext;
                                std::string::size_type p = upload_file_name.find_last_of(".");
                                if (p != std::string::npos) {
                                    ext = upload_file_name.substr(p);
                                }
                                std::string temp_file = TEMP_DIRECTORY + "/" + random_string(req.client + item.second->GetFileName()).append(ext);
                                rename(item.second->GetTempFileName().c_str(), temp_file.c_str());
                                req.form.insert(std::make_pair(item.first, temp_file));
                            }
                        }

                    } catch (MPFD::Exception& err) {
                        res.content = err.GetError();
                        res.status = 500;
                        goto done;
                    }
                }
            }

            std::string SESSION_ID_VALUE;
            if (item->session && ENABLE_SESSION) {
                if (req.cookies.find(SESSION_ID_NAME) != req.cookies.end()) {
                    SESSION_ID_VALUE = req.cookies[SESSION_ID_NAME ];
                    if (!REDIS->exists(SESSION_ID_VALUE)) {
                        REDIS->hset(SESSION_ID_VALUE, SESSION_ID_NAME, SESSION_ID_VALUE);
                        REDIS->expire(SESSION_ID_VALUE, SESSION_EXPIRES);
                        res.session[SESSION_ID_NAME] = SESSION_ID_VALUE;
                    } else {
                        REDIS->hgetall(SESSION_ID_VALUE, req.session);
                    }
                } else {
                    std::string session_cookie_string(SESSION_ID_NAME);
                    session_cookie_string.append("=")
                            .append(random_string(req.client))
                            .append(";Path=/;");
                    const char* host = evhttp_uri_get_host(ev_uri);
                    if (host) {
                        session_cookie_string.append("Domain=").append(host);
                    }
                    evhttp_add_header(ev_output_headers, "Set-Cookie", session_cookie_string.c_str());
                }
            }

            instance->handler(req, res);

            if (ENABLE_GZIP && item->gzip) {
                const char *gzip_header = evhttp_find_header(ev_input_headers, "Accept-Encoding"),
                        *content = res.content.c_str();
                size_t content_len = res.content.size();
                if (gzip_header && content_len >= GZIP_MIN_SIZE && content_len <= GZIP_MAX_SIZE) {
                    res.headers.insert(std::make_pair("Content-Encoding", "gzip"));
                    res.content = gzip::compress(content, content_len, GZIP_LEVEL);
                }
            }



            for (auto&header : res.headers) {
                evhttp_add_header(ev_output_headers, header.first.c_str(), header.second.c_str());
            }

            if (item->cache) {
                cache_ele_t cache_new_ele;
                cache_new_ele.content = res.content;
                cache_new_ele.status = res.status;
                cache_new_ele.content_type = res.headers.find("Content-Type")->second;
                cache_new_ele.t = time(NULL);
                item->cache->put(md5_key, cache_new_ele);
                evhttp_add_header(ev_output_headers, "Last-Modified", hi::http_time(&cache_new_ele.t).c_str());
            }
            if (item->session && ENABLE_SESSION&&!SESSION_ID_VALUE.empty()) {
                REDIS->hmset(SESSION_ID_VALUE, res.session);
            }
        }
    } else if (ENABLE_STATIC_SERVER) {
        std::string full_path = ROOT + req.uri;
        struct stat st;
        int s_t = stat(full_path.c_str(), &st);
        if (s_t >= 0) {
            if (S_ISDIR(st.st_mode)) {
                if (ENABLE_LIST_DIRECTORY) {
                    res.content = list_dir(full_path);
                    res.status = 200;
                } else {
                    res.content = "<p style='text-align:center;margin:100px;'>403 Forbidden</p>";
                    res.status = 403;
                }
            } else if (S_ISREG(st.st_mode)) {
                const char* if_modified_since = evhttp_find_header(evhttp_request_get_input_headers(ev_req), "If-Modified-Since");
                if (if_modified_since) {
                    time_t if_modified_since_time = hi::parse_http_time((u_char*) if_modified_since, strlen(if_modified_since));
                    if (if_modified_since_time == st.st_mtim.tv_sec) {
                        evhttp_send_reply(ev_req, 304, "Not Modified", ev_res);
                        return;
                    }
                }
                int file = open(full_path.c_str(), O_RDONLY);
                if (file < 0) {
                    evhttp_send_error(ev_req, 500, NULL);
                    return;
                }
                evbuffer_add_file(ev_res, file, 0, st.st_size);
                evhttp_add_header(ev_output_headers, "Content-Type", content_type(full_path).c_str());
                evhttp_add_header(ev_output_headers, "Last-Modified", hi::http_time(&st.st_mtim.tv_sec).c_str());
                evhttp_add_header(ev_output_headers, "Server", PANGPANG);
                evhttp_send_reply(ev_req, 200, "OK", ev_res);
                return;
            }
        }
    }
done:
    evhttp_add_header(ev_output_headers, "Server", PANGPANG);
    evhttp_add_header(ev_output_headers, "Connection", "keep-alive");
    evbuffer_add(ev_res, res.content.c_str(), res.content.size());
    evhttp_send_reply(ev_req, res.status, NULL, ev_res);

}

static bool is_file(const std::string& s) {
    struct stat st;
    return stat(s.c_str(), &st) >= 0 && S_ISREG(st.st_mode);
}

static bool is_dir(const std::string& s) {
    struct stat st;
    return stat(s.c_str(), &st) >= 0 && S_ISDIR(st.st_mode);
}

static std::string list_dir(const std::string& path) {

    std::string list_content = "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<style>"
            "</style>"
            "</head>"
            "<body>"
            "<div>"
            "<h3>Directory index</h3>"
            "<ul>"
            "{{#list}}"
            "<li>"
            "<a real_path='{{real_path}}' href=\"{{href}}\">{{name}}</a>"
            "</li>"
            "{{/list}}"
            "</ul>"
            "</div>"
            "</body>"
            "</html>";
    kainjow::mustache::mustache render_engine(list_content);
    kainjow::mustache::data list{kainjow::mustache::data::type::list};

    DIR * dir = opendir(path.c_str());
    std::string tmp_path;
    size_t n = ROOT.size();
    struct dirent * entry;
    bool b = path.back() != '/';
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            tmp_path = b ? path + "/" + entry->d_name : path + entry->d_name;
            auto p = tmp_path.find(ROOT);
            kainjow::mustache::data item;
            item.set("name", entry->d_name);
            item.set("href", tmp_path.substr(p + n));
            item.set("real_path", tmp_path);
            list.push_back(item);
        }
    }
    closedir(dir);
    return render_engine.render({"list", list});

}

static void read_file(const std::string& path, std::string& out) {
    std::ifstream fs(path, std::ios_base::binary);
    fs.seekg(0, std::ios_base::end);
    auto size = fs.tellg();
    fs.seekg(0);
    out.resize(static_cast<size_t> (size));
    fs.read(&out[0], size);
}

static const std::string& content_type(const std::string& path) {
    auto p = path.find_last_of(".");
    const std::string ext = path.substr(p + 1);
    if (MIME.find(ext) != MIME.end()) {
        return MIME[ext];
    }
    return MIME["*"];
}

static std::string md5(const std::string& str) {
    unsigned char digest[16] = {0};
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, str.c_str(), str.size());
    MD5_Final(digest, &ctx);

    unsigned char tmp[32] = {0}, *dst = &tmp[0], *src = &digest[0];
    unsigned char hex[] = "0123456789abcdef";
    int len = 16;
    while (len--) {
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0xf];
    }

    return std::string((char*) tmp, 32);
}

static std::string random_string(const std::string& s) {
    time_t now = time(NULL);
    char* now_str = ctime(&now);
    return md5(s + now_str);
}

static void forker(size_t nprocesses, struct event_base* base) {
    static size_t t = 0;
    if (nprocesses > 0) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
        } else if (pid == 0) {
            //Child
            event_reinit(BASE);
            ++t;
            worker();
            stoper();
            raise(SIGHUP);
        } else if (pid > 0) {
            //parent 
            PIDS.push_back(pid);
            if (t != nprocesses - 1) {
                forker(nprocesses - 1, base);
            } else {
                int status;
                pid_t ppid = getpid();
                PIDS.push_back(ppid);
                waitpid(-ppid, &status, WNOHANG);
                if (CPU_AFFINITY) {
                    size_t cpu_size = get_cpu_count();
                    for (size_t i = 0; i < cpu_size; ++i) {
                        if (i <= PIDS.size() - 1) {
                            process_bind_cpu(PIDS[i], i);
                        }
                    }
                }
                worker();
                killpg(ppid, SIGHUP);
            }
        }
    }
}

static void worker() {
    event_base_dispatch(BASE);
}

static void stoper() {
    evhttp_free(SERVER);
    event_base_free(BASE);
    event_config_free(EV_CONFIG);
    if (ECDH) {
        EC_KEY_free(ECDH);
    }
    if (CTX) {
        SSL_CTX_free(CTX);
    }
    PLUGIN.clear();
    MIME.clear();
    if (is_file(PID_FILE)) {
        remove(PID_FILE);
    }
}

static size_t get_cpu_count() {
    return (size_t) sysconf(_SC_NPROCESSORS_CONF);
}

static int process_bind_cpu(pid_t pid, int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(pid, sizeof (cpu_set_t), &set);
}