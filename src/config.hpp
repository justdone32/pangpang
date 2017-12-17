#ifndef CONFIG_HPP
#define CONFIG_HPP

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
#include <sys/mman.h>

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
#include "lib/zlog/zlog.h"

#define PANGPANG                "pangpang/0.9.0"
#define CONFIG_FILE             "conf/pangpang.json"
#define PATTERN_FILE            "conf/pattern.conf"
#define ZLOG_CONFIG_FILE        "conf/zlog.conf"
#define PID_FILE                "logs/pangpang.pid"
#define LOGS_ACCESS_FILE        "logs/access.log"
#define LOGS_ERROR_FILE         "logs/error.log"
#define SESSION_ID_NAME         "SESSIONID"

namespace pangpang {

    struct cache_ele_t {
        int status = 200;
        time_t t;
        bool gzip = false;
        std::string content_type, content;
    };

    struct route_ele_t {
        std::shared_ptr<hi::cregex> cregex;
        std::shared_ptr<hi::module_class<hi::servlet>> module;
        std::shared_ptr<hi::cache::lru_cache<std::string, cache_ele_t>> cache;
        size_t expires, max_match_size;
        bool session, gzip, header, cookie, log;
    };

    struct config {
        bool DAEMON = false,
                ENABLE_SSL = false,
                ENABLE_STATIC_SERVER = false,
                ENABLE_LIST_DIRECTORY = false,
                ENABLE_SESSION = false,
                ENABLE_GZIP = true,
                ENABLE_MULTIPROCESS = true,
                CPU_AFFINITY = true,
                ENABLE_LOG = FALSE;

        int PORT = 9000, TIMEOUT = 60,
                REDIS_PORT = 6379,
                GZIP_LEVEL = Z_DEFAULT_COMPRESSION;
        std::string HOST = "127.0.0.1",
                REDIS_HOST = "127.0.0.1",
                ROOT = "html",
                DEFAULT_CONTENT_TYPE = "text/html",
                CERT_CERTIFICATE_FILE,
                CERT_PRIVATE_KEY_FILE,
                TEMP_DIRECTORY = "temp";

        size_t MAX_HEADERS_SIZE = 8192,
                MAX_BODY_SIZE = 1048567,
                SESSION_EXPIRES = 600,
                GZIP_MIN_SIZE = 1024,
                GZIP_MAX_SIZE = 2048,
                PROCESS_SIZE = 0;

        std::vector<pid_t> PIDS;

        std::list<std::shared_ptr<route_ele_t>> PLUGIN;
        std::unordered_map<std::string, std::string> MIME;
        std::shared_ptr<hi::redis> REDIS;
    };
}

#endif /* CONFIG_HPP */

