# pangpang
High performance web server and application server for c++

## wiki
[wiki](https://github.com/webcpp/pangpang/wiki)


# hello,world

## cpp servlet class

```cpp
#include "servlet.hpp"
namespace hi{
class hello : public servlet {
    public:

        void handler(request& req, response& res) {
            res.headers.find("Content-Type")->second = "text/plain;charset=UTF-8";
            res.content = "hello,world";
            res.status = 200;
        }

    };
}

extern "C" hi::servlet* create() {
    return new hi::hello();
}

extern "C" void destroy(hi::servlet* p) {
    delete p;
}

```

## cpp compile

```
g++ -std=c++11 -I/usr/local/pangpang/include  -shared -fPIC hello.cpp -o hello.so
install hello.so /usr/local/pangpang/mod

```

# Dependency
- linux
- gcc,g++(c++11)
- hiredis-devel
- libevent-devel(2.0.21+,require 2.1.8+ if enable https )

## centos
```
sudo yum install gcc gcc-c++ make pcre-devel zlib-devel openssl-devel hiredis-devel libevent-devel

```
## ubuntu
```
sudo apt-get install build-essential libpcre3-dev zlib1g-dev libssl-dev libhiredis-dev libevent-dev 

```

# Installation
`make`  and  `sudo make install` and `sudo systemctl daemon-reload` . prefix=`/usr/local/pangpang`.

# Configure
see `conf/pangpang.json`

## Run
`sudo systemctl enable pangpang`

`sudo systemctl (start|stop|restart|status) pangpang`

## Configure example
see `conf/pangpang.json` and `conf/pattern.conf`
### Base configure
```json
{
    "daemon": true,
    "multiprocess": {
        "enable": true,
        "cpu_affinity": true,
        "size": 1
    },
    "host": "127.0.0.1",
    "port": 9000,
    "ssl": {
        "enable": false,
        "cert": "",
        "key": ""
    },
    "max_headers_size": 8192,
    "max_body_size": 1048567,
    "timeout": 60,
    "gzip": {
        "enable": true,
        "min_size": 1024,
        "max_size": 2048,
        "level": -1
    },
    "session": {
        "enable": true,
        "host": "127.0.0.1",
        "port": 6379,
        "expires": 600
    },
    "temp_directory": "temp",
    "route": [{
            "pattern": "hello",
            "max_match_size": 0,
            "module": "mod/hello.so",
            "cache": {
                "enable": false,
                "expires": 300,
                "size": 30
            },
            "session": false,
            "header": false,
            "cookie": false,
            "gzip": false
        },
        {
            "pattern": "form",
            "max_match_size": 3,
            "module": "mod/form.so",
            "cache": {
                "enable": false,
                "expires": 300,
                "size": 30
            },
            "session": false,
            "header": true,
            "cookie": true,
            "gzip": false
        },
        {
            "pattern": "session",
            "max_match_size": 0,
            "module": "mod/session.so",
            "cache": {
                "enable": false,
                "expires": 300,
                "size": 30
            },
            "session": true,
            "header": false,
            "cookie": true,
            "gzip": false
        }
    ],
    "static_server": {
        "enable": true,
        "root": "html",
        "default_content_type": "text/html",
        "list_directory": true,
        "mime": [{
                "extension": "html",
                "content_type": "text/html"
            }, {
                "extension": "txt",
                "content_type": "text/plain"
            }, {
                "extension": "js",
                "content_type": "application/x-javascript"
            },
            {
                "extension": "css",
                "content_type": "text/css"
            },
            {
                "extension": "jpg",
                "content_type": "image/jpeg"
            },
            {
                "extension": "jpeg",
                "content_type": "image/jpeg"
            },
            {
                "extension": "gif",
                "content_type": "image/gif"
            },
            {
                "extension": "png",
                "content_type": "image/png"
            },
            {
                "extension": "ico",
                "content_type": "image/x-icon"
            },
            {
                "extension": "json",
                "content_type": "application/json"
            },
            {
                "extension": "zip",
                "content_type": "application/zip"
            },
            {
                "extension": "*",
                "content_type": "application/octet-stream"
            }
        ]
    }
}

```
### Route pattern configure
```
hello       =       ^/hello/?([0-9a-z]?)?$
form        =       /form
session     =       /session

```

