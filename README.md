# pangpang
web server and application server for c++

# hello,world

## cpp servlet class

```
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

## Run
`sudo systemctl enable pangpang`

`sudo systemctl (start|stop|restart|status) pangpang`

