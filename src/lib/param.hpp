#ifndef PARAM_HPP
#define PARAM_HPP


#include <string>
#include <unordered_map>

namespace hi {

    static std::string trim(const std::string& s) {
        auto it = s.begin();
        while (it != s.end() && isspace(*it)) {
            it++;
        }
        auto rit = s.rbegin();
        while (rit.base() != it && isspace(*rit)) {
            rit++;
        }
        return std::string(it, rit.base());
    }

    static void parser_param(const std::string& data, std::unordered_map<std::string, std::string>& result, char c = '&', char cc = '=') {
        if (data.empty())return;
        size_t start = 0, p, q;
        while (true) {
            p = data.find(c, start);
            if (p == std::string::npos) {
                q = data.find(cc, start);
                if (q != std::string::npos) {
                    result[trim(data.substr(start, q - start))] = std::move(trim(data.substr(q + 1)));
                }
                break;
            } else {
                q = data.find(cc, start);
                if (q != std::string::npos) {
                    result[trim(data.substr(start, q - start))] = std::move(trim(data.substr(q + 1, p - q - 1)));
                }
                start = p + 1;
            }
        }
    }

    static void split(const std::string& s, char delim, std::vector<std::string>& v) {
        auto i = 0;
        auto pos = s.find(delim);
        while (pos != std::string::npos) {
            v.push_back(s.substr(i, pos - i));
            i = ++pos;
            pos = s.find(delim, pos);
            if (pos == std::string::npos)
                v.push_back(s.substr(i, s.length()));
        }
    }
}

#endif /* PARAM_HPP */

