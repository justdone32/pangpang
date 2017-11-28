#ifndef CREGEX_HPP
#define CREGEX_HPP

#include <regex.h>
#include <string>
#include <vector>

namespace hi {

    class cregex {
    public:
        cregex() = delete;

        cregex(const std::string& pattern, bool store_match = false) : reg(), ok(false) {
            this->ok = (regcomp(&this->reg, pattern.c_str(), store_match ? REG_EXTENDED : REG_EXTENDED | REG_NOSUB) == 0);
        }

        virtual~cregex() {
            if (ok)regfree(&this->reg);
        }

        bool match(const std::string& subject) {
            return this->ok && regexec(&this->reg, subject.c_str(), (size_t) 0, NULL, 0) == 0;
        }

        static bool match(const char *str, const char *pattern) {
            regex_t re;
            if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0)return false;

            int ret = regexec(&re, str, (size_t) 0, NULL, 0);
            regfree(&re);

            return ret == 0;
        }

    private:
        regex_t reg;
        bool ok;
    };
}

#endif /* CREGEX_HPP */

