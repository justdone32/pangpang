#ifndef CREGEX_HPP
#define CREGEX_HPP

#include <regex.h>
#include <string>
#include <vector>

namespace hi {

    class cregex {
    public:
        cregex() = delete;

        cregex(const std::string& pattern, bool store_match = true) : reg(), ok(false) {
            this->ok = (regcomp(&this->reg, pattern.c_str(), store_match ? REG_EXTENDED : REG_EXTENDED | REG_NOSUB) == 0);
        }

        virtual~cregex() {
            if (ok)regfree(&this->reg);
        }

        bool match(const std::string& subject) {
            return this->ok && regexec(&this->reg, subject.c_str(), (size_t) 0, NULL, 0) == 0;
        }

        bool match_and_get(const std::string& subject, std::vector<std::string>& matches, size_t n = 10) {
            bool result = false;
            regmatch_t m[n];
            if (this->ok && regexec(&this->reg, subject.c_str(), n, m, 0) == 0) {
                result = true;
                for (size_t i = 0, len = 0; i < n && m[i].rm_so != -1; ++i) {
                    len = m[i].rm_eo - m[i].rm_so;
                    matches.push_back(std::move(subject.substr(m[i].rm_so, len)));
                }
            }
            return result;
        }

        static bool match_and_get(const std::string& subject, const std::string& pattern, std::vector<std::string>& matches, size_t n = 10) {
            bool result = false;
            regex_t re;
            if (regcomp(&re, pattern.c_str(), REG_EXTENDED) == 0) {
                regmatch_t m[n];
                if (regexec(&re, subject.c_str(), n, m, 0) == 0) {
                    result = true;
                    for (size_t i = 0, len = 0; i < n && m[i].rm_so != -1; ++i) {
                        len = m[i].rm_eo - m[i].rm_so;
                        matches.push_back(std::move(subject.substr(m[i].rm_so, len)));
                    }
                }
                regfree(&re);
            }
            return result;
        }

        static bool match(const std::string& subject, const std::string& pattern) {
            bool result = false;
            regex_t re;
            if (regcomp(&re, pattern.c_str(), REG_EXTENDED | REG_NOSUB) == 0) {
                if (regexec(&re, subject.c_str(), (size_t) 0, NULL, 0) == 0) {
                    result = true;
                }
                regfree(&re);
            }
            return result;
        }

    private:
        regex_t reg;
        bool ok;
    };
}

#endif /* CREGEX_HPP */

