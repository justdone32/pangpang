#ifndef CREGEX_HPP
#define CREGEX_HPP

#include <regex.h>
#include <pcre.h>
#include <string>
#include <list>

namespace hi {

    class cpcre {
    public:
        cpcre() = delete;

        cpcre(const std::string& pattern) : reg(0), reg_extra(0) {
            const char *error;
            int erroffset;
            this->reg = pcre_compile(pattern.c_str(), 0, &error, &erroffset, NULL);
            if (!this->reg) {
                this->reg_extra = pcre_study(this->reg, 0, &error);
            }
        }

        virtual~cpcre() {
            if (this->reg)pcre_free(this->reg);
            if (this->reg_extra)pcre_free_study(this->reg_extra);
        }

        bool match(const std::string& subject, std::list<std::string>& matches, size_t n = 30) {
            bool result = false;
            int ovector[n];
            int rc = pcre_exec(this->reg, this->reg_extra, subject.c_str(), subject.size(), 0, 0, ovector, n);
            if (rc >= 0) {
                result = true;
                int start, len;
                for (int i = 0; i < rc; i++) {
                    start = ovector[2 * i];
                    len = ovector[2 * i + 1] - start;
                    matches.push_back(std::move(subject.substr(start, len)));
                }

            }
            return result;
        }

    private:
        pcre* reg;
        pcre_extra *reg_extra;
    };

    class cposix {
    public:

        cposix() = delete;

        cposix(const std::string& pattern) : reg(), ok(false) {
            this->ok = (regcomp(&this->reg, pattern.c_str(), REG_EXTENDED) == 0);
        }

        virtual~cposix() {
            if (this->ok)regfree(&this->reg);
        }

        bool match(const std::string& subject, std::list<std::string>& matches, size_t n = 30) {
            bool result = false;
            if (n > 1) {
                regmatch_t m[n];
                if (this->ok && regexec(&this->reg, subject.c_str(), n, m, 0) == 0) {
                    result = true;
                    for (size_t i = 0, len = 0; i < n && m[i].rm_so != -1; ++i) {
                        len = m[i].rm_eo - m[i].rm_so;
                        matches.push_back(std::move(subject.substr(m[i].rm_so, len)));
                    }
                }
            }

            return result;
        }
    private:
        regex_t reg;
        bool ok;
    };


#ifdef USE_POSIX_REGEX
    typedef cposix cregex;
#else
    typedef cpcre cregex;
#endif

}

#endif /* CREGEX_HPP */

