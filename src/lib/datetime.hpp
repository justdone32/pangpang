#ifndef DATETIME_HPP
#define DATETIME_HPP

#include <time.h>
#include <regex>
#include <string>

namespace hi {
    //    static char *week[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    //    static char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
    //        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    static unsigned mday[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    std::string http_time(time_t *t) {
        struct tm * timeinfo = gmtime(t);
        char buffer [80] = {0};
        size_t n = strftime(buffer, 80, "%a, %d %b %Y %T GMT", timeinfo);
        return std::string(buffer, n);
    }

    time_t parse_http_time(u_char* value, size_t len) {
        u_char *p, *end;
        int month;
        uint day = 0, year = 0, hour = 0, min = 0, sec = 0;
        uint64_t time = 0;

        enum {
            no = 0,
            rfc822, /* Tue, 10 Nov 2002 23:50:13   */
            rfc850, /* Tuesday, 10-Dec-02 23:50:13 */
            isoc /* Tue Dec 10 23:50:13 2002    */
        } fmt;

        fmt = no;
        end = value + len;


        for (p = value; p < end; p++) {
            if (*p == ',') {
                break;
            }

            if (*p == ' ') {
                fmt = isoc;
                break;
            }
        }

        for (p++; p < end; p++) {
            if (*p != ' ') {
                break;
            }
        }

        if (end - p < 18) {
            return -1;
        }

        if (fmt != isoc) {
            if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
                return -1;
            }

            day = (*p - '0') * 10 + (*(p + 1) - '0');
            p += 2;

            if (*p == ' ') {
                if (end - p < 18) {
                    return -1;
                }
                fmt = rfc822;

            } else if (*p == '-') {
                fmt = rfc850;

            } else {
                return -1;
            }

            p++;
        }

        switch (*p) {

            case 'J':
                month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
                break;

            case 'F':
                month = 1;
                break;

            case 'M':
                month = *(p + 2) == 'r' ? 2 : 4;
                break;

            case 'A':
                month = *(p + 1) == 'p' ? 3 : 7;
                break;

            case 'S':
                month = 8;
                break;

            case 'O':
                month = 9;
                break;

            case 'N':
                month = 10;
                break;

            case 'D':
                month = 11;
                break;

            default:
                return -1;
        }

        p += 3;

        if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
            return -1;
        }

        p++;

        if (fmt == rfc822) {
            if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
                    || *(p + 2) < '0' || *(p + 2) > '9'
                    || *(p + 3) < '0' || *(p + 3) > '9') {
                return -1;
            }

            year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
                    + (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
            p += 4;

        } else if (fmt == rfc850) {
            if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
                return -1;
            }

            year = (*p - '0') * 10 + (*(p + 1) - '0');
            year += (year < 70) ? 2000 : 1900;
            p += 2;
        }

        if (fmt == isoc) {
            if (*p == ' ') {
                p++;
            }

            if (*p < '0' || *p > '9') {
                return -1;
            }

            day = *p++ -'0';

            if (*p != ' ') {
                if (*p < '0' || *p > '9') {
                    return -1;
                }

                day = day * 10 + (*p++ -'0');
            }

            if (end - p < 14) {
                return -1;
            }
        }

        if (*p++ != ' ') {
            return -1;
        }

        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
            return -1;
        }

        hour = (*p - '0') * 10 + (*(p + 1) - '0');
        p += 2;

        if (*p++ != ':') {
            return -1;
        }

        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
            return -1;
        }

        min = (*p - '0') * 10 + (*(p + 1) - '0');
        p += 2;

        if (*p++ != ':') {
            return -1;
        }

        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
            return -1;
        }

        sec = (*p - '0') * 10 + (*(p + 1) - '0');

        if (fmt == isoc) {
            p += 2;

            if (*p++ != ' ') {
                return -1;
            }

            if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
                    || *(p + 2) < '0' || *(p + 2) > '9'
                    || *(p + 3) < '0' || *(p + 3) > '9') {
                return -1;
            }

            year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
                    + (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
        }

        if (hour > 23 || min > 59 || sec > 59) {
            return -1;
        }

        if (day == 29 && month == 1) {
            if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
                return -1;
            }

        } else if (day > mday[month]) {
            return -1;
        }

        /*
         * shift new year to March 1 and start months from 1 (not 0),
         * it is needed for Gauss' formula
         */

        if (--month <= 0) {
            month += 12;
            year -= 1;
        }

        /* Gauss' formula for Gregorian days since March 1, 1 BC */

        time = (uint64_t) (
                /* days in years including leap years since March 1, 1 BC */

                365 * year + year / 4 - year / 100 + year / 400

                /* days before the month */

                + 367 * month / 12 - 30

                /* days before the day */

                + day - 1

                /*
                 * 719527 days were between March 1, 1 BC and March 1, 1970,
                 * 31 and 28 days were in January and February 1970
                 */

                - 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;

        return (time_t) time;
    }

}

#endif /* DATETIME_HPP */

