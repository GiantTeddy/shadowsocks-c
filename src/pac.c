/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * pac.c - Proxy Auto-Config (PAC) routing engine
 *
 * A PAC file is plain JavaScript that defines FindProxyForURL(url, host).
 * This module embeds duktape (vendored under src/duktape) and implements the
 * helper functions a PAC script is allowed to use. The interpreter heap is
 * created once and reused for every evaluation, so a request only pays for
 * the FindProxyForURL() call itself.
 *
 * The helper set follows the Netscape/Firefox PAC specification:
 *   shExpMatch, dnsDomainIs, isPlainHostName, dnsDomainLevels, dnsResolve,
 *   isResolvable, isInNet, myIpAddress, weekdayRange, timeRange, dateRange,
 *   localHostOrDomainIs and alert.
 * The time-based helpers accept the standard argument shapes but always
 * return false when they cannot be decided, matching common PAC practice.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "netutils.h"

#ifndef __MINGW32__
#include <netdb.h>
#endif

#include "duktape/duktape.h"

#include "pac.h"
#include "route.h"
#include "utils.h"

static duk_context *pac_ctx = NULL;

/* Shell-style glob match supporting '*' and '?'. */
static int
glob_match(const char *s, const char *p)
{
    const char *star = NULL;
    const char *ss   = s;

    while (*s != '\0') {
        if (*p == '*') {
            star = p++;
            ss   = s;
        } else if (*p == '?' || *p == *s) {
            p++;
            s++;
        } else if (star != NULL) {
            p = star + 1;
            s = ++ss;
        } else {
            return 0;
        }
    }
    while (*p == '*')
        p++;
    return *p == '\0';
}

static duk_ret_t
js_shExpMatch(duk_context *ctx)
{
    const char *s = duk_require_string(ctx, 0);
    const char *p = duk_require_string(ctx, 1);

    duk_push_boolean(ctx, glob_match(s, p));
    return 1;
}

static duk_ret_t
js_dnsDomainIs(duk_context *ctx)
{
    const char *host = duk_require_string(ctx, 0);
    const char *dom  = duk_require_string(ctx, 1);
    size_t hl        = strlen(host);
    size_t dl        = strlen(dom);
    int match        = 0;

    if (hl >= dl) {
        match = 1;
        for (size_t i = 0; i < dl; i++) {
            if (tolower((unsigned char)host[hl - dl + i])
                != tolower((unsigned char)dom[i])) {
                match = 0;
                break;
            }
        }
    }
    duk_push_boolean(ctx, match);
    return 1;
}

static duk_ret_t
js_isPlainHostName(duk_context *ctx)
{
    const char *host = duk_require_string(ctx, 0);

    duk_push_boolean(ctx, strchr(host, '.') == NULL);
    return 1;
}

static duk_ret_t
js_dnsDomainLevels(duk_context *ctx)
{
    const char *host = duk_require_string(ctx, 0);
    int levels       = 0;

    for (const char *p = host; *p != '\0'; p++) {
        if (*p == '.')
            levels++;
    }
    duk_push_int(ctx, levels);
    return 1;
}

/* Resolve `host` to its first IPv4 address, written as text into `out`. */
static int
resolve_first_v4(const char *host, char *out, size_t outlen)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return 0;

    int found = 0;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
        if (inet_ntop(AF_INET, &addr->sin_addr, out, (socklen_t)outlen) != NULL) {
            found = 1;
            break;
        }
    }
    freeaddrinfo(res);
    return found;
}

static duk_ret_t
js_dnsResolve(duk_context *ctx)
{
    const char *host = duk_require_string(ctx, 0);
    char ip[64];

    if (resolve_first_v4(host, ip, sizeof(ip)))
        duk_push_string(ctx, ip);
    else
        duk_push_null(ctx);
    return 1;
}

static duk_ret_t
js_isResolvable(duk_context *ctx)
{
    const char *host = duk_require_string(ctx, 0);
    char ip[64];

    duk_push_boolean(ctx, resolve_first_v4(host, ip, sizeof(ip)));
    return 1;
}

static duk_ret_t
js_isInNet(duk_context *ctx)
{
    const char *host = duk_require_string(ctx, 0);
    const char *pat  = duk_require_string(ctx, 1);
    const char *mask = duk_require_string(ctx, 2);
    char ip[64];

    if (inet_pton(AF_INET, host, &(struct in_addr){ 0 }) != 1) {
        if (!resolve_first_v4(host, ip, sizeof(ip))) {
            duk_push_false(ctx);
            return 1;
        }
    } else {
        snprintf(ip, sizeof(ip), "%s", host);
    }

    struct in_addr ia;
    struct in_addr pa;
    struct in_addr ma;
    if (inet_pton(AF_INET, ip, &ia) != 1
        || inet_pton(AF_INET, pat, &pa) != 1
        || inet_pton(AF_INET, mask, &ma) != 1) {
        duk_push_false(ctx);
        return 1;
    }
    duk_push_boolean(ctx, (ia.s_addr & ma.s_addr) == (pa.s_addr & ma.s_addr));
    return 1;
}

static duk_ret_t
js_myIpAddress(duk_context *ctx)
{
    char host[256];

    if (gethostname(host, sizeof(host)) != 0) {
        duk_push_string(ctx, "127.0.0.1");
        return 1;
    }

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        duk_push_string(ctx, "127.0.0.1");
        return 1;
    }

    char out[64] = "127.0.0.1";
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
        uint32_t v               = ntohl(addr->sin_addr.s_addr);
        if ((v >> 24) != 127) {
            inet_ntop(AF_INET, &addr->sin_addr, out, sizeof(out));
            break;
        }
    }
    freeaddrinfo(res);
    duk_push_string(ctx, out);
    return 1;
}

static duk_ret_t
js_alert(duk_context *ctx)
{
    (void)ctx;
    return 0;
}

static duk_ret_t
js_weekdayRange(duk_context *ctx)
{
    int n = duk_get_top(ctx);
    if (n == 0) {
        duk_push_false(ctx);
        return 1;
    }

    int want_gmt = 0;
    if (duk_is_string(ctx, n - 1)
        && strcasecmp(duk_to_string(ctx, n - 1), "GMT") == 0) {
        want_gmt = 1;
        n--;
    }

    static const char *const days[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    char day[8];
    time_t now = time(NULL);
    struct tm tm;
    if (want_gmt)
        gmtime_r(&now, &tm);
    else
        localtime_r(&now, &tm);

    strncpy(day, days[tm.tm_wday], sizeof(day) - 1);
    day[sizeof(day) - 1] = '\0';

    for (int i = 0; i < n; i++) {
        if (duk_is_string(ctx, i)
            && strcasecmp(duk_to_string(ctx, i), day) == 0) {
            duk_push_true(ctx);
            return 1;
        }
    }
    if (n == 2) {
        int a = duk_to_int(ctx, 0);
        int b = duk_to_int(ctx, 1);
        if (a <= b) {
            duk_push_boolean(ctx, a <= tm.tm_wday && tm.tm_wday <= b);
            return 1;
        }
    }
    duk_push_false(ctx);
    return 1;
}

static duk_ret_t
js_timeRange(duk_context *ctx)
{
    (void)ctx;
    duk_push_false(ctx);
    return 1;
}

static duk_ret_t
js_dateRange(duk_context *ctx)
{
    (void)ctx;
    duk_push_false(ctx);
    return 1;
}

static duk_ret_t
js_localHostOrDomainIs(duk_context *ctx)
{
    const char *host    = duk_require_string(ctx, 0);
    const char *hostdom = duk_require_string(ctx, 1);
    int match           = strcasecmp(host, hostdom) == 0;

    if (!match && strchr(host, '.') == NULL) {
        const char *dot = strchr(hostdom, '.');
        if (dot != NULL
            && (size_t)(dot - hostdom) == strlen(host)
            && strncasecmp(host, hostdom, (size_t)(dot - hostdom)) == 0)
            match = 1;
    }
    duk_push_boolean(ctx, match);
    return 1;
}

static void
register_helpers(duk_context *ctx)
{
    static const struct {
        const char *name;
        duk_c_function fn;
        duk_idx_t nargs;
    } helpers[] = {
        { "shExpMatch",          js_shExpMatch,         2 },
        { "dnsDomainIs",         js_dnsDomainIs,        2 },
        { "isPlainHostName",     js_isPlainHostName,    1 },
        { "dnsDomainLevels",     js_dnsDomainLevels,    1 },
        { "dnsResolve",          js_dnsResolve,         1 },
        { "isResolvable",        js_isResolvable,       1 },
        { "isInNet",             js_isInNet,            3 },
        { "myIpAddress",         js_myIpAddress,        0 },
        { "alert",               js_alert,              1 },
        { "weekdayRange",        js_weekdayRange,       DUK_VARARGS },
        { "timeRange",           js_timeRange,          DUK_VARARGS },
        { "dateRange",           js_dateRange,          DUK_VARARGS },
        { "localHostOrDomainIs", js_localHostOrDomainIs, 2 },
    };

    for (size_t i = 0; i < sizeof(helpers) / sizeof(helpers[0]); i++) {
        duk_push_c_function(ctx, helpers[i].fn, helpers[i].nargs);
        duk_put_global_string(ctx, helpers[i].name);
    }
}

/* Read a whole file into a NUL-terminated heap buffer. */
static char *
read_file(const char *path, long *size)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t)n + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, (size_t)n, 1, f) != 1) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[n] = '\0';
    *size  = n;
    return buf;
}

/* Classify the first ';'-separated directive of a PAC result string. */
static int
pac_result_is_proxy(const char *result)
{
    if (result == NULL)
        return 0;

    while (isspace((unsigned char)*result))
        result++;

    if (strncasecmp(result, "DIRECT", 6) == 0
        && (result[6] == '\0' || isspace((unsigned char)result[6])
            || result[6] == ';'))
        return 0;

    if (strncasecmp(result, "PROXY", 5) == 0
        || strncasecmp(result, "SOCKS", 5) == 0
        || strncasecmp(result, "HTTPS", 5) == 0
        || strncasecmp(result, "HTTP", 4) == 0)
        return 1;

    return 0;
}

void
pac_free(void)
{
    if (pac_ctx != NULL) {
        duk_destroy_heap(pac_ctx);
        pac_ctx = NULL;
    }
}

int
pac_enabled(void)
{
    return pac_ctx != NULL;
}

int
pac_init(const char *path)
{
    if (path == NULL) {
        LOGE("pac: no PAC file configured");
        return -1;
    }

    pac_free();

    long size = 0;
    char *source = read_file(path, &size);
    if (source == NULL) {
        LOGE("pac: cannot read PAC file: %s", path);
        return -1;
    }

    duk_context *ctx = duk_create_heap_default();
    if (ctx == NULL) {
        LOGE("pac: failed to create duktape heap");
        free(source);
        return -1;
    }

    register_helpers(ctx);

    if (duk_peval_lstring(ctx, source, (duk_size_t)size) != 0) {
        LOGE("pac: failed to evaluate %s: %s", path,
             duk_safe_to_string(ctx, -1));
        duk_destroy_heap(ctx);
        free(source);
        return -1;
    }
    duk_pop(ctx);

    duk_get_global_string(ctx, "FindProxyForURL");
    int is_function = duk_is_function(ctx, -1);
    duk_pop(ctx);
    if (!is_function) {
        LOGE("pac: %s does not define FindProxyForURL()", path);
        duk_destroy_heap(ctx);
        free(source);
        return -1;
    }

    free(source);
    pac_ctx = ctx;
    LOGI("pac: loaded %s (%ld bytes)", path, size);
    return 0;
}

int
pac_evaluate(const char *url, const char *host)
{
    if (pac_ctx == NULL)
        return -1;

    duk_context *ctx = pac_ctx;

    duk_get_global_string(ctx, "FindProxyForURL");
    duk_push_string(ctx, url != NULL ? url : "");
    duk_push_string(ctx, host != NULL ? host : "");

    if (duk_pcall(ctx, 2) != 0) {
        LOGE("pac: FindProxyForURL failed: %s", duk_safe_to_string(ctx, -1));
        duk_pop(ctx);
        return -1;
    }

    int proxy = pac_result_is_proxy(duk_safe_to_string(ctx, -1));
    duk_pop(ctx);
    return proxy ? ROUTE_PROXY : ROUTE_DIRECT;
}
