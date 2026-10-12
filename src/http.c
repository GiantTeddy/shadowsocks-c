/*
 * http.c - Minimal HTTP proxy request parser (no I/O, no allocation)
 *
 * This file is part of shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "http.h"

static const char *http_methods[] = {
    "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT",
    "TRACE", NULL
};

/* Empty target means the effective request-target is "/". */
static const char *
http_effective_target(const http_request_t *req)
{
    return req->target[0] != '\0' ? req->target : "/";
}

static int
http_is_known_method(const char *method)
{
    for (int i = 0; http_methods[i] != NULL; i++) {
        if (strcmp(method, http_methods[i]) == 0)
            return 1;
    }
    return 0;
}

int
http_looks_like_request(const unsigned char *data, size_t len)
{
    if (data == NULL || len == 0)
        return 0;

    for (int i = 0; http_methods[i] != NULL; i++) {
        const char *method = http_methods[i];
        size_t mlen        = strlen(method);
        size_t cmp         = len < mlen ? len : mlen;

        if (memcmp(data, method, cmp) != 0)
            continue;

        /* Partial token: still could become this method. */
        if (len <= mlen)
            return 1;

        /* Full token must be followed by the request-line space. */
        if (data[mlen] == ' ')
            return 1;
    }
    return 0;
}

/*
 * Locate the header terminator. Prefers CRLFCRLF but accepts bare LFLF.
 * On success sets *hdr_end (offset of the terminator) and *hdr_len (total
 * request+header length including the terminator).
 */
static int
http_find_header_end(const char *data, size_t len, size_t *hdr_end, size_t *hdr_len)
{
    for (size_t i = 0; i < len; i++) {
        if (i + 3 < len &&
            data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            *hdr_end = i;
            *hdr_len = i + 4;
            return 1;
        }
        if (i + 1 < len && data[i] == '\n' && data[i + 1] == '\n') {
            *hdr_end = i;
            *hdr_len = i + 2;
            return 1;
        }
    }
    return 0;
}

static int
http_valid_host(const char *host, size_t len)
{
    if (len == 0 || len > MAX_HOSTNAME_LEN - 1)
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)host[i];
        /* Reject whitespace and control characters (and DEL). */
        if (c <= 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

/* Accepts a decimal port in [1, 65535] and normalizes it into `out`. */
static int
http_parse_port(const char *s, size_t len, char *out, size_t out_cap)
{
    unsigned long value = 0;

    if (len == 0 || len > 5)
        return 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return 0;
        value = value * 10 + (unsigned long)(s[i] - '0');
        if (value > 65535)
            return 0;
    }
    if (value == 0)
        return 0;
    if (snprintf(out, out_cap, "%lu", value) >= (int)out_cap)
        return 0;
    return 1;
}

/*
 * Parse "host[:port]" or "[ipv6][:port]" from a CONNECT target or a URI
 * authority. `default_port` is used when no ":" is present.
 */
static int
http_parse_authority(const char *s, size_t len, http_request_t *req, int default_port)
{
    if (len == 0)
        return 0;

    if (s[0] == '[') {
        size_t close = 1;
        while (close < len && s[close] != ']')
            close++;
        if (close >= len)
            return 0;

        size_t hlen = close - 1;
        if (!http_valid_host(s + 1, hlen))
            return 0;
        memcpy(req->host, s + 1, hlen);
        req->host[hlen] = '\0';

        if (close + 1 < len) {
            if (s[close + 1] != ':')
                return 0;
            if (!http_parse_port(s + close + 2, len - (close + 2),
                                 req->port, sizeof(req->port)))
                return 0;
        } else {
            if (snprintf(req->port, sizeof(req->port), "%d", default_port) >= (int)sizeof(req->port))
                return 0;
        }
        return 1;
    }

    size_t colon = (size_t)-1;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == ':')
            colon = i;
    }

    size_t hlen = (colon == (size_t)-1) ? len : colon;
    if (colon != (size_t)-1) {
        for (size_t i = 0; i < hlen; i++) {
            if (s[i] == ':')
                return 0; /* unbracketed IPv6 is not a valid authority */
        }
    }
    if (!http_valid_host(s, hlen))
        return 0;
    memcpy(req->host, s, hlen);
    req->host[hlen] = '\0';

    if (colon == (size_t)-1) {
        if (snprintf(req->port, sizeof(req->port), "%d", default_port) >= (int)sizeof(req->port))
            return 0;
    } else {
        if (!http_parse_port(s + colon + 1, len - colon - 1,
                             req->port, sizeof(req->port)))
            return 0;
    }
    return 1;
}

/* Look up and parse a Host header value into req->host/req->port. */
static int
http_parse_host_header(const char *data, size_t headers_off, size_t headers_end,
                       http_request_t *req, int default_port)
{
    size_t p = headers_off;

    while (p < headers_end) {
        size_t e = p;
        while (e < headers_end && data[e] != '\n')
            e++;

        size_t content_end = e;
        if (content_end > p && data[content_end - 1] == '\r')
            content_end--;

        size_t name_end = p;
        while (name_end < content_end && data[name_end] != ':')
            name_end++;

        if (name_end < content_end &&
            (name_end - p) == 4 && strncasecmp(data + p, "Host", 4) == 0) {
            size_t v = name_end + 1;
            while (v < content_end && (data[v] == ' ' || data[v] == '\t'))
                v++;
            size_t ve = content_end;
            while (ve > v && (data[ve - 1] == ' ' || data[ve - 1] == '\t'))
                ve--;
            return http_parse_authority(data + v, ve - v, req, default_port);
        }

        p = (e < headers_end) ? e + 1 : headers_end;
    }
    return 0;
}

static int
http_parse_non_connect(const char *data, size_t t_start, size_t tl,
                       size_t headers_off, size_t headers_end, http_request_t *req)
{
    const char *tgt = data + t_start;

    if (tl == 0)
        return 0;

    /* origin-form: /path[?query]; host comes from the Host header */
    if (tgt[0] == '/') {
        if (tl >= sizeof(req->target))
            return 0;
        memcpy(req->target, tgt, tl);
        req->target[tl] = '\0';
        return http_parse_host_header(data, headers_off, headers_end, req, 80);
    }

    /* absolute-form: http://host[:port]/path[?query] */
    if (tl >= 7 && strncasecmp(tgt, "http://", 7) == 0) {
        size_t auth_start = 7;
        size_t auth_end   = auth_start;
        while (auth_end < tl && tgt[auth_end] != '/' && tgt[auth_end] != '?' &&
               tgt[auth_end] != '#')
            auth_end++;

        if (!http_parse_authority(tgt + auth_start, auth_end - auth_start, req, 80))
            return 0;

        size_t plen = tl - auth_end;
        if (plen == 0) {
            req->target[0] = '/';
            req->target[1] = '\0';
        } else {
            if (plen >= sizeof(req->target))
                return 0;
            memcpy(req->target, tgt + auth_end, plen);
            req->target[plen] = '\0';
        }
        return 1;
    }

    /* Reject https:// and any other absolute-URI scheme, plus authority-form
     * and asterisk-form targets that this proxy does not support. */
    for (size_t i = 0; i + 2 < tl; i++) {
        if (tgt[i] == ':' && tgt[i + 1] == '/' && tgt[i + 2] == '/')
            return 0;
    }
    return 0;
}

enum http_parse_status
http_parse_request(const char *data, size_t len, http_request_t *req, size_t *need_more)
{
    size_t hdr_end = 0, hdr_len = 0;

    if (need_more != NULL)
        *need_more = 0;
    if (data == NULL || req == NULL)
        return HTTP_PARSE_ERROR;

    memset(req, 0, sizeof(*req));

    if (!http_find_header_end(data, len, &hdr_end, &hdr_len)) {
        if (len >= HTTP_MAX_HEADER_SIZE)
            return HTTP_PARSE_ERROR;
        if (need_more != NULL)
            *need_more = 1;
        return HTTP_PARSE_INCOMPLETE;
    }

    /* End of the request line. It may run right up to the terminator when the
     * request carries no headers. */
    size_t line_end = 0;
    while (line_end < hdr_end && data[line_end] != '\r' && data[line_end] != '\n')
        line_end++;
    if (line_end == 0)
        return HTTP_PARSE_ERROR;

    /* METHOD SP request-target SP HTTP-version */
    size_t m_end = 0;
    while (m_end < line_end && data[m_end] != ' ')
        m_end++;
    if (m_end == 0 || m_end >= line_end || m_end >= sizeof(req->method))
        return HTTP_PARSE_ERROR;
    memcpy(req->method, data, m_end);
    req->method[m_end] = '\0';
    if (!http_is_known_method(req->method))
        return HTTP_PARSE_ERROR;

    size_t t_start = m_end;
    while (t_start < line_end && data[t_start] == ' ')
        t_start++;
    size_t t_end = t_start;
    while (t_end < line_end && data[t_end] != ' ')
        t_end++;
    if (t_end == t_start)
        return HTTP_PARSE_ERROR;

    size_t v_start = t_end;
    while (v_start < line_end && data[v_start] == ' ')
        v_start++;
    if (v_start >= line_end)
        return HTTP_PARSE_ERROR;
    if (line_end - v_start < 5 || strncasecmp(data + v_start, "HTTP/", 5) != 0)
        return HTTP_PARSE_ERROR;

    req->is_connect = strcmp(req->method, "CONNECT") == 0;

    /* Offset of the first header line (skip the request line's CRLF/LF). */
    size_t headers_off = line_end + 1;
    if (data[line_end] == '\r' && headers_off < hdr_end && data[headers_off] == '\n')
        headers_off++;

    if (req->is_connect) {
        if (!http_parse_authority(data + t_start, t_end - t_start, req, 443))
            return HTTP_PARSE_ERROR;
        req->target[0] = '\0';
    } else {
        if (!http_parse_non_connect(data, t_start, t_end - t_start,
                                    headers_off, hdr_end, req))
            return HTTP_PARSE_ERROR;
    }

    req->header_len  = hdr_len;
    req->raw         = data;
    req->headers_off = headers_off;
    req->headers_end = hdr_end;
    return HTTP_PARSE_OK;
}

static int
http_header_should_remove(const char *name, size_t len)
{
    static const char *hop_by_hop[] = {
        "Connection", "Proxy-Connection", "Proxy-Authorization",
        "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Upgrade", NULL
    };

    for (int i = 0; hop_by_hop[i] != NULL; i++) {
        size_t nlen = strlen(hop_by_hop[i]);
        if (len == nlen && strncasecmp(name, hop_by_hop[i], nlen) == 0)
            return 1;
    }
    return 0;
}

static int
http_append(char *out, size_t out_cap, size_t *pos, const char *src, size_t len)
{
    if (len > out_cap - *pos)
        return 0;
    memcpy(out + *pos, src, len);
    *pos += len;
    return 1;
}

size_t
http_build_forward_request(const http_request_t *req, char *out, size_t out_cap)
{
    size_t pos = 0;

    if (req == NULL || out == NULL || out_cap == 0 ||
        req->is_connect || req->raw == NULL)
        return 0;

    /* Rewritten request line: origin-form for the upstream server. */
    if (!http_append(out, out_cap, &pos, req->method, strlen(req->method)) ||
        !http_append(out, out_cap, &pos, " ", 1) ||
        !http_append(out, out_cap, &pos, http_effective_target(req),
                     strlen(http_effective_target(req))) ||
        !http_append(out, out_cap, &pos, " HTTP/1.1\r\n", 11))
        return 0;

    int host_present = 0;
    size_t p = req->headers_off;

    while (p < req->headers_end) {
        size_t e = p;
        while (e < req->headers_end && req->raw[e] != '\n')
            e++;

        size_t content_end = e;
        if (content_end > p && req->raw[content_end - 1] == '\r')
            content_end--;

        size_t name_end = p;
        while (name_end < content_end && req->raw[name_end] != ':')
            name_end++;
        size_t name_len = name_end - p;

        if (name_len == 4 && strncasecmp(req->raw + p, "Host", 4) == 0)
            host_present = 1;

        if (!http_header_should_remove(req->raw + p, name_len)) {
            if (!http_append(out, out_cap, &pos, req->raw + p, content_end - p) ||
                !http_append(out, out_cap, &pos, "\r\n", 2))
                return 0;
        }

        p = (e < req->headers_end) ? e + 1 : req->headers_end;
    }

    if (!host_present) {
        if (!http_append(out, out_cap, &pos, "Host: ", 6) ||
            !http_append(out, out_cap, &pos, req->host, strlen(req->host)))
            return 0;
        if (strcmp(req->port, "80") != 0) {
            if (!http_append(out, out_cap, &pos, ":", 1) ||
                !http_append(out, out_cap, &pos, req->port, strlen(req->port)))
                return 0;
        }
        if (!http_append(out, out_cap, &pos, "\r\n", 2))
            return 0;
    }

    if (!http_append(out, out_cap, &pos, "Connection: close\r\n", 19) ||
        !http_append(out, out_cap, &pos, "\r\n", 2))
        return 0;

    return pos;
}
