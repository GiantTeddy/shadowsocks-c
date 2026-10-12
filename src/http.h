/*
 * http.h - Minimal HTTP proxy request parser (no I/O, no allocation)
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

#ifndef _HTTP_H
#define _HTTP_H

#include <stddef.h>

#include "netutils.h" /* MAX_HOSTNAME_LEN */

#define HTTP_METHOD_MAX_LEN 16
#define HTTP_PORT_MAX_LEN   8
#define HTTP_TARGET_MAX_LEN (MAX_HOSTNAME_LEN + 1 + 1024)

/*
 * The parser refuses to buffer an unbounded request line. The local relay
 * buffer is SOCKET_BUF_SIZE (16 KiB); anything larger is malformed or hostile.
 */
#define HTTP_MAX_HEADER_SIZE (32 * 1024)

enum http_parse_status {
    HTTP_PARSE_OK = 0,
    HTTP_PARSE_INCOMPLETE,
    HTTP_PARSE_ERROR
};

typedef struct {
    char method[HTTP_METHOD_MAX_LEN];  /* uppercase, NUL-terminated */
    char host[MAX_HOSTNAME_LEN + 1];   /* IPv6 hosts have no brackets */
    char port[HTTP_PORT_MAX_LEN];      /* decimal string, 1..65535 */
    char target[HTTP_TARGET_MAX_LEN];  /* origin-form path+query, "/" default */
    int  is_connect;
    size_t header_len;                 /* request + headers incl. final CRLFCRLF */

    /*
     * Header rewriting needs the original bytes. `raw` points into the caller's
     * buffer and must stay valid until http_build_forward_request() returns.
     * [headers_off, headers_end) bounds the header block, excluding the
     * request line and the terminating CRLFCRLF.
     */
    const char *raw;
    size_t headers_off;
    size_t headers_end;
} http_request_t;

/*
 * Return 1 when `data` is a prefix of a known HTTP method token. Used to
 * distinguish HTTP from SOCKS5 on the very first client byte(s).
 */
int http_looks_like_request(const unsigned char *data, size_t len);

/*
 * Parse a full request (request line + headers). Returns HTTP_PARSE_INCOMPLETE
 * when the header terminator has not arrived yet (and sets *need_more to a
 * non-zero hint). Returns HTTP_PARSE_ERROR for malformed input.
 */
enum http_parse_status http_parse_request(const char *data, size_t len,
                                          http_request_t *req, size_t *need_more);

/*
 * Rewrite a non-CONNECT request as an origin-form HTTP/1.1 request suitable
 * for forwarding to the origin server: ensures a Host header, strips the
 * proxy/hop-by-hop headers and appends "Connection: close". Only the headers
 * are written; the caller appends any body bytes after req->header_len.
 * Returns the number of bytes written, or 0 when it does not fit / on error.
 */
size_t http_build_forward_request(const http_request_t *req, char *out, size_t out_cap);

#endif // _HTTP_H
