#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "http.h"

static void
test_looks_like_request(void)
{
    assert(http_looks_like_request((const unsigned char *)"G", 1) == 1);
    assert(http_looks_like_request((const unsigned char *)"GE", 2) == 1);
    assert(http_looks_like_request((const unsigned char *)"GET ", 4) == 1);
    assert(http_looks_like_request((const unsigned char *)"CONNECT ", 8) == 1);
    assert(http_looks_like_request((const unsigned char *)"POST / HTTP/1.1", 14) == 1);
    assert(http_looks_like_request((const unsigned char *)"X", 1) == 0);
    assert(http_looks_like_request((const unsigned char *)"POSTX", 5) == 0);
    assert(http_looks_like_request((const unsigned char *)"", 0) == 0);
}

static void
test_connect_hostname(void)
{
    const char *msg = "CONNECT example.com:443 HTTP/1.1\r\n"
                      "Host: example.com:443\r\n\r\n";
    http_request_t req;
    size_t need_more = 0;

    assert(http_parse_request(msg, strlen(msg), &req, &need_more) == HTTP_PARSE_OK);
    assert(req.is_connect == 1);
    assert(strcmp(req.method, "CONNECT") == 0);
    assert(strcmp(req.host, "example.com") == 0);
    assert(strcmp(req.port, "443") == 0);
    assert(req.header_len == strlen(msg));
}

static void
test_connect_ipv6(void)
{
    const char *msg = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n";
    http_request_t req;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(req.is_connect == 1);
    assert(strcmp(req.host, "2001:db8::1") == 0);
    assert(strcmp(req.port, "443") == 0);
}

static void
test_connect_default_port(void)
{
    const char *msg = "CONNECT example.com HTTP/1.1\r\n\r\n";
    http_request_t req;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(req.is_connect == 1);
    assert(strcmp(req.host, "example.com") == 0);
    assert(strcmp(req.port, "443") == 0);
}

static void
test_plain_absolute_form(void)
{
    const char *msg = "GET http://example.com/ HTTP/1.1\r\n"
                      "Host: example.com\r\n\r\n";
    http_request_t req;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(req.is_connect == 0);
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.host, "example.com") == 0);
    assert(strcmp(req.port, "80") == 0);
    assert(strcmp(req.target, "/") == 0);
}

static void
test_plain_explicit_port(void)
{
    const char *msg = "GET http://example.com:8080/path HTTP/1.1\r\n"
                      "Host: example.com\r\n\r\n";
    http_request_t req;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(strcmp(req.host, "example.com") == 0);
    assert(strcmp(req.port, "8080") == 0);
    assert(strcmp(req.target, "/path") == 0);
}

static void
test_plain_query(void)
{
    const char *msg = "GET http://example.com/search?q=1&x=2 HTTP/1.1\r\n"
                      "Host: example.com\r\n\r\n";
    http_request_t req;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(strcmp(req.target, "/search?q=1&x=2") == 0);
}

static void
test_origin_form_uses_host_header(void)
{
    const char *msg = "GET /index.html HTTP/1.1\r\n"
                      "Host: Example.COM:8000\r\n\r\n";
    http_request_t req;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(strcmp(req.host, "Example.COM") == 0);
    assert(strcmp(req.port, "8000") == 0);
    assert(strcmp(req.target, "/index.html") == 0);
}

static void
test_incomplete(void)
{
    const char *msg = "GET http://example.com/ HTTP/1.1\r\nHost: exa";
    http_request_t req;
    size_t need_more = 0;

    assert(http_parse_request(msg, strlen(msg), &req, &need_more) ==
           HTTP_PARSE_INCOMPLETE);
    assert(need_more > 0);
}

static void
test_malformed(void)
{
    http_request_t req;

    /* Unknown method */
    const char *bad_method = "FOO / HTTP/1.1\r\n\r\n";
    assert(http_parse_request(bad_method, strlen(bad_method), &req, NULL) ==
           HTTP_PARSE_ERROR);

    /* No spaces at all */
    const char *no_space = "GARBAGE\r\n\r\n";
    assert(http_parse_request(no_space, strlen(no_space), &req, NULL) ==
           HTTP_PARSE_ERROR);

    /* https absolute-form without CONNECT */
    const char *https = "GET https://example.com/ HTTP/1.1\r\n"
                        "Host: example.com\r\n\r\n";
    assert(http_parse_request(https, strlen(https), &req, NULL) ==
           HTTP_PARSE_ERROR);

    /* origin-form without Host header */
    const char *no_host = "GET / HTTP/1.1\r\n\r\n";
    assert(http_parse_request(no_host, strlen(no_host), &req, NULL) ==
           HTTP_PARSE_ERROR);

    /* port out of range */
    const char *bad_port = "GET http://example.com:70000/ HTTP/1.1\r\n\r\n";
    assert(http_parse_request(bad_port, strlen(bad_port), &req, NULL) ==
           HTTP_PARSE_ERROR);
}

static void
test_build_forward_request(void)
{
    const char *msg = "GET http://example.com/page HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Proxy-Connection: keep-alive\r\n"
                      "Proxy-Authorization: Basic dXNlcg==\r\n"
                      "Connection: keep-alive\r\n"
                      "User-Agent: curl/8\r\n"
                      "\r\n";
    http_request_t req;
    char out[1024];
    size_t len;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    len = http_build_forward_request(&req, out, sizeof(out));
    assert(len > 0);
    out[len] = '\0';

    assert(strncmp(out, "GET /page HTTP/1.1\r\n", 20) == 0);
    assert(strstr(out, "Host: example.com\r\n") != NULL);
    assert(strstr(out, "User-Agent: curl/8\r\n") != NULL);
    assert(strstr(out, "Proxy-Connection") == NULL);
    assert(strstr(out, "Proxy-Authorization") == NULL);
    assert(strstr(out, "Connection: keep-alive") == NULL);
    assert(strstr(out, "Connection: close\r\n") != NULL);
    assert(strcmp(out + len - 2, "\r\n") == 0);
}

static void
test_build_ensures_host(void)
{
    const char *msg = "GET http://example.com:8080/ HTTP/1.1\r\n"
                      "User-Agent: x\r\n\r\n";
    http_request_t req;
    char out[1024];
    size_t len;

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    len = http_build_forward_request(&req, out, sizeof(out));
    assert(len > 0);
    out[len] = '\0';

    assert(strstr(out, "Host: example.com:8080\r\n") != NULL);
}


static void
test_build_too_small(void)
{
    const char *msg = "GET http://example.com/ HTTP/1.1\r\n"
                      "Host: example.com\r\n\r\n";
    http_request_t req;
    char out[8];

    assert(http_parse_request(msg, strlen(msg), &req, NULL) == HTTP_PARSE_OK);
    assert(http_build_forward_request(&req, out, sizeof(out)) == 0);
}

int
main(void)
{
    test_looks_like_request();
    test_connect_hostname();
    test_connect_ipv6();
    test_connect_default_port();
    test_plain_absolute_form();
    test_plain_explicit_port();
    test_plain_query();
    test_origin_form_uses_host_header();
    test_incomplete();
    test_malformed();
    test_build_forward_request();
    test_build_ensures_host();
    test_build_too_small();
    return 0;
}
