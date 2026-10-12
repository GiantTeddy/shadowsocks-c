#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_helpers.h"

int verbose = 0;

#include "pac.h"
#include "route.h"
#include "socks5.h"

static void
write_temp(char *path, size_t size, const char *content)
{
    FILE *f = test_tempfile(path, size);
    assert(f != NULL);
    assert(fputs(content, f) >= 0);
    assert(fclose(f) == 0);
}

static const char *const HELPER_PAC =
    "function FindProxyForURL(url, host) {\n"
    "    if (shExpMatch(host, \"*.google.com\")) return \"PROXY 127.0.0.1:1080\";\n"
    "    if (dnsDomainIs(host, \".example.org\")) return \"PROXY 127.0.0.1:1080; DIRECT\";\n"
    "    if (isPlainHostName(host)) return \"DIRECT\";\n"
    "    if (dnsDomainLevels(host) > 3) return \"DIRECT\";\n"
    "    if (localHostOrDomainIs(host, \"host.example.com\")) return \"DIRECT\";\n"
    "    return \"DIRECT\";\n"
    "}\n";

static const char *const INNET_PAC =
    "function FindProxyForURL(url, host) {\n"
    "    if (isInNet(host, \"10.0.0.0\", \"255.0.0.0\")) return \"DIRECT\";\n"
    "    return \"PROXY 127.0.0.1:1080\";\n"
    "}\n";

static void
test_helpers(const char *path)
{
    assert(pac_enabled() == 0);
    assert(pac_init(path) == 0);
    assert(pac_enabled() == 1);

    assert(pac_evaluate("http://www.google.com/", "www.google.com") == ROUTE_PROXY);
    assert(pac_evaluate("http://a.example.org/", "a.example.org") == ROUTE_PROXY);
    assert(pac_evaluate("http://intranet/", "intranet") == ROUTE_DIRECT);
    assert(pac_evaluate("http://a.b.c.d.example/", "a.b.c.d.example") == ROUTE_DIRECT);
    assert(pac_evaluate("http://host.example.com/", "host.example.com") == ROUTE_DIRECT);
    assert(pac_evaluate("http://www.baidu.com/", "www.baidu.com") == ROUTE_DIRECT);

    pac_free();
    assert(pac_enabled() == 0);
}

static void
test_isinnet(const char *path)
{
    /* Only literal IPs reach isInNet, so no DNS lookup is performed. */
    assert(pac_init(path) == 0);
    assert(pac_evaluate("http://10.1.2.3/", "10.1.2.3") == ROUTE_DIRECT);
    assert(pac_evaluate("http://11.1.2.3/", "11.1.2.3") == ROUTE_PROXY);
    pac_free();
}

static void
test_directives(const char *path)
{
    assert(pac_init(path) == 0);

    assert(pac_evaluate("http://p/", "p") == ROUTE_PROXY);
    assert(pac_evaluate("http://s/", "s") == ROUTE_PROXY);
    assert(pac_evaluate("http://h/", "h") == ROUTE_PROXY);
    assert(pac_evaluate("http://t/", "t") == ROUTE_PROXY);
    assert(pac_evaluate("http://d/", "d") == ROUTE_DIRECT);

    pac_free();
}

static void
test_invalid(const char *syntax_path, const char *nofunc_path)
{
    assert(pac_init(NULL) == -1);
    assert(pac_enabled() == 0);
    assert(pac_evaluate("http://x/", "x") == -1);

    assert(pac_init("/nonexistent/pac/file.pac") == -1);
    assert(pac_enabled() == 0);

    assert(pac_init(syntax_path) == -1);
    assert(pac_enabled() == 0);

    assert(pac_init(nofunc_path) == -1);
    assert(pac_enabled() == 0);
}

static void
test_runtime_error(const char *path)
{
    assert(pac_init(path) == 0);
    assert(pac_enabled() == 1);
    assert(pac_evaluate("http://x/", "x") == -1);
    pac_free();
}

static void
test_route_integration(const char *path)
{
    char ip[INET6_ADDRSTRLEN];
    struct sockaddr_storage storage;

    assert(route_enabled() == 0);
    assert(route_init(ROUTE_MODE_PAC, NULL, NULL, path, 0) == 0);
    assert(route_enabled() == 1);

    ip[0] = '\0';
    memset(&storage, 0, sizeof(storage));
    assert(route_decide(NULL, "127.0.0.1", "80", SOCKS5_ATYP_DOMAIN,
                        ip, sizeof(ip), &storage) == ROUTE_DIRECT);
    assert(storage.ss_family == AF_INET);
    assert(strcmp(ip, "127.0.0.1") == 0);

    assert(route_decide(NULL, "blocked.example", "80", SOCKS5_ATYP_DOMAIN,
                        ip, sizeof(ip), &storage) == ROUTE_PROXY);

    route_free();
    assert(route_enabled() == 0);

    /* PAC mode without a file must fail cleanly. */
    assert(route_init(ROUTE_MODE_PAC, NULL, NULL, NULL, 0) == -1);
    assert(route_enabled() == 0);
}

int
main(void)
{
    char helper_pac[256];
    char innet_pac[256];
    char directive_pac[256];
    char syntax_pac[256];
    char nofunc_pac[256];
    char runtime_pac[256];
    char route_pac[256];

    test_network_init();

    write_temp(helper_pac, sizeof(helper_pac), HELPER_PAC);
    write_temp(innet_pac, sizeof(innet_pac), INNET_PAC);
    write_temp(directive_pac, sizeof(directive_pac),
               "function FindProxyForURL(url, host) {\n"
               "    if (host == \"p\") return \"PROXY 127.0.0.1:1080; DIRECT\";\n"
               "    if (host == \"s\") return \"SOCKS5 127.0.0.1:1080\";\n"
               "    if (host == \"h\") return \"HTTPS proxy:443\";\n"
               "    if (host == \"t\") return \"HTTP proxy:80\";\n"
               "    return \"DIRECT\";\n"
               "}\n");
    write_temp(syntax_pac, sizeof(syntax_pac),
               "function FindProxyForURL(url, host) {\n");
    write_temp(nofunc_pac, sizeof(nofunc_pac), "var x = 1;\n");
    write_temp(runtime_pac, sizeof(runtime_pac),
               "function FindProxyForURL(url, host) {\n"
               "    return undefinedFunction();\n"
               "}\n");
    write_temp(route_pac, sizeof(route_pac),
               "function FindProxyForURL(url, host) {\n"
               "    if (host == \"127.0.0.1\") return \"DIRECT\";\n"
               "    return \"PROXY 127.0.0.1:1080\";\n"
               "}\n");

    test_helpers(helper_pac);
    test_isinnet(innet_pac);
    test_directives(directive_pac);
    test_invalid(syntax_pac, nofunc_pac);
    test_runtime_error(runtime_pac);
    test_route_integration(route_pac);

    return 0;
}
