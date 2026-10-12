#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_helpers.h"

int verbose = 0;

#include "route.h"
#include "socks5.h"

static const char *const CHN_FILE_CONTENT =
    "# synthetic china list\n"
    "[proxy_all]\n"
    "\n"
    "[bypass_list]\n"
    "1.2.3.0/24\n"
    "2400:cb00::/32\n";

static void
write_temp(char *path, size_t size, const char *content)
{
    FILE *f = test_tempfile(path, size);
    assert(f != NULL);
    assert(fputs(content, f) >= 0);
    assert(fclose(f) == 0);
}

static int
decide(const char *host, int atyp)
{
    char ip[INET6_ADDRSTRLEN];
    struct sockaddr_storage storage;

    ip[0] = '\0';
    memset(&storage, 0, sizeof(storage));
    return route_decide(host, "443", atyp, ip, sizeof(ip), &storage);
}

static void
test_mode_strings(void)
{
    assert(route_mode_from_string("all") == ROUTE_MODE_ALL);
    assert(route_mode_from_string("bypass_lan") == ROUTE_MODE_BYPASS_LAN);
    assert(route_mode_from_string("bypass_local") == ROUTE_MODE_BYPASS_LOCAL);
    assert(route_mode_from_string("bypass_chn") == ROUTE_MODE_BYPASS_CHN);
    assert(route_mode_from_string("chn_only") == ROUTE_MODE_CHN_ONLY);
    assert(route_mode_from_string("unknown") == -1);
    assert(route_mode_from_string("") == -1);
    assert(route_mode_from_string(NULL) == -1);

    assert(strcmp(route_mode_name(ROUTE_MODE_ALL), "all") == 0);
    assert(strcmp(route_mode_name(ROUTE_MODE_BYPASS_LAN), "bypass_lan") == 0);
    assert(strcmp(route_mode_name(ROUTE_MODE_BYPASS_LOCAL), "bypass_local") == 0);
    assert(strcmp(route_mode_name(ROUTE_MODE_BYPASS_CHN), "bypass_chn") == 0);
    assert(strcmp(route_mode_name(ROUTE_MODE_CHN_ONLY), "chn_only") == 0);
}

static void
test_all(const char *chn)
{
    assert(route_enabled() == 0);
    assert(route_init(ROUTE_MODE_ALL, chn, NULL, 0) == 0);
    assert(route_enabled() == 1);
    assert(decide("127.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("10.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("8.8.8.8", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("1.2.3.4", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    route_free();
    assert(route_enabled() == 0);
    assert(decide("127.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
}

static void
test_bypass_lan(const char *chn)
{
    assert(route_init(ROUTE_MODE_BYPASS_LAN, chn, NULL, 0) == 0);
    assert(decide("10.1.2.3", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("192.168.1.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("127.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("fc00::1", SOCKS5_ATYP_IPV6) == ROUTE_DIRECT);
    assert(decide("8.8.8.8", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    /* China addresses are not bypassed by this mode. */
    assert(decide("1.2.3.4", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    route_free();
}

static void
test_bypass_local(const char *chn)
{
    assert(route_init(ROUTE_MODE_BYPASS_LOCAL, chn, NULL, 0) == 0);
    assert(decide("127.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("169.254.1.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("::1", SOCKS5_ATYP_IPV6) == ROUTE_DIRECT);
    assert(decide("fe80::1", SOCKS5_ATYP_IPV6) == ROUTE_DIRECT);
    /* Private LAN addresses are not "local" for this mode. */
    assert(decide("10.1.2.3", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("192.168.1.1", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("fc00::1", SOCKS5_ATYP_IPV6) == ROUTE_PROXY);
    assert(decide("8.8.8.8", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    route_free();
}

static void
test_bypass_chn(const char *chn)
{
    assert(route_init(ROUTE_MODE_BYPASS_CHN, chn, NULL, 0) == 0);
    assert(decide("1.2.3.4", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("2400:cb00::1", SOCKS5_ATYP_IPV6) == ROUTE_DIRECT);
    assert(decide("10.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("127.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("fc00::1", SOCKS5_ATYP_IPV6) == ROUTE_DIRECT);
    assert(decide("8.8.8.8", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("1.1.1.1", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    route_free();
}

static void
test_chn_only(const char *chn)
{
    assert(route_init(ROUTE_MODE_CHN_ONLY, chn, NULL, 0) == 0);
    assert(decide("1.2.3.4", SOCKS5_ATYP_IPV4) == ROUTE_PROXY);
    assert(decide("2400:cb00::1", SOCKS5_ATYP_IPV6) == ROUTE_PROXY);
    assert(decide("10.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("127.0.0.1", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    assert(decide("8.8.8.8", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    route_free();
}

static void
test_local_acl_augment(const char *chn)
{
    char local[256];
    write_temp(local, sizeof(local), "203.0.113.0/24\n");

    assert(route_init(ROUTE_MODE_BYPASS_LAN, chn, local, 0) == 0);
    assert(decide("203.0.113.5", SOCKS5_ATYP_IPV4) == ROUTE_DIRECT);
    route_free();
}

int
main(void)
{
    char chn[256];

    test_network_init();
    write_temp(chn, sizeof(chn), CHN_FILE_CONTENT);

    test_mode_strings();
    test_all(chn);
    test_bypass_lan(chn);
    test_bypass_local(chn);
    test_bypass_chn(chn);
    test_chn_only(chn);
    test_local_acl_augment(chn);

    return 0;
}
