/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * route.c - IP-based routing modes for the local proxy
 *
 * Sets are stored in `struct ss_ipset` (see ipset.h). The China set comes
 * from a CIDR file; the reserved/local sets are hardcoded and optionally
 * augmented by a local ACL file. List files are parsed line by line:
 * blank lines, '#' comments and '[...]' section headers are ignored.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "ipset.h"
#include "netutils.h"
#include "route.h"
#include "socks5.h"
#include "utils.h"

/* Hardcoded loopback / link-local / this-host ranges. */
static const char *const local_ranges[] = {
    "127.0.0.0/8",
    "0.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fe80::/10",
};

/* LAN additions on top of the local ranges. */
static const char *const lan_ranges[] = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
};

static struct ss_ipset china_v4;
static struct ss_ipset china_v6;
static struct ss_ipset reserved_v4;
static struct ss_ipset reserved_v6;
static struct ss_ipset local_v4;
static struct ss_ipset local_v6;

static int route_initialized = 0;
static enum route_mode route_mode = ROUTE_MODE_ALL;
static int route_ipv6first = 0;

static char *
route_trim(char *str)
{
    while (*str != '\0' && isspace((unsigned char)*str))
        str++;

    if (*str == '\0')
        return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';
    return str;
}

static int
assign_cidr(struct ss_ipset *v4, struct ss_ipset *v6, const char *spec)
{
    const char *slash = strchr(spec, '/');
    size_t host_len   = slash != NULL ? (size_t)(slash - spec) : strlen(spec);
    char host[INET6_ADDRSTRLEN + 1];
    int prefix = -1;

    if (host_len == 0 || host_len >= sizeof(host))
        return -1;
    memcpy(host, spec, host_len);
    host[host_len] = '\0';

    if (slash != NULL && ss_parse_int(slash + 1, 0, 128, &prefix) == -1)
        return -1;

    struct ss_ip addr;
    if (ss_ip_init(&addr, host) != 0)
        return -1;

    if (addr.version == 4) {
        if (prefix == -1)
            prefix = 32;
        if (prefix > 32)
            return -1;
        ss_ipset_assign(v4, addr.bytes, 32, (unsigned)prefix, true);
    } else {
        if (prefix == -1)
            prefix = 128;
        if (prefix > 128)
            return -1;
        ss_ipset_assign(v6, addr.bytes, 128, (unsigned)prefix, true);
    }
    return 0;
}

static int
try_load_file(const char *path, struct ss_ipset *v4, struct ss_ipset *v6)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;

    char buf[2048];
    while (fgets(buf, sizeof(buf), f) != NULL) {
        char *comment = strchr(buf, '#');
        if (comment != NULL)
            *comment = '\0';

        char *line = route_trim(buf);
        if (line[0] == '\0' || line[0] == '[')
            continue;

        if (assign_cidr(v4, v6, line) != 0)
            LOGI("route: ignoring invalid entry: %s", line);
    }

    fclose(f);
    return 0;
}

static int
load_first(const char *configured, const char *name,
           struct ss_ipset *v4, struct ss_ipset *v6)
{
    if (configured != NULL && try_load_file(configured, v4, v6) == 0)
        return 0;

    static const char *const dirs[] = {
        "acl",
        "/usr/share/shadowsocks-libev",
        "/usr/local/share/shadowsocks-libev",
        "/etc/shadowsocks-libev",
    };
    char path[1024];

    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", dirs[i], name);
        if (try_load_file(path, v4, v6) == 0)
            return 0;
    }
    return -1;
}

static void
add_ranges(struct ss_ipset *v4, struct ss_ipset *v6,
           const char *const *ranges, size_t count)
{
    for (size_t i = 0; i < count; i++)
        assign_cidr(v4, v6, ranges[i]);
}

static int
route_fallback(void)
{
    return route_mode == ROUTE_MODE_CHN_ONLY ? ROUTE_DIRECT : ROUTE_PROXY;
}

static int
decide_addr(const struct ss_ip *addr)
{
    unsigned width = addr->version == 4 ? 32 : 128;
    const struct ss_ipset *china    = addr->version == 4 ? &china_v4 : &china_v6;
    const struct ss_ipset *reserved = addr->version == 4 ? &reserved_v4 : &reserved_v6;
    const struct ss_ipset *local    = addr->version == 4 ? &local_v4 : &local_v6;

    switch (route_mode) {
    case ROUTE_MODE_ALL:
        return ROUTE_PROXY;
    case ROUTE_MODE_BYPASS_LAN:
        return ss_ipset_contains(reserved, addr->bytes, width) ? ROUTE_DIRECT : ROUTE_PROXY;
    case ROUTE_MODE_BYPASS_LOCAL:
        return ss_ipset_contains(local, addr->bytes, width) ? ROUTE_DIRECT : ROUTE_PROXY;
    case ROUTE_MODE_BYPASS_CHN:
        if (ss_ipset_contains(china, addr->bytes, width)
            || ss_ipset_contains(reserved, addr->bytes, width))
            return ROUTE_DIRECT;
        return ROUTE_PROXY;
    case ROUTE_MODE_CHN_ONLY:
        return ss_ipset_contains(china, addr->bytes, width) ? ROUTE_PROXY : ROUTE_DIRECT;
    default:
        return ROUTE_PROXY;
    }
}

int
route_mode_from_string(const char *s)
{
    if (s == NULL)
        return -1;
    if (strcmp(s, "all") == 0)
        return ROUTE_MODE_ALL;
    if (strcmp(s, "bypass_lan") == 0)
        return ROUTE_MODE_BYPASS_LAN;
    if (strcmp(s, "bypass_local") == 0)
        return ROUTE_MODE_BYPASS_LOCAL;
    if (strcmp(s, "bypass_chn") == 0)
        return ROUTE_MODE_BYPASS_CHN;
    if (strcmp(s, "chn_only") == 0)
        return ROUTE_MODE_CHN_ONLY;
    return -1;
}

const char *
route_mode_name(enum route_mode mode)
{
    switch (mode) {
    case ROUTE_MODE_ALL:
        return "all";
    case ROUTE_MODE_BYPASS_LAN:
        return "bypass_lan";
    case ROUTE_MODE_BYPASS_LOCAL:
        return "bypass_local";
    case ROUTE_MODE_BYPASS_CHN:
        return "bypass_chn";
    case ROUTE_MODE_CHN_ONLY:
        return "chn_only";
    default:
        return "unknown";
    }
}

void
route_free(void)
{
    ss_ipset_clear(&china_v4);
    ss_ipset_clear(&china_v6);
    ss_ipset_clear(&reserved_v4);
    ss_ipset_clear(&reserved_v6);
    ss_ipset_clear(&local_v4);
    ss_ipset_clear(&local_v6);
    route_initialized = 0;
    route_mode        = ROUTE_MODE_ALL;
}

int
route_init(enum route_mode mode, const char *chn_path,
           const char *local_path, int ipv6first)
{
    if (mode < ROUTE_MODE_ALL || mode > ROUTE_MODE_CHN_ONLY)
        return -1;

    route_free();
    route_mode      = mode;
    route_ipv6first = ipv6first;

    switch (mode) {
    case ROUTE_MODE_ALL:
        break;
    case ROUTE_MODE_BYPASS_LOCAL:
        add_ranges(&local_v4, &local_v6, local_ranges,
                   sizeof(local_ranges) / sizeof(local_ranges[0]));
        break;
    case ROUTE_MODE_BYPASS_LAN:
    case ROUTE_MODE_BYPASS_CHN:
        add_ranges(&reserved_v4, &reserved_v6, local_ranges,
                   sizeof(local_ranges) / sizeof(local_ranges[0]));
        add_ranges(&reserved_v4, &reserved_v6, lan_ranges,
                   sizeof(lan_ranges) / sizeof(lan_ranges[0]));
        load_first(local_path, "local.acl", &reserved_v4, &reserved_v6);
        if (mode == ROUTE_MODE_BYPASS_CHN
            && load_first(chn_path, "chn.acl", &china_v4, &china_v6) != 0) {
            route_free();
            return -1;
        }
        break;
    case ROUTE_MODE_CHN_ONLY:
        if (load_first(chn_path, "chn.acl", &china_v4, &china_v6) != 0) {
            route_free();
            return -1;
        }
        break;
    }

    route_initialized = 1;
    return 0;
}

int
route_enabled(void)
{
    return route_initialized;
}

int
route_decide(const char *host, const char *port, int atyp,
             char *ip, size_t ip_len,
             struct sockaddr_storage *storage)
{
    if (!route_initialized)
        return ROUTE_PROXY;
    if (route_mode == ROUTE_MODE_ALL)
        return ROUTE_PROXY;

    const char *literal = NULL;
    if (atyp != SOCKS5_ATYP_DOMAIN && ip != NULL && ip[0] != '\0') {
        literal = ip;
    } else if (host != NULL && host[0] != '\0') {
        struct ss_ip tmp;
        if (ss_ip_init(&tmp, host) == 0)
            literal = host;
    }

    if (literal != NULL) {
        struct ss_ip addr;
        if (ss_ip_init(&addr, literal) != 0)
            return route_fallback();
        if (storage != NULL) {
            memset(storage, 0, sizeof(*storage));
            get_sockaddr((char *)literal, (char *)port, storage, 0, route_ipv6first);
        }
        return decide_addr(&addr);
    }

    if (host == NULL || host[0] == '\0' || storage == NULL)
        return route_fallback();

    memset(storage, 0, sizeof(*storage));
    if (get_sockaddr((char *)host, (char *)port, storage, 1, route_ipv6first) != 0)
        return route_fallback();

    struct ss_ip addr;
    if (storage->ss_family == AF_INET) {
        addr.version = 4;
        memcpy(addr.bytes, &((struct sockaddr_in *)storage)->sin_addr, 4);
    } else if (storage->ss_family == AF_INET6) {
        addr.version = 6;
        memcpy(addr.bytes, &((struct sockaddr_in6 *)storage)->sin6_addr, 16);
    } else {
        return route_fallback();
    }

    if (ip != NULL && ip_len > 0) {
        int family = addr.version == 4 ? AF_INET : AF_INET6;
        if (!ss_inet_ntop(family, addr.bytes, ip, (socklen_t)ip_len))
            ip[0] = '\0';
    }
    return decide_addr(&addr);
}
