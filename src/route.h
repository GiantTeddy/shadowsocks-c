/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * route.h - IP-based routing modes for the local proxy
 *
 * A "route mode" decides, per destination, whether a request is proxied
 * through the shadowsocks server or sent directly. The sets are built from
 * a China CIDR list and hardcoded LAN/local ranges. The module performs no
 * I/O beyond reading the configured list files during route_init().
 */
#ifndef SS_ROUTE_H
#define SS_ROUTE_H

#include <stddef.h>

#include "netutils.h" /* struct sockaddr_storage, MAX_HOSTNAME_LEN */

/* Decision results. */
enum {
    ROUTE_PROXY    = 0,
    ROUTE_DIRECT   = 1,
    ROUTE_DISABLED = -1
};

enum route_mode {
    ROUTE_MODE_ALL = 0,   /* proxy everything (default)                     */
    ROUTE_MODE_BYPASS_LAN, /* direct for LAN/reserved, proxy the rest        */
    ROUTE_MODE_BYPASS_LOCAL, /* direct for loopback/link-local only          */
    ROUTE_MODE_BYPASS_CHN, /* direct for China + local + LAN                 */
    ROUTE_MODE_CHN_ONLY,   /* proxy only for China addresses                 */
    ROUTE_MODE_PAC         /* decide per request with a PAC file             */
};

/* Parse a mode name; returns -1 when the name is unknown. */
int route_mode_from_string(const char *s);

/* Human-readable name for a mode (never NULL). */
const char *route_mode_name(enum route_mode mode);

/*
 * Initialize routing. chn_path/local_path may be NULL to use the default
 * search paths; pac_path is the PAC file for ROUTE_MODE_PAC. Modes that need
 * the China set fail (-1) when no candidate file exists, and PAC mode fails
 * when pac_path is NULL or cannot be loaded. Returns 0 on success.
 */
int route_init(enum route_mode mode, const char *chn_path,
               const char *local_path, const char *pac_path, int ipv6first);

/* Release all loaded sets. Safe to call at any time. */
void route_free(void);

/* Non-zero once route_init() has succeeded. */
int route_enabled(void);

/*
 * Decide whether a request should be proxied or connected directly.
 *
 * `url` is the request URL used by PAC mode and may be NULL for the IP modes
 * (and for a SOCKS5 request). For a literal IP (atyp is not
 * SOCKS5_ATYP_DOMAIN) the `ip` argument must hold the numeric address. For a
 * domain the name is resolved synchronously and, on a DIRECT result, `storage`
 * holds the resolved address; when the result is PROXY the caller must still
 * forward the original domain. Returns ROUTE_DIRECT or ROUTE_PROXY.
 */
int route_decide(const char *url, const char *host, const char *port, int atyp,
                 char *ip, size_t ip_len,
                 struct sockaddr_storage *storage);

#endif /* SS_ROUTE_H */
