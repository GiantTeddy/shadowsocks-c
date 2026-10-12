/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * pac.h - Proxy Auto-Config (PAC) routing engine
 *
 * Evaluates a standard PAC file's FindProxyForURL(url, host) function in a
 * duktape heap. The heap is created once by pac_init() and kept alive so that
 * pac_evaluate() can be called for every request without re-parsing the file.
 * All I/O is limited to reading the PAC source in pac_init().
 */
#ifndef SS_PAC_H
#define SS_PAC_H

/*
 * Load and evaluate a PAC file. Registers the standard helper functions
 * (shExpMatch, dnsDomainIs, isInNet, ...) before running the source.
 * Returns 0 on success, -1 when the path is NULL/unreadable or the source
 * fails to evaluate.
 */
int pac_init(const char *path);

/* Destroy the PAC heap. Safe to call at any time, including before pac_init(). */
void pac_free(void);

/* Non-zero once pac_init() has succeeded. */
int pac_enabled(void);

/*
 * Evaluate FindProxyForURL(url, host) and classify the first directive.
 * Returns ROUTE_PROXY for PROXY/HTTP/HTTPS/SOCKS/SOCKS5, ROUTE_DIRECT for
 * DIRECT, or -1 when the call throws a JavaScript error.
 */
int pac_evaluate(const char *url, const char *host);

#endif /* SS_PAC_H */
