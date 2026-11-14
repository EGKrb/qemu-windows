/*
 * passt for Windows: user-mode networking for QEMU guests, with the command
 * line and the protocols of passt (https://passt.top), which is Linux only.
 *
 * QEMU starts it for -netdev passt: --fd gives one end of a socket pair
 * (frames with a 32-bit big-endian length, as -netdev stream), or the
 * vhost-user connection with --vhost-user.  Run by hand, it listens on a
 * UNIX socket (--socket) for -netdev stream.
 *
 * As passt does, the guest gets the address, gateway, MTU, DNS servers and
 * search domains of the host's interface with the default route, the
 * gateway address leads to the host itself (--map-host-loopback), and
 * connections of the guest leave from host sockets; forwarded ports
 * (-t, -u) are bound on the host.  The TCP/IP stack is libslirp's.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/sockets.h"
#include "qemu/iov.h"
#include "qemu/win32-fdpass.h"
#include "standard-headers/linux/virtio_net.h"
#include "libvhost-user.h"
#include <getopt.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <slirp/libslirp.h>

#define PASST_VERSION "passt for Windows (QEMU " QEMU_VERSION ")"
#define FRAME_MAX 65535
#define MAX_FWD 4096

/* ------------------------------------------------------------------ */
/* configuration                                                       */

typedef struct Forward {
    bool udp;
    bool v6;                  /* bound on an IPv6 address */
    struct sockaddr_storage host;
    uint16_t host_port;
    uint16_t guest_port;
} Forward;

typedef struct Conf {
    bool foreground, debug, quiet, use_stderr, one_off, vhost_user;
    bool v4, v6;
    bool no_tcp, no_udp, no_icmp, no_dhcp, no_ndp, no_dhcpv6, no_ra;
    bool no_dhcp_dns, no_dhcp_search, no_map_gw, freebind;
    char *log_file, *pcap, *pidfile, *socket_path, *iface, *fqdn;
    long long fd;
    int mtu;
    bool have_addr4, have_mask4, have_gw4, have_addr6, have_gw6;
    struct in_addr addr4, mask4, gw4, dns_fwd4, map_loopback4, map_guest4;
    struct in6_addr addr6, gw6, dns_fwd6, prefix6;
    int prefix_len4, prefix_len6;
    bool have_dns_fwd4, have_dns_fwd6, have_map_loopback4, have_map_guest4;
    GPtrArray *dns4, *dns6;   /* struct in_addr *, struct in6_addr * */
    bool dns_none;
    GPtrArray *search;
    bool search_none;
    char *outbound4, *outbound6, *outbound_if4, *outbound_if6;
    uint8_t mac[6];
    bool have_mac;
    GArray *fwd;              /* Forward */
} Conf;

static Conf conf = { .v4 = true, .v6 = true, .fd = -1 };
static FILE *log_fp;

static void G_GNUC_PRINTF(2, 3) logmsg(int level, const char *fmt, ...)
{
    va_list ap;
    FILE *f = log_fp ? log_fp : stderr;

    /* 0 error, 1 warning, 2 info, 3 debug */
    if ((level >= 3 && !conf.debug) || (level >= 1 && conf.quiet &&
                                        !conf.debug)) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fflush(f);
}

#define err(...) logmsg(0, __VA_ARGS__)
#define warn(...) logmsg(1, __VA_ARGS__)
#define info(...) logmsg(2, __VA_ARGS__)
#define debug(...) logmsg(3, __VA_ARGS__)

static G_NORETURN void G_GNUC_PRINTF(1, 2) die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (log_fp) {
        va_start(ap, fmt);
        vfprintf(log_fp, fmt, ap);
        va_end(ap);
        fputc('\n', log_fp);
        fflush(log_fp);
    }
    exit(EXIT_FAILURE);
}

static void usage(FILE *f, int code)
{
    fprintf(f,
"Usage: passt [OPTION]...\n"
"\n"
"  -d, --debug\t\tBe verbose\n"
"      --trace\t\tBe extra verbose, implies --debug\n"
"  -q, --quiet\t\tDon't print informational messages\n"
"  -f, --foreground\tDon't run in background\n"
"  -e, --stderr\t\tLog to stderr too\n"
"  -l, --log-file PATH\tLog (only) to given file\n"
"      --log-size BYTES\tAccepted, no rotation\n"
"      --version\t\tShow version and exit\n"
"  -s, --socket, --socket-path PATH\tUNIX domain socket path\n"
"  -F, --fd FD\t\tUse a connected socket (a socket handle)\n"
"  -1, --one-off\t\tQuit after handling one single client\n"
"  -p, --pcap FILE\tLog tap-facing traffic to pcap file\n"
"  -P, --pid FILE\tWrite own PID to the given file\n"
"  -m, --mtu MTU\t\tAssign MTU via DHCP/NDP\n"
"  -a, --address ADDR\tAssign IPv4 or IPv6 address ADDR\n"
"  -n, --netmask MASK\tAssign IPv4 MASK, dot-decimal or bits\n"
"  -M, --mac-addr ADDR\tUse source MAC address ADDR\n"
"  -g, --gateway ADDR\tPass IPv4 or IPv6 address as gateway\n"
"  -i, --interface NAME\tInterface for addresses and routes\n"
"  -o, --outbound ADDR\tBind to address as outbound source\n"
"      --outbound-if4 NAME\tBind to outbound interface for IPv4\n"
"      --outbound-if6 NAME\tBind to outbound interface for IPv6\n"
"  -D, --dns ADDR\tUse IPv4 or IPv6 address as DNS\n"
"      --dns-forward ADDR\tForward DNS queries sent to ADDR\n"
"      --dns-host ADDR\tAccepted (the resolver of the host is used)\n"
"      --no-dhcp-dns\tNo DNS list in DHCP/DHCPv6/NDP\n"
"  -S, --search LIST\tSpace-separated list, search domains\n"
"      --no-dhcp-search\tNo list in DHCP/DHCPv6/NDP\n"
"  -H, --hostname NAME\tAccepted\n"
"      --fqdn NAME\tFQDN to configure client with\n"
"      --map-host-loopback ADDR\tTranslate ADDR to refer to host\n"
"      --no-map-gw\tDon't map gateway address to host\n"
"      --map-guest-addr ADDR\tTranslate ADDR to guest's address\n"
"  -4, --ipv4-only\tEnable IPv4 operation only\n"
"  -6, --ipv6-only\tEnable IPv6 operation only\n"
"  -t, --tcp-ports SPEC\tTCP port forwarding to guest\n"
"  -u, --udp-ports SPEC\tUDP port forwarding to guest\n"
"      --no-tcp, --no-udp, --no-icmp, --no-dhcp, --no-ndp,\n"
"      --no-dhcpv6, --no-ra\tDisable the given protocol or service\n"
"      --freebind\tBind to any address for forwarding\n"
"      --vhost-user\tEnable vhost-user mode\n"
"      --print-capabilities\tPrint back-end capabilities (vhost-user)\n");
    exit(code);
}

/* ------------------------------------------------------------------ */
/* host network                                                        */

static int prefix_of_mask(struct in_addr m)
{
    uint32_t v = ntohl(m.s_addr);
    int n = 0;

    while (v & 0x80000000u) {
        n++;
        v <<= 1;
    }
    return n;
}

static struct in_addr mask_of_prefix(int n)
{
    struct in_addr m;

    m.s_addr = htonl(n ? 0xffffffffu << (32 - n) : 0);
    return m;
}

static IP_ADAPTER_ADDRESSES *adapters(void)
{
    ULONG size = 32768;
    IP_ADAPTER_ADDRESSES *a = NULL;
    ULONG rc;

    do {
        g_free(a);
        a = g_malloc(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL,
                                  a, &size);
    } while (rc == ERROR_BUFFER_OVERFLOW);
    if (rc != NO_ERROR) {
        g_free(a);
        return NULL;
    }
    return a;
}

/* the interface of the default route of @family, or the one named @name */
static IP_ADAPTER_ADDRESSES *find_adapter(IP_ADAPTER_ADDRESSES *list,
                                          int family, const char *name)
{
    IP_ADAPTER_ADDRESSES *a;
    NET_IFINDEX index = 0;

    if (name) {
        gunichar2 *w = g_utf8_to_utf16(name, -1, NULL, NULL, NULL);

        for (a = list; a; a = a->Next) {
            if (!g_strcmp0(a->AdapterName, name) ||
                (w && a->FriendlyName && !wcscmp((wchar_t *)w,
                                                 a->FriendlyName)) ||
                (a->IfIndex && strtoul(name, NULL, 10) == a->IfIndex)) {
                g_free(w);
                return a;
            }
        }
        g_free(w);
        return NULL;
    } else {
        MIB_IPFORWARD_TABLE2 *t;
        ULONG metric = ~0u, i;

        if (GetIpForwardTable2(family, &t) != NO_ERROR) {
            return NULL;
        }
        for (i = 0; i < t->NumEntries; i++) {
            MIB_IPFORWARD_ROW2 *r = &t->Table[i];
            MIB_IPINTERFACE_ROW ifr = { 0 };

            if (r->DestinationPrefix.PrefixLength != 0) {
                continue;
            }
            ifr.Family = family;
            ifr.InterfaceIndex = r->InterfaceIndex;
            if (GetIpInterfaceEntry(&ifr) != NO_ERROR || !ifr.Connected) {
                continue;
            }
            if (r->Metric + ifr.Metric < metric) {
                metric = r->Metric + ifr.Metric;
                index = r->InterfaceIndex;
            }
        }
        FreeMibTable(t);
    }
    for (a = list; a && index; a = a->Next) {
        if ((family == AF_INET ? a->IfIndex : a->Ipv6IfIndex) == index &&
            a->OperStatus == IfOperStatusUp) {
            return a;
        }
    }
    return NULL;
}

static bool is_loopback_or_ll(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        uint32_t a = ntohl(((struct sockaddr_in *)sa)->sin_addr.s_addr);

        return (a >> 24) == 127 || (a >> 16) == 0xa9fe;
    }
    if (sa->sa_family == AF_INET6) {
        const struct in6_addr *a = &((struct sockaddr_in6 *)sa)->sin6_addr;

        return IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_LINKLOCAL(a) ||
               IN6_IS_ADDR_SITELOCAL(a);
    }
    return true;
}

static void host_conf(void)
{
    IP_ADAPTER_ADDRESSES *list = adapters(), *a4, *a6;
    IP_ADAPTER_UNICAST_ADDRESS *u;
    IP_ADAPTER_GATEWAY_ADDRESS_LH *g;
    IP_ADAPTER_DNS_SERVER_ADDRESS *d;

    if (!list) {
        die("Cannot read the network interfaces of the host");
    }
    a4 = find_adapter(list, AF_INET, conf.iface);
    a6 = find_adapter(list, AF_INET6, conf.iface);
    if (conf.iface && !a4) {
        die("Invalid interface name %s", conf.iface);
    }

    if (conf.v4 && a4) {
        for (u = a4->FirstUnicastAddress; u && !conf.have_addr4;
             u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET) {
                conf.addr4 = ((struct sockaddr_in *)
                              u->Address.lpSockaddr)->sin_addr;
                conf.have_addr4 = true;
                if (!conf.have_mask4) {
                    conf.prefix_len4 = u->OnLinkPrefixLength;
                    conf.mask4 = mask_of_prefix(conf.prefix_len4);
                }
            }
        }
        for (g = a4->FirstGatewayAddress; g && !conf.have_gw4; g = g->Next) {
            if (g->Address.lpSockaddr->sa_family == AF_INET) {
                conf.gw4 = ((struct sockaddr_in *)
                            g->Address.lpSockaddr)->sin_addr;
                conf.have_gw4 = true;
            }
        }
        if (!conf.mtu && a4->Mtu && a4->Mtu < 65521) {
            conf.mtu = a4->Mtu;
        }
    }
    if (conf.v6 && a6) {
        for (u = a6->FirstUnicastAddress; u; u = u->Next) {
            struct sockaddr_in6 *s6 = (void *)u->Address.lpSockaddr;

            if (s6->sin6_family == AF_INET6 && !conf.have_addr6 &&
                !is_loopback_or_ll(u->Address.lpSockaddr) &&
                u->OnLinkPrefixLength <= 64) {
                conf.addr6 = s6->sin6_addr;
                conf.have_addr6 = true;
                conf.prefix_len6 = 64;
            }
        }
        for (g = a6->FirstGatewayAddress; g && !conf.have_gw6; g = g->Next) {
            if (g->Address.lpSockaddr->sa_family == AF_INET6) {
                conf.gw6 = ((struct sockaddr_in6 *)
                            g->Address.lpSockaddr)->sin6_addr;
                conf.have_gw6 = true;
            }
        }
    }

    /* DNS servers and search domains of the host */
    if (!conf.dns_none && !conf.dns4->len && !conf.dns6->len) {
        IP_ADAPTER_ADDRESSES *a;

        for (a = a4 ? a4 : a6; a; a = a == a4 && a6 && a6 != a4 ? a6 : NULL) {
            for (d = a->FirstDnsServerAddress; d; d = d->Next) {
                struct sockaddr *sa = d->Address.lpSockaddr;

                if (sa->sa_family == AF_INET) {
                    struct in_addr *x = g_new(struct in_addr, 1);

                    *x = ((struct sockaddr_in *)sa)->sin_addr;
                    g_ptr_array_add(conf.dns4, x);
                } else if (sa->sa_family == AF_INET6 &&
                           !IN6_IS_ADDR_SITELOCAL(
                               &((struct sockaddr_in6 *)sa)->sin6_addr)) {
                    struct in6_addr *x = g_new(struct in6_addr, 1);

                    *x = ((struct sockaddr_in6 *)sa)->sin6_addr;
                    g_ptr_array_add(conf.dns6, x);
                }
            }
        }
    }
    if (!conf.search_none && !conf.search->len) {
        IP_ADAPTER_ADDRESSES *a = a4 ? a4 : a6;

        if (a && a->DnsSuffix && a->DnsSuffix[0]) {
            g_ptr_array_add(conf.search,
                            g_utf16_to_utf8((gunichar2 *)a->DnsSuffix, -1,
                                            NULL, NULL, NULL));
        }
    }
    g_free(list);

    if (conf.v4 && !conf.have_addr4) {
        if (conf.have_gw4) {
            die("IPv4: a gateway without an address");
        }
        info("No interfaces with usable IPv4 routes");
        conf.v4 = false;
    }
    if (conf.v4 && !conf.have_gw4) {
        /* an address given without a gateway: the first of its network */
        conf.gw4.s_addr = htonl((ntohl(conf.addr4.s_addr) &
                                 ntohl(conf.mask4.s_addr)) | 1);
        if (conf.gw4.s_addr == conf.addr4.s_addr) {
            conf.gw4.s_addr = htonl(ntohl(conf.gw4.s_addr) + 1);
        }
        conf.have_gw4 = true;
    }
    if (conf.v6 && !conf.have_addr6) {
        info("No interfaces with usable IPv6 routes");
        conf.v6 = false;
    }
    if (!conf.v4 && !conf.v6) {
        die("External interface not usable");
    }
}

/* the address an interface named @name has, for outbound connections */
static bool interface_address(const char *name, int family,
                              struct sockaddr_storage *ss)
{
    IP_ADAPTER_ADDRESSES *list = adapters(), *a;
    IP_ADAPTER_UNICAST_ADDRESS *u;
    bool found = false;

    a = list ? find_adapter(list, family, name) : NULL;
    for (u = a ? a->FirstUnicastAddress : NULL; u && !found; u = u->Next) {
        if (u->Address.lpSockaddr->sa_family == family &&
            (family == AF_INET || !is_loopback_or_ll(u->Address.lpSockaddr))) {
            memcpy(ss, u->Address.lpSockaddr, u->Address.iSockaddrLength);
            found = true;
        }
    }
    g_free(list);
    return found;
}

/* ------------------------------------------------------------------ */
/* option parsing                                                      */

static bool parse_addr(const char *s, int *family, void *addr)
{
    if (inet_pton(AF_INET, s, addr) == 1) {
        *family = AF_INET;
        return true;
    }
    if (inet_pton(AF_INET6, s, addr) == 1) {
        *family = AF_INET6;
        return true;
    }
    return false;
}

static int parse_port(const char *s, char **end)
{
    unsigned long v = strtoul(s, end, 10);

    if (*end == s || v > 65535) {
        die("Invalid port in %s", s);
    }
    return v;
}

/* [addr[%iface]/]ports[:targets][,...] with ~excluded ports, or all/none */
static void parse_forward(const char *spec, bool udp)
{
    g_autofree char *copy = g_strdup(spec);
    char *ports = copy, *slash = strchr(copy, '/');
    struct sockaddr_storage host = { 0 };
    bool excluded[65536] = { false };
    g_auto(GStrv) items = NULL;
    int i, family = 0;
    bool all = false;
    uint8_t addr[16];

    if (!strcmp(spec, "none")) {
        return;
    }
    if (slash) {
        char *pct;

        *slash = '\0';
        ports = slash + 1;
        pct = strchr(copy, '%');
        if (pct) {
            *pct = '\0';     /* the interface: the address is enough */
        }
        if (*copy && !parse_addr(copy, &family, addr)) {
            die("Invalid address in port specification %s", spec);
        }
        if (family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&host;

            s4->sin_family = AF_INET;
            memcpy(&s4->sin_addr, addr, 4);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&host;

            s6->sin6_family = AF_INET6;
            memcpy(&s6->sin6_addr, addr, 16);
        }
    }

    items = g_strsplit(ports, ",", -1);
    /* exclusions first, they apply to the whole specification */
    for (i = 0; items[i]; i++) {
        char *p = items[i], *end;
        int lo, hi;

        if (*p != '~') {
            continue;
        }
        lo = hi = parse_port(p + 1, &end);
        if (*end == '-') {
            hi = parse_port(end + 1, &end);
        }
        for (; lo <= hi; lo++) {
            excluded[lo] = true;
        }
    }
    for (i = 0; items[i]; i++) {
        char *p = items[i], *end;
        int lo, hi, tlo, thi, port;

        if (*p == '~' || !*p) {
            continue;
        }
        if (!strcmp(p, "all")) {
            all = true;
            continue;
        }
        lo = hi = parse_port(p, &end);
        if (*end == '-') {
            hi = parse_port(end + 1, &end);
        }
        tlo = lo;
        thi = hi;
        if (*end == ':') {
            tlo = thi = parse_port(end + 1, &end);
            if (*end == '-') {
                thi = parse_port(end + 1, &end);
            }
        }
        if (*end || hi < lo || thi - tlo != hi - lo) {
            die("Invalid port specification %s", p);
        }
        for (port = lo; port <= hi; port++) {
            Forward f = { .udp = udp, .host = host, .host_port = port,
                          .guest_port = tlo + (port - lo) };

            if (!excluded[port]) {
                g_array_append_val(conf.fwd, f);
            }
        }
    }
    if (all) {
        /* the ports the host does not use, but the ephemeral ones */
        int port;

        for (port = 1; port < 49152; port++) {
            Forward f = { .udp = udp, .host = host, .host_port = port,
                          .guest_port = port };

            if (!excluded[port]) {
                g_array_append_val(conf.fwd, f);
            }
        }
    }
}

enum {
    OPT_TRACE = 256, OPT_VERSION, OPT_LOG_SIZE, OPT_OUT_IF4, OPT_OUT_IF6,
    OPT_DNS_FWD, OPT_DNS_HOST, OPT_NO_DHCP_DNS, OPT_NO_DHCP_SEARCH, OPT_FQDN,
    OPT_MAP_LOOPBACK, OPT_NO_MAP_GW, OPT_MAP_GUEST, OPT_NO_TCP, OPT_NO_UDP,
    OPT_NO_ICMP, OPT_NO_DHCP, OPT_NO_NDP, OPT_NO_DHCPV6, OPT_NO_RA,
    OPT_FREEBIND, OPT_VHOST_USER, OPT_PRINT_CAPS, OPT_RUNAS, OPT_REPAIR,
    OPT_MIGRATE,
};

static const struct option options[] = {
    { "debug", no_argument, NULL, 'd' },
    { "trace", no_argument, NULL, OPT_TRACE },
    { "quiet", no_argument, NULL, 'q' },
    { "foreground", no_argument, NULL, 'f' },
    { "stderr", no_argument, NULL, 'e' },
    { "log-file", required_argument, NULL, 'l' },
    { "log-size", required_argument, NULL, OPT_LOG_SIZE },
    { "version", no_argument, NULL, OPT_VERSION },
    { "help", no_argument, NULL, 'h' },
    { "socket", required_argument, NULL, 's' },
    { "socket-path", required_argument, NULL, 's' },
    { "fd", required_argument, NULL, 'F' },
    { "one-off", no_argument, NULL, '1' },
    { "pcap", required_argument, NULL, 'p' },
    { "pid", required_argument, NULL, 'P' },
    { "mtu", required_argument, NULL, 'm' },
    { "address", required_argument, NULL, 'a' },
    { "netmask", required_argument, NULL, 'n' },
    { "mac-addr", required_argument, NULL, 'M' },
    { "gateway", required_argument, NULL, 'g' },
    { "interface", required_argument, NULL, 'i' },
    { "outbound", required_argument, NULL, 'o' },
    { "outbound-if4", required_argument, NULL, OPT_OUT_IF4 },
    { "outbound-if6", required_argument, NULL, OPT_OUT_IF6 },
    { "dns", required_argument, NULL, 'D' },
    { "dns-forward", required_argument, NULL, OPT_DNS_FWD },
    { "dns-host", required_argument, NULL, OPT_DNS_HOST },
    { "no-dhcp-dns", no_argument, NULL, OPT_NO_DHCP_DNS },
    { "search", required_argument, NULL, 'S' },
    { "no-dhcp-search", no_argument, NULL, OPT_NO_DHCP_SEARCH },
    { "hostname", required_argument, NULL, 'H' },
    { "fqdn", required_argument, NULL, OPT_FQDN },
    { "map-host-loopback", required_argument, NULL, OPT_MAP_LOOPBACK },
    { "no-map-gw", no_argument, NULL, OPT_NO_MAP_GW },
    { "map-guest-addr", required_argument, NULL, OPT_MAP_GUEST },
    { "ipv4-only", no_argument, NULL, '4' },
    { "ipv6-only", no_argument, NULL, '6' },
    { "tcp-ports", required_argument, NULL, 't' },
    { "udp-ports", required_argument, NULL, 'u' },
    { "no-tcp", no_argument, NULL, OPT_NO_TCP },
    { "no-udp", no_argument, NULL, OPT_NO_UDP },
    { "no-icmp", no_argument, NULL, OPT_NO_ICMP },
    { "no-dhcp", no_argument, NULL, OPT_NO_DHCP },
    { "no-ndp", no_argument, NULL, OPT_NO_NDP },
    { "no-dhcpv6", no_argument, NULL, OPT_NO_DHCPV6 },
    { "no-ra", no_argument, NULL, OPT_NO_RA },
    { "freebind", no_argument, NULL, OPT_FREEBIND },
    { "vhost-user", no_argument, NULL, OPT_VHOST_USER },
    { "print-capabilities", no_argument, NULL, OPT_PRINT_CAPS },
    { "runas", required_argument, NULL, OPT_RUNAS },
    { "repair-path", required_argument, NULL, OPT_REPAIR },
    { "migrate-exit", no_argument, NULL, OPT_MIGRATE },
    { "migrate-no-linger", no_argument, NULL, OPT_MIGRATE },
    { NULL, 0, NULL, 0 }
};

static void parse_options(int argc, char **argv)
{
    int c, family;
    uint8_t addr[16];

    conf.dns4 = g_ptr_array_new_with_free_func(g_free);
    conf.dns6 = g_ptr_array_new_with_free_func(g_free);
    conf.search = g_ptr_array_new_with_free_func(g_free);
    conf.fwd = g_array_new(false, false, sizeof(Forward));

    while ((c = getopt_long(argc, argv,
                            "dqfel:s:F:1p:P:m:a:n:M:g:i:o:D:S:H:46t:u:T:U:h",
                            options, NULL)) != -1) {
        switch (c) {
        case 'd':
        case OPT_TRACE:
            conf.debug = true;
            break;
        case 'q':
            conf.quiet = true;
            break;
        case 'f':
            conf.foreground = true;
            break;
        case 'e':
            conf.use_stderr = true;
            break;
        case 'l':
            conf.log_file = g_strdup(optarg);
            break;
        case OPT_LOG_SIZE:
        case 'H':
        case OPT_DNS_HOST:
        case OPT_RUNAS:
        case OPT_REPAIR:
        case OPT_MIGRATE:
            break;
        case OPT_VERSION:
            printf("%s\n", PASST_VERSION);
            exit(EXIT_SUCCESS);
        case 'h':
            usage(stdout, EXIT_SUCCESS);
            break;
        case 's':
            conf.socket_path = g_strdup(optarg);
            break;
        case 'F':
            conf.fd = strtoll(optarg, NULL, 0);
            conf.one_off = true;
            break;
        case '1':
            conf.one_off = true;
            break;
        case 'p':
            conf.pcap = g_strdup(optarg);
            break;
        case 'P':
            conf.pidfile = g_strdup(optarg);
            break;
        case 'm':
            conf.mtu = atoi(optarg);
            if (conf.mtu < 68 || conf.mtu > 65520) {
                die("Invalid MTU: %s", optarg);
            }
            break;
        case 'a':
            if (!parse_addr(optarg, &family, addr)) {
                die("Invalid address: %s", optarg);
            }
            if (family == AF_INET) {
                memcpy(&conf.addr4, addr, 4);
                conf.have_addr4 = true;
                if (!conf.have_mask4) {
                    uint32_t a = ntohl(conf.addr4.s_addr);

                    /* the class of the address, as passt does */
                    conf.prefix_len4 = a >> 31 == 0 ? 8 :
                                       a >> 30 == 2 ? 16 : 24;
                    conf.mask4 = mask_of_prefix(conf.prefix_len4);
                }
            } else {
                memcpy(&conf.addr6, addr, 16);
                conf.have_addr6 = true;
                conf.prefix_len6 = 64;
            }
            break;
        case 'n': {
            char *end;
            long bits = strtol(optarg, &end, 10);

            if (!*end && bits >= 0 && bits <= 32) {
                conf.prefix_len4 = bits;
                conf.mask4 = mask_of_prefix(bits);
            } else if (inet_pton(AF_INET, optarg, &conf.mask4) == 1) {
                conf.prefix_len4 = prefix_of_mask(conf.mask4);
            } else {
                die("Invalid netmask: %s", optarg);
            }
            conf.have_mask4 = true;
            break;
        }
        case 'M': {
            unsigned int m[6];

            if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2],
                       &m[3], &m[4], &m[5]) != 6) {
                die("Invalid MAC address: %s", optarg);
            }
            for (family = 0; family < 6; family++) {
                conf.mac[family] = m[family];
            }
            conf.have_mac = true;
            break;
        }
        case 'g':
            if (!parse_addr(optarg, &family, addr)) {
                die("Invalid gateway address: %s", optarg);
            }
            if (family == AF_INET) {
                memcpy(&conf.gw4, addr, 4);
                conf.have_gw4 = true;
            } else {
                memcpy(&conf.gw6, addr, 16);
                conf.have_gw6 = true;
            }
            break;
        case 'i':
            conf.iface = g_strdup(optarg);
            break;
        case 'o':
            if (!parse_addr(optarg, &family, addr)) {
                die("Invalid outbound address: %s", optarg);
            }
            if (family == AF_INET) {
                conf.outbound4 = g_strdup(optarg);
            } else {
                conf.outbound6 = g_strdup(optarg);
            }
            break;
        case OPT_OUT_IF4:
            conf.outbound_if4 = g_strdup(optarg);
            break;
        case OPT_OUT_IF6:
            conf.outbound_if6 = g_strdup(optarg);
            break;
        case 'D':
            if (!strcmp(optarg, "none")) {
                conf.dns_none = true;
                break;
            }
            if (!parse_addr(optarg, &family, addr)) {
                die("Invalid DNS address: %s", optarg);
            }
            if (family == AF_INET) {
                g_ptr_array_add(conf.dns4, g_memdup2(addr, 4));
            } else {
                g_ptr_array_add(conf.dns6, g_memdup2(addr, 16));
            }
            break;
        case OPT_DNS_FWD:
            if (!parse_addr(optarg, &family, addr)) {
                die("Invalid DNS forwarding address: %s", optarg);
            }
            if (family == AF_INET) {
                memcpy(&conf.dns_fwd4, addr, 4);
                conf.have_dns_fwd4 = true;
            } else {
                memcpy(&conf.dns_fwd6, addr, 16);
                conf.have_dns_fwd6 = true;
            }
            break;
        case OPT_NO_DHCP_DNS:
            conf.no_dhcp_dns = true;
            break;
        case 'S':
            if (!strcmp(optarg, "none")) {
                conf.search_none = true;
            } else {
                g_auto(GStrv) l = g_strsplit(optarg, " ", -1);
                int i;

                for (i = 0; l[i]; i++) {
                    if (*l[i]) {
                        g_ptr_array_add(conf.search, g_strdup(l[i]));
                    }
                }
            }
            break;
        case OPT_NO_DHCP_SEARCH:
            conf.no_dhcp_search = true;
            break;
        case OPT_FQDN:
            conf.fqdn = g_strdup(optarg);
            break;
        case OPT_MAP_LOOPBACK:
            if (!strcmp(optarg, "none")) {
                conf.no_map_gw = true;
            } else if (inet_pton(AF_INET, optarg,
                                 &conf.map_loopback4) == 1) {
                conf.have_map_loopback4 = true;
            } else if (!parse_addr(optarg, &family, addr)) {
                die("Invalid address: %s", optarg);
            }
            break;
        case OPT_NO_MAP_GW:
            conf.no_map_gw = true;
            break;
        case OPT_MAP_GUEST:
            if (inet_pton(AF_INET, optarg, &conf.map_guest4) == 1) {
                conf.have_map_guest4 = true;
            } else if (strcmp(optarg, "none") &&
                       !parse_addr(optarg, &family, addr)) {
                die("Invalid address: %s", optarg);
            }
            break;
        case '4':
            conf.v6 = false;
            break;
        case '6':
            conf.v4 = false;
            break;
        case 't':
            parse_forward(optarg, false);
            break;
        case 'u':
            parse_forward(optarg, true);
            break;
        case 'T':
        case 'U':
            die("-%c is for pasta only", c);
        case OPT_NO_TCP:
            conf.no_tcp = true;
            break;
        case OPT_NO_UDP:
            conf.no_udp = true;
            break;
        case OPT_NO_ICMP:
            conf.no_icmp = true;
            break;
        case OPT_NO_DHCP:
            conf.no_dhcp = true;
            break;
        case OPT_NO_NDP:
            conf.no_ndp = true;
            break;
        case OPT_NO_DHCPV6:
            conf.no_dhcpv6 = true;
            break;
        case OPT_NO_RA:
            conf.no_ra = true;
            break;
        case OPT_FREEBIND:
            conf.freebind = true;
            break;
        case OPT_VHOST_USER:
            conf.vhost_user = true;
            break;
        case OPT_PRINT_CAPS:
            printf("{\n  \"type\": \"net\"\n}\n");
            exit(EXIT_SUCCESS);
        default:
            usage(stderr, EXIT_FAILURE);
        }
    }
    if (optind < argc) {
        usage(stderr, EXIT_FAILURE);
    }
    if (!conf.v4 && !conf.v6) {
        die("Options ipv4-only and ipv6-only are mutually exclusive");
    }
}

/* ------------------------------------------------------------------ */
/* pcap                                                                */

static FILE *pcap_fp;

static void pcap_open(void)
{
    struct {
        uint32_t magic;
        uint16_t major, minor;
        int32_t zone;
        uint32_t sigfigs, snaplen, linktype;
    } hdr = { 0xa1b2c3d4, 2, 4, 0, 0, FRAME_MAX, 1 };

    if (!conf.pcap) {
        return;
    }
    pcap_fp = fopen(conf.pcap, "wb");
    if (!pcap_fp) {
        die("Cannot open %s: %s", conf.pcap, strerror(errno));
    }
    fwrite(&hdr, sizeof(hdr), 1, pcap_fp);
    fflush(pcap_fp);
    info("Saving packet capture to %s", conf.pcap);
}

static void pcap_frame(const void *buf, size_t len)
{
    struct {
        uint32_t sec, usec, caplen, len;
    } rec;
    gint64 now = g_get_real_time();

    if (!pcap_fp) {
        return;
    }
    rec.sec = now / G_USEC_PER_SEC;
    rec.usec = now % G_USEC_PER_SEC;
    rec.caplen = rec.len = len;
    fwrite(&rec, sizeof(rec), 1, pcap_fp);
    fwrite(buf, 1, len, pcap_fp);
    fflush(pcap_fp);
}

/* ------------------------------------------------------------------ */
/* slirp                                                               */

typedef struct Timer {
    SlirpTimerCb cb;
    void *opaque;
    int64_t expire;           /* ms, -1 = not armed */
    struct Timer *next;
} Timer;

static Slirp *slirp;
static Timer *timers;
static WSAEVENT net_event;    /* any socket: slirp's and the guest's */
static int tap_fd = -1;       /* stream mode: the connection to the guest */
static int listen_fd = -1;    /* --socket */
static VuDev vudev;           /* vhost-user mode */
static bool vu_running;

static int64_t clock_ns(void *opaque)
{
    return g_get_monotonic_time() * 1000;
}

static void *timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
    Timer *t = g_new0(Timer, 1);

    t->cb = cb;
    t->opaque = cb_opaque;
    t->expire = -1;
    t->next = timers;
    timers = t;
    return t;
}

static void timer_free(void *timer, void *opaque)
{
    Timer **p;

    for (p = &timers; *p; p = &(*p)->next) {
        if (*p == timer) {
            *p = ((Timer *)timer)->next;
            g_free(timer);
            return;
        }
    }
}

static void timer_mod(void *timer, int64_t expire_ms, void *opaque)
{
    ((Timer *)timer)->expire = expire_ms;
}

static void timers_run(void)
{
    int64_t now = g_get_monotonic_time() / 1000;
    Timer *t;

    for (t = timers; t; t = t->next) {
        if (t->expire >= 0 && t->expire <= now) {
            t->expire = -1;
            t->cb(t->opaque);
            break;      /* the list may have changed: next time */
        }
    }
}

static uint32_t timers_timeout(uint32_t timeout)
{
    int64_t now = g_get_monotonic_time() / 1000;
    Timer *t;

    for (t = timers; t; t = t->next) {
        if (t->expire >= 0) {
            int64_t left = MAX(t->expire - now, 0);

            timeout = MIN(timeout, (uint32_t)MIN(left, UINT32_MAX - 1));
        }
    }
    return timeout;
}

static void guest_error(const char *msg, void *opaque)
{
    warn("%s", msg);
}

static void notify(void *opaque)
{
    WSASetEvent(net_event);
}

static void register_poll_socket(slirp_os_socket s, void *opaque)
{
    /* FD_WRITE comes once a send() could not go through: no busy loop */
    WSAEventSelect(s, net_event, FD_READ | FD_WRITE | FD_ACCEPT |
                   FD_CONNECT | FD_CLOSE | FD_OOB);
}

static void unregister_poll_socket(slirp_os_socket s, void *opaque)
{
    WSAEventSelect(s, NULL, 0);
}

/* send() and recv() of QEMU take a descriptor, as on Linux */
static ssize_t send_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = send(fd, p + done, len - done, 0);

        if (n < 0) {
            fd_set wr;

            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
            FD_ZERO(&wr);
            FD_SET((SOCKET)_get_osfhandle(fd), &wr);
            select(0, NULL, &wr, NULL, NULL);
            continue;
        }
        done += n;
    }
    return done;
}

static void vu_send_frame(const uint8_t *buf, size_t len);
static void from_guest(uint8_t *f, size_t len);
static void translate_in(uint8_t *f, size_t len);
static void slirp_learn_guest(void);
static bool guest_mac_known, learn_pending;

static void to_guest(const uint8_t *buf, size_t len)
{
    uint32_t be = htonl(len);

    pcap_frame(buf, len);
    if (conf.vhost_user) {
        vu_send_frame(buf, len);
        return;
    }
    if (tap_fd < 0) {
        return;         /* no guest yet: dropped, as a cable unplugged */
    }
    if (send_all(tap_fd, &be, 4) < 0 || send_all(tap_fd, buf, len) < 0) {
        debug("tap: send failed");
    }
}

/* a frame of libslirp */
static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    static uint8_t f[FRAME_MAX + 64];
    const uint8_t *b = buf;

    if (len > sizeof(f) || len < 14) {
        return len;
    }
    if (b[12] == 0x08 && b[13] == 0x06) {
        /* ARP of libslirp: it asks for the guest, it knows from us */
        if (conf.v4 && len >= 42 && b[21] == 1 && guest_mac_known) {
            learn_pending = true;       /* not from inside libslirp */
        }
        return len;
    }
    memcpy(f, buf, len);
    if (conf.v4) {
        translate_in(f, len);
    }
    to_guest(f, len);
    return len;
}

static const SlirpCb callbacks = {
    .send_packet = send_packet,
    .guest_error = guest_error,
    .clock_get_ns = clock_ns,
    .timer_new = timer_new,
    .timer_free = timer_free,
    .timer_mod = timer_mod,
    .notify = notify,
    .register_poll_socket = register_poll_socket,
    .unregister_poll_socket = unregister_poll_socket,
};

/* ------------------------------------------------------------------ */
/* IPv4: the guest's view and libslirp's                               */

/*
 * libslirp takes every address of its virtual network for the host
 * itself: with the host's network there, the guest could reach neither its
 * gateway nor the other machines of that network.  libslirp gets a network
 * of its own, and the frames are translated between the two views:
 *
 *   guest's view                          libslirp's
 *   the guest's address (the host's)  <-> 10.0.2.15
 *   gateway (--map-host-loopback)     <-> 10.0.2.2, the host
 *   DNS forwarder, port 53            <-> 10.0.2.3, the host's resolver
 *   any other address                     as is, reached from host sockets
 *
 * ARP and DHCP are answered here, as passt does: every address but the
 * guest's has our MAC address.
 */
#define S_GUEST 0x0a00020fu
#define S_HOST  0x0a000202u
#define S_DNS   0x0a000203u

static const uint8_t our_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
static uint8_t guest_mac[6];
static uint32_t g_addr, g_gw, g_loop, g_dns_fwd;     /* network order */
static bool g_map_loop, g_have_dns_fwd;
static GArray *g_dns;                                /* uint32_t */

static uint16_t csum_fold(uint32_t s)
{
    while (s >> 16) {
        s = (s & 0xffff) + (s >> 16);
    }
    return ~s;
}

static uint32_t csum_add(uint32_t s, const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i += 2) {
        s += (p[i] << 8) | p[i + 1];
    }
    if (len & 1) {
        s += p[len - 1] << 8;
    }
    return s;
}

/* RFC 1624: @sum (network order) after a 32-bit word went @from -> @to */
static void csum_replace4(uint8_t *sum, uint32_t from, uint32_t to)
{
    uint32_t s = (uint16_t)~((sum[0] << 8) | sum[1]);

    from = ntohl(from);
    to = ntohl(to);
    s += (uint16_t)~(from >> 16) + (uint16_t)~(from & 0xffff);
    s += (to >> 16) + (to & 0xffff);
    s = csum_fold(s);
    sum[0] = s >> 8;
    sum[1] = s;
}

static uint32_t rd32(const uint8_t *p)
{
    uint32_t v;

    memcpy(&v, p, 4);
    return v;
}

/* change the IPv4 address at @a, with the checksums that cover it */
static void ip_set(uint8_t *ip, uint8_t *a, uint32_t to, uint8_t *l4sum,
                   bool udp)
{
    uint32_t from = rd32(a);

    if (from == to) {
        return;
    }
    memcpy(a, &to, 4);
    csum_replace4(ip + 10, from, to);
    if (l4sum && !(udp && !l4sum[0] && !l4sum[1])) {
        csum_replace4(l4sum, from, to);
        if (udp && !l4sum[0] && !l4sum[1]) {
            l4sum[0] = l4sum[1] = 0xff;
        }
    }
}

/* the checksum of the TCP or UDP header of a packet, NULL without one */
static uint8_t *l4_csum(uint8_t *ip, size_t len, bool *udp, uint16_t *dport,
                        uint16_t *sport)
{
    size_t ihl = (ip[0] & 15) * 4;
    uint8_t *l4 = ip + ihl;

    *udp = ip[9] == 17;
    *dport = *sport = 0;
    if ((((ip[6] << 8) | ip[7]) & 0x1fff) || len < ihl + 8) {
        return NULL;        /* a fragment, but the first one */
    }
    *sport = (l4[0] << 8) | l4[1];
    *dport = (l4[2] << 8) | l4[3];
    if (ip[9] == 6 && len >= ihl + 18) {
        return l4 + 16;
    }
    if (ip[9] == 17) {
        return l4 + 6;
    }
    return NULL;
}

static bool is_dns_fwd(uint32_t a)
{
    return g_have_dns_fwd && a == g_dns_fwd;
}

/* a frame of the guest, for libslirp; false to drop it */
static bool translate_out(uint8_t *f, size_t len)
{
    uint8_t *ip = f + 14, *sum;
    uint16_t dport, sport;
    uint32_t dst;
    bool udp;

    if (len < 34 || (ip[0] >> 4) != 4) {
        return true;
    }
    len -= 14;
    sum = l4_csum(ip, len, &udp, &dport, &sport);
    if (rd32(ip + 12) == g_addr) {
        ip_set(ip, ip + 12, htonl(S_GUEST), sum, udp);
    }
    dst = rd32(ip + 16);
    if (is_dns_fwd(dst) && dport == 53 && (ip[9] == 6 || ip[9] == 17)) {
        ip_set(ip, ip + 16, htonl(S_DNS), sum, udp);
    } else if (g_map_loop && dst == g_loop) {
        ip_set(ip, ip + 16, htonl(S_HOST), sum, udp);
    }
    return true;
}

static uint32_t view_of(uint32_t a)
{
    if (a == htonl(S_GUEST)) {
        return g_addr;
    }
    if (a == htonl(S_HOST)) {
        return g_loop;
    }
    if (a == htonl(S_DNS)) {
        return g_dns_fwd;
    }
    return a;
}

/* a frame of libslirp, for the guest */
static void translate_in(uint8_t *f, size_t len)
{
    uint8_t *ip = f + 14, *sum;
    uint16_t dport, sport;
    bool udp;

    if (len < 34 || (ip[0] >> 4) != 4) {
        return;
    }
    len -= 14;
    sum = l4_csum(ip, len, &udp, &dport, &sport);
    ip_set(ip, ip + 12, view_of(rd32(ip + 12)), sum, udp);
    ip_set(ip, ip + 16, view_of(rd32(ip + 16)), sum, udp);

    /* ICMP errors: the packet they quote, and their checksum */
    if (ip[9] == 1) {
        size_t ihl = (ip[0] & 15) * 4;
        uint8_t *icmp = ip + ihl, *inner = icmp + 8;
        uint32_t s;

        if (len >= ihl + 8 + 20 && (icmp[0] == 3 || icmp[0] == 4 ||
                                    icmp[0] == 5 || icmp[0] == 11 ||
                                    icmp[0] == 12)) {
            ip_set(inner, inner + 12, view_of(rd32(inner + 12)), NULL, false);
            ip_set(inner, inner + 16, view_of(rd32(inner + 16)), NULL, false);
        }
        if (len >= ihl + 4) {
            icmp[2] = icmp[3] = 0;
            s = csum_fold(csum_add(0, icmp, len - ihl));
            icmp[2] = s >> 8;
            icmp[3] = s;
        }
    }
}

static void put32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

/* ARP: what libslirp knows of the guest, as if the guest had asked */
static void slirp_learn_guest(void)
{
    uint8_t f[42] = { 0 };

    memset(f, 0xff, 6);
    memcpy(f + 6, guest_mac, 6);
    f[12] = 0x08; f[13] = 0x06;                 /* ARP */
    f[15] = 1; f[16] = 0x08; f[18] = 6; f[19] = 4;
    f[21] = 1;                                  /* request */
    memcpy(f + 22, guest_mac, 6);
    put32(f + 28, htonl(S_GUEST));
    put32(f + 38, htonl(S_HOST));
    slirp_input(slirp, f, sizeof(f));
}

/* ARP request of the guest: every address but its own is ours */
static void arp_reply(const uint8_t *req, size_t len)
{
    uint8_t f[42];

    if (len < 42 || req[21] != 1 || rd32(req + 38) == g_addr ||
        rd32(req + 38) == rd32(req + 28)) {
        return;
    }
    memcpy(f, req + 6, 6);
    memcpy(f + 6, our_mac, 6);
    memcpy(f + 12, req + 12, 8);
    f[20] = 0;
    f[21] = 2;                                  /* reply */
    memcpy(f + 22, our_mac, 6);
    memcpy(f + 28, req + 38, 4);
    memcpy(f + 32, req + 22, 10);
    to_guest(f, sizeof(f));
}

/* DHCP: the guest gets the host's address, mask, gateway, DNS, domains */
static void dhcp_answer(const uint8_t *f, size_t len)
{
    const uint8_t *ip = f + 14, *udp, *b, *opt;
    uint8_t r[600] = { 0 }, *o, *rip, *rudp, *rb;
    int type = 0, out;
    uint32_t requested = 0, s;
    size_t ihl, n, i;

    if (len < 14 + 20 + 8 + 240) {
        return;
    }
    ihl = (ip[0] & 15) * 4;
    udp = ip + ihl;
    b = udp + 8;
    if (b + 240 > f + len || b[0] != 1 ||
        memcmp(b + 236, "\x63\x82\x53\x63", 4)) {
        return;
    }
    for (opt = b + 240; opt < f + len && *opt != 255;) {
        if (*opt == 0) {
            opt++;
            continue;
        }
        if (opt + 2 > f + len || opt + 2 + opt[1] > f + len) {
            break;
        }
        if (opt[0] == 53 && opt[1] >= 1) {
            type = opt[2];
        } else if (opt[0] == 50 && opt[1] == 4) {
            requested = rd32(opt + 2);
        }
        opt += 2 + opt[1];
    }
    switch (type) {
    case 1:                                     /* DISCOVER */
        out = 2;                                /* OFFER */
        break;
    case 3:                                     /* REQUEST */
        out = (!requested || requested == g_addr) &&
              (!rd32(b + 12) || rd32(b + 12) == g_addr) ? 5 : 6;
        break;
    case 8:                                     /* INFORM */
        out = 5;
        break;
    default:
        return;
    }

    /* Ethernet, IPv4, UDP, BOOTP */
    memcpy(r, (b[10] & 0x80) || out == 6 ? (const uint8_t *)"\xff\xff\xff"
           "\xff\xff\xff" : b + 28, 6);
    memcpy(r + 6, our_mac, 6);
    r[12] = 0x08;
    rip = r + 14;
    rudp = rip + 20;
    rb = rudp + 8;
    rb[0] = 2;
    rb[1] = 1;
    rb[2] = 6;
    memcpy(rb + 4, b + 4, 4);                   /* xid */
    memcpy(rb + 10, b + 10, 2);                 /* flags */
    memcpy(rb + 12, b + 12, 4);                 /* ciaddr */
    if (out != 6 && type != 8) {
        put32(rb + 16, g_addr);                 /* yiaddr */
    }
    put32(rb + 20, g_gw);                       /* siaddr */
    memcpy(rb + 28, b + 28, 16);                /* chaddr */
    memcpy(rb + 236, "\x63\x82\x53\x63", 4);
    o = rb + 240;
    *o++ = 53; *o++ = 1; *o++ = out;
    *o++ = 54; *o++ = 4; put32(o, g_gw); o += 4;
    if (out != 6) {
        uint32_t mask = mask_of_prefix(conf.prefix_len4).s_addr;

        *o++ = 51; *o++ = 4; put32(o, 0xffffffff); o += 4;
        *o++ = 1; *o++ = 4; put32(o, mask); o += 4;
        *o++ = 3; *o++ = 4; put32(o, g_gw); o += 4;
        if (!conf.no_dhcp_dns && !conf.dns_none && g_dns->len) {
            n = MIN(g_dns->len, 8);
            *o++ = 6; *o++ = n * 4;
            for (i = 0; i < n; i++) {
                put32(o, g_array_index(g_dns, uint32_t, i));
                o += 4;
            }
        }
        if (conf.mtu) {
            *o++ = 26; *o++ = 2; *o++ = conf.mtu >> 8; *o++ = conf.mtu;
        }
        if (!conf.no_dhcp_search && !conf.search_none && conf.search->len) {
            const char *dom = g_ptr_array_index(conf.search, 0);
            uint8_t enc[256], *e = enc;

            n = MIN(strlen(dom), 64);
            *o++ = 15; *o++ = n; memcpy(o, dom, n); o += n;
            /* option 119: names in DNS encoding */
            for (i = 0; i < conf.search->len; i++) {
                g_auto(GStrv) labels = g_strsplit(
                    g_ptr_array_index(conf.search, i), ".", -1);
                int k;

                for (k = 0; labels[k]; k++) {
                    size_t l = strlen(labels[k]);

                    if (!l || l > 63 || e + l + 2 > enc + sizeof(enc) - 1) {
                        continue;
                    }
                    *e++ = l;
                    memcpy(e, labels[k], l);
                    e += l;
                }
                *e++ = 0;
            }
            if (e - enc <= 255) {
                *o++ = 119; *o++ = e - enc;
                memcpy(o, enc, e - enc);
                o += e - enc;
            }
        }
    }
    *o++ = 255;
    n = MAX(o - rb, 300);                       /* BOOTP minimum size */

    rip[0] = 0x45;
    rip[2] = (20 + 8 + n) >> 8;
    rip[3] = 20 + 8 + n;
    rip[8] = 64;
    rip[9] = 17;
    put32(rip + 12, g_gw);
    put32(rip + 16, out == 6 || !rd32(b + 12) ? 0xffffffff : rd32(b + 12));
    s = csum_fold(csum_add(0, rip, 20));
    rip[10] = s >> 8;
    rip[11] = s;
    rudp[1] = 67;
    rudp[3] = 68;
    rudp[4] = (8 + n) >> 8;
    rudp[5] = 8 + n;                            /* no UDP checksum */
    to_guest(r, 14 + 20 + 8 + n);
}

/* a frame from the guest */
static void from_guest(uint8_t *f, size_t len)
{
    pcap_frame(f, len);
    if (len < 14) {
        return;
    }
    if (conf.v4 && (!guest_mac_known || memcmp(guest_mac, f + 6, 6)) &&
        !(f[6] & 1)) {
        memcpy(guest_mac, f + 6, 6);
        guest_mac_known = true;
        slirp_learn_guest();
    }
    if (f[12] == 0x08 && f[13] == 0x06) {
        if (conf.v4) {
            arp_reply(f, len);
        }
        return;
    }
    if (conf.v4 && f[12] == 0x08 && f[13] == 0x00 && len >= 14 + 28) {
        const uint8_t *ip = f + 14;
        size_t ihl = (ip[0] & 15) * 4;

        if (ip[9] == 17 && len >= 14 + ihl + 8 &&
            ((ip[ihl + 2] << 8) | ip[ihl + 3]) == 67) {
            if (!conf.no_dhcp) {
                dhcp_answer(f, len);
            }
            return;
        }
        if (!translate_out(f, len)) {
            return;
        }
    }
    slirp_input(slirp, f, len);
}

static void ipv4_view(void)
{
    guint i;

    g_dns = g_array_new(false, false, sizeof(uint32_t));
    if (!conf.v4) {
        return;
    }
    g_addr = conf.addr4.s_addr;
    g_gw = conf.gw4.s_addr;
    g_map_loop = !conf.no_map_gw;
    g_loop = conf.have_map_loopback4 ? conf.map_loopback4.s_addr : g_gw;
    if (conf.have_dns_fwd4) {
        g_dns_fwd = conf.dns_fwd4.s_addr;
        g_have_dns_fwd = true;
    }
    /*
     * The resolvers of the host, as they are; one on the host itself (or
     * on the address mapped to it) is reached through the gateway, which
     * forwards DNS to the host's resolver
     */
    for (i = 0; i < conf.dns4->len; i++) {
        struct in_addr *d = g_ptr_array_index(conf.dns4, i);
        uint32_t a = d->s_addr;

        if ((ntohl(a) >> 24) == 127 || (g_map_loop && a == g_loop)) {
            if (!g_have_dns_fwd) {
                g_dns_fwd = g_loop;
                g_have_dns_fwd = true;
            }
            a = g_dns_fwd;
        }
        g_array_append_val(g_dns, a);
    }
    if (!g_dns->len && !conf.dns_none && g_map_loop) {
        g_dns_fwd = g_loop;
        g_have_dns_fwd = true;
        g_array_append_val(g_dns, g_dns_fwd);
    }
}

static void slirp_start(void)
{
    SlirpConfig cfg = { .version = 6 };
    static struct sockaddr_in out4;
    static struct sockaddr_in6 out6;
    static const char *search[64];
    guint i;

    ipv4_view();
    cfg.restricted = 0;
    cfg.in_enabled = conf.v4;
    if (conf.v4) {
        cfg.vnetwork.s_addr = htonl(S_GUEST & 0xffffff00);
        cfg.vnetmask.s_addr = htonl(0xffffff00);
        cfg.vhost.s_addr = htonl(S_HOST);
        cfg.vnameserver.s_addr = htonl(S_DNS);
        cfg.vdhcp_start.s_addr = htonl(S_GUEST);
        cfg.disable_dhcp = true;            /* answered here */
    }
    cfg.in6_enabled = conf.v6;
    if (conf.v6) {
        cfg.vprefix_addr6 = conf.addr6;
        memset(cfg.vprefix_addr6.s6_addr + 8, 0, 8);
        cfg.vprefix_len = 64;
        cfg.vhost6 = cfg.vprefix_addr6;
        cfg.vhost6.s6_addr[15] = 2;
        cfg.vnameserver6 = conf.have_dns_fwd6 ? conf.dns_fwd6 :
                           cfg.vprefix_addr6;
        if (!conf.have_dns_fwd6) {
            cfg.vnameserver6.s6_addr[15] = 3;
        }
    }
    if (!conf.no_dhcp_search && !conf.search_none) {
        for (i = 0; i < conf.search->len && i < G_N_ELEMENTS(search) - 1;
             i++) {
            search[i] = g_ptr_array_index(conf.search, i);
        }
        cfg.vdnssearch = conf.search->len ? search : NULL;
        if (conf.search->len) {
            cfg.vdomainname = search[0];
        }
    }
    cfg.vhostname = NULL;
    cfg.if_mtu = conf.mtu ? conf.mtu : 65520;
    cfg.if_mru = cfg.if_mtu;
    cfg.disable_host_loopback = conf.no_map_gw;
    if (conf.outbound4 || conf.outbound_if4) {
        struct sockaddr_storage ss;

        out4.sin_family = AF_INET;
        if (conf.outbound4) {
            inet_pton(AF_INET, conf.outbound4, &out4.sin_addr);
        } else if (interface_address(conf.outbound_if4, AF_INET, &ss)) {
            out4 = *(struct sockaddr_in *)&ss;
            out4.sin_port = 0;
        } else {
            die("Invalid interface name %s", conf.outbound_if4);
        }
        cfg.outbound_addr = &out4;
    }
    if (conf.outbound6 || conf.outbound_if6) {
        struct sockaddr_storage ss;

        out6.sin6_family = AF_INET6;
        if (conf.outbound6) {
            inet_pton(AF_INET6, conf.outbound6, &out6.sin6_addr);
        } else if (interface_address(conf.outbound_if6, AF_INET6, &ss)) {
            out6 = *(struct sockaddr_in6 *)&ss;
            out6.sin6_port = 0;
        } else {
            die("Invalid interface name %s", conf.outbound_if6);
        }
        cfg.outbound_addr6 = &out6;
    }

    slirp = slirp_new(&cfg, &callbacks, NULL);
    if (!slirp) {
        die("Cannot set up the network stack");
    }

    if (conf.v4) {
        char a[INET_ADDRSTRLEN], g[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
        GString *dns = g_string_new(NULL);

        inet_ntop(AF_INET, &g_addr, a, sizeof(a));
        inet_ntop(AF_INET, &g_gw, g, sizeof(g));
        for (i = 0; i < g_dns->len; i++) {
            inet_ntop(AF_INET, &g_array_index(g_dns, uint32_t, i), d,
                      sizeof(d));
            g_string_append_printf(dns, "%s%s", i ? ", " : "", d);
        }
        info("IPv4: address %s/%d, gateway %s, DNS %s", a, conf.prefix_len4,
             g, dns->len ? dns->str : "none");
        if (g_have_dns_fwd) {
            inet_ntop(AF_INET, &g_dns_fwd, d, sizeof(d));
            info("DNS forwarding: %s -> resolver of the host", d);
        }
        g_string_free(dns, TRUE);
    }
    if (conf.v6) {
        char a[INET6_ADDRSTRLEN], g[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &cfg.vprefix_addr6, a, sizeof(a));
        inet_ntop(AF_INET6, &cfg.vhost6, g, sizeof(g));
        info("IPv6: prefix %s/64, gateway %s", a, g);
    }
    info("MTU: %d", (int)cfg.if_mtu);

    /* port forwarding: the guest gets what reaches these host ports */
    for (i = 0; i < conf.fwd->len; i++) {
        Forward *f = &g_array_index(conf.fwd, Forward, i);
        int family = f->host.ss_family;
        bool ok = false;

        if ((f->udp && conf.no_udp) || (!f->udp && conf.no_tcp)) {
            continue;
        }
        if (conf.v4 && (family == AF_INET || family == 0)) {
            struct sockaddr_in h = { .sin_family = AF_INET };
            struct sockaddr_in g = { .sin_family = AF_INET };

            if (family == AF_INET) {
                h = *(struct sockaddr_in *)&f->host;
            }
            h.sin_port = htons(f->host_port);
            g.sin_addr.s_addr = htonl(S_GUEST);
            g.sin_port = htons(f->guest_port);
            ok |= slirp_add_hostxfwd(slirp, (struct sockaddr *)&h, sizeof(h),
                                     (struct sockaddr *)&g, sizeof(g),
                                     f->udp ? SLIRP_HOSTFWD_UDP : 0) == 0;
        }
        if (conf.v6 && (family == AF_INET6 || family == 0)) {
            struct sockaddr_in6 h = { .sin6_family = AF_INET6 };
            struct sockaddr_in6 g = { .sin6_family = AF_INET6 };

            if (family == AF_INET6) {
                h = *(struct sockaddr_in6 *)&f->host;
            }
            h.sin6_port = htons(f->host_port);
            /* the address the guest takes in the prefix: from its MAC */
            g.sin6_addr = cfg.vprefix_addr6;
            g.sin6_addr.s6_addr[15] = 0;    /* filled in by libslirp */
            g.sin6_port = htons(f->guest_port);
            ok |= slirp_add_hostxfwd(slirp, (struct sockaddr *)&h, sizeof(h),
                                     (struct sockaddr *)&g, sizeof(g),
                                     (f->udp ? SLIRP_HOSTFWD_UDP : 0) |
                                     SLIRP_HOSTFWD_V6ONLY) == 0;
        }
        if (!ok && conf.fwd->len < 64) {
            warn("Cannot forward %s port %u", f->udp ? "UDP" : "TCP",
                 f->host_port);
        }
    }
}

/* ------------------------------------------------------------------ */
/* the guest: stream mode                                              */

static uint8_t tap_buf[4 + FRAME_MAX + 4];
static size_t tap_len;

/* false when the guest went away */
static bool tap_read(void)
{
    for (;;) {
        ssize_t n = recv(tap_fd, (char *)tap_buf + tap_len,
                         sizeof(tap_buf) - tap_len, 0);

        if (n == 0) {
            return false;
        }
        if (n < 0) {
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        tap_len += n;
        for (;;) {
            uint32_t len;

            if (tap_len < 4) {
                break;
            }
            len = ntohl(*(uint32_t *)tap_buf);
            if (len > FRAME_MAX) {
                err("tap: bad frame length %u", len);
                return false;
            }
            if (tap_len < 4 + len) {
                break;
            }
            from_guest(tap_buf + 4, len);
            memmove(tap_buf, tap_buf + 4 + len, tap_len - 4 - len);
            tap_len -= 4 + len;
        }
    }
}

/* ------------------------------------------------------------------ */
/* the guest: vhost-user mode                                          */

#define VU_RX 0
#define VU_TX 1

static int vu_hdrlen = 12;
static GHashTable *vu_watches;    /* fd -> VuWatch */

typedef struct VuWatch {
    int fd;
    HANDLE handle;
    vu_watch_cb cb;
    void *data;
} VuWatch;

static void vu_send_frame(const uint8_t *buf, size_t len)
{
    VuVirtq *vq;
    VuVirtqElement *elem;
    struct virtio_net_hdr_mrg_rxbuf hdr = { .num_buffers = 1 };
    size_t done;

    if (!vu_running) {
        return;
    }
    vq = vu_get_queue(&vudev, VU_RX);
    if (!vu_queue_started(&vudev, vq) || !vu_queue_enabled(&vudev, vq)) {
        return;
    }
    elem = vu_queue_pop(&vudev, vq, sizeof(VuVirtqElement));
    if (!elem) {
        debug("vhost-user: no buffer from the guest, frame dropped");
        return;
    }
    done = iov_from_buf(elem->in_sg, elem->in_num, 0, &hdr, vu_hdrlen);
    done += iov_from_buf(elem->in_sg, elem->in_num, vu_hdrlen, buf, len);
    if (done < vu_hdrlen + len) {
        debug("vhost-user: frame of %zu bytes truncated", len);
    }
    vu_queue_push(&vudev, vq, elem, done);
    vu_queue_notify(&vudev, vq);
    free(elem);
}

static void vu_handle_tx(VuDev *dev, int qidx)
{
    VuVirtq *vq = vu_get_queue(dev, qidx);
    static uint8_t frame[FRAME_MAX + 64];

    for (;;) {
        VuVirtqElement *elem = vu_queue_pop(dev, vq, sizeof(VuVirtqElement));
        size_t len;

        if (!elem) {
            break;
        }
        len = iov_to_buf(elem->out_sg, elem->out_num, vu_hdrlen, frame,
                         sizeof(frame));
        if (len) {
            from_guest(frame, len);
        }
        vu_queue_push(dev, vq, elem, 0);
        free(elem);
    }
    vu_queue_notify(dev, vq);
}

static uint64_t vu_get_features(VuDev *dev)
{
    return 1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE |
           1ULL << VIRTIO_NET_F_MRG_RXBUF |
           1ULL << VIRTIO_NET_F_MTU |
           1ULL << VIRTIO_F_VERSION_1 |
           1ULL << VHOST_USER_F_PROTOCOL_FEATURES;
}

static void vu_set_features(VuDev *dev, uint64_t features)
{
    vu_hdrlen = features & (1ULL << VIRTIO_F_VERSION_1 |
                            1ULL << VIRTIO_NET_F_MRG_RXBUF) ? 12 : 10;
}

static uint64_t vu_get_protocol_features(VuDev *dev)
{
    return 1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK;
}

static int vu_get_config(VuDev *dev, uint8_t *config, uint32_t len)
{
    struct virtio_net_config c = { 0 };

    c.mtu = conf.mtu ? conf.mtu : 65520;
    c.status = VIRTIO_NET_S_LINK_UP;
    memcpy(config, &c, MIN(len, sizeof(c)));
    return 0;
}

static void vu_queue_set_started(VuDev *dev, int qidx, bool started)
{
    if (qidx % 2 == VU_TX) {
        vu_set_queue_handler(dev, vu_get_queue(dev, qidx),
                             started ? vu_handle_tx : NULL);
    }
}

static bool vu_in_order(VuDev *dev, int qidx)
{
    return true;
}

static void vu_panic(VuDev *dev, const char *msg)
{
    err("vhost-user: %s", msg);
    vu_running = false;
}

static void vu_set_watch(VuDev *dev, int fd, int condition, vu_watch_cb cb,
                         void *data)
{
    VuWatch *w = g_new0(VuWatch, 1);

    w->fd = fd;
    w->cb = cb;
    w->data = data;
    if (w32fd_is_token(fd)) {
        w->handle = w32fd_token_handle(fd);
    } else {
        /* a socket: through the event of all sockets */
        WSAEventSelect(_get_osfhandle(fd), net_event,
                       FD_READ | FD_CLOSE);
    }
    g_hash_table_replace(vu_watches, GINT_TO_POINTER(fd), w);
}

static void vu_remove_watch(VuDev *dev, int fd)
{
    g_hash_table_remove(vu_watches, GINT_TO_POINTER(fd));
}

static const VuDevIface vu_iface = {
    .get_features = vu_get_features,
    .set_features = vu_set_features,
    .get_protocol_features = vu_get_protocol_features,
    .get_config = vu_get_config,
    .queue_set_started = vu_queue_set_started,
    .queue_is_processed_in_order = vu_in_order,
};

/* ------------------------------------------------------------------ */
/* main loop                                                           */

typedef struct PollSet {
    WSAPOLLFD *fds;
    int n, size;
} PollSet;

static int add_poll(slirp_os_socket s, int events, void *opaque)
{
    PollSet *ps = opaque;
    WSAPOLLFD *p;

    if (ps->n == ps->size) {
        ps->size = ps->size ? ps->size * 2 : 64;
        ps->fds = g_renew(WSAPOLLFD, ps->fds, ps->size);
    }
    p = &ps->fds[ps->n];
    p->fd = s;
    p->events = 0;
    p->revents = 0;
    if (events & SLIRP_POLL_IN) {
        p->events |= POLLRDNORM;
    }
    if (events & SLIRP_POLL_OUT) {
        p->events |= POLLWRNORM;
    }
    if (events & SLIRP_POLL_PRI) {
        p->events |= POLLRDBAND;
    }
    return ps->n++;
}

static int get_revents(int idx, void *opaque)
{
    PollSet *ps = opaque;
    short r = ps->fds[idx].revents;
    int ev = 0;

    if (r & (POLLRDNORM | POLLRDBAND)) {
        ev |= SLIRP_POLL_IN;
    }
    if (r & POLLWRNORM) {
        ev |= SLIRP_POLL_OUT;
    }
    if (r & POLLRDBAND) {
        ev |= SLIRP_POLL_PRI;
    }
    if (r & POLLERR) {
        ev |= SLIRP_POLL_ERR;
    }
    if (r & POLLHUP) {
        ev |= SLIRP_POLL_HUP | SLIRP_POLL_IN;
    }
    return ev;
}

static void accept_guest(void)
{
    int fd = accept(listen_fd, NULL, NULL);

    if (fd < 0) {
        return;
    }
    if (tap_fd >= 0) {
        /* one guest at a time, as passt does */
        close(fd);
        return;
    }
    info("accepted connection from PID 0");
    tap_fd = fd;
    tap_len = 0;
    WSAEventSelect(_get_osfhandle(tap_fd), net_event, FD_READ | FD_CLOSE);
}

static void guest_gone(void)
{
    info("Client connection closed%s", conf.one_off ? ", exiting" : "");
    if (conf.one_off) {
        exit(EXIT_SUCCESS);
    }
    close(tap_fd);
    tap_fd = -1;
}

static void main_loop(void)
{
    PollSet ps = { 0 };

    for (;;) {
        uint32_t timeout = UINT32_MAX;
        int tap_idx = -1, listen_idx = -1, vu_idx = -1, n;
        HANDLE waits[MAXIMUM_WAIT_OBJECTS];
        VuWatch *wl[MAXIMUM_WAIT_OBJECTS];
        int nwaits = 0;
        GHashTableIter it;
        gpointer v;

        ps.n = 0;
        slirp_pollfds_fill_socket(slirp, &timeout, add_poll, &ps);
        if (tap_fd >= 0) {
            tap_idx = add_poll(_get_osfhandle(tap_fd), SLIRP_POLL_IN, &ps);
        }
        if (listen_fd >= 0) {
            listen_idx = add_poll(_get_osfhandle(listen_fd), SLIRP_POLL_IN,
                                  &ps);
        }
        if (conf.vhost_user && vu_running) {
            vu_idx = add_poll(_get_osfhandle(vudev.sock), SLIRP_POLL_IN, &ps);
        }

        n = ps.n ? WSAPoll(ps.fds, ps.n, 0) : 0;
        if (n == 0) {
            /* nothing ready: wait for a socket, a kick or a timer */
            waits[nwaits++] = net_event;
            if (vu_watches) {
                g_hash_table_iter_init(&it, vu_watches);
                while (g_hash_table_iter_next(&it, NULL, &v) &&
                       nwaits < MAXIMUM_WAIT_OBJECTS) {
                    VuWatch *w = v;

                    if (w->handle) {
                        wl[nwaits] = w;
                        waits[nwaits++] = w->handle;
                    }
                }
            }
            timeout = timers_timeout(timeout);
            n = WaitForMultipleObjects(nwaits, waits, FALSE,
                                       timeout == UINT32_MAX ? INFINITE :
                                       timeout);
            WSAResetEvent(net_event);
            if (n > WAIT_OBJECT_0 && n < WAIT_OBJECT_0 + nwaits) {
                VuWatch *w = wl[n - WAIT_OBJECT_0];

                w->cb(&vudev, VU_WATCH_IN, w->data);
            }
            n = ps.n ? WSAPoll(ps.fds, ps.n, 0) : 0;
        }
        slirp_pollfds_poll(slirp, n < 0, get_revents, &ps);
        if (n > 0 && listen_idx >= 0 && ps.fds[listen_idx].revents) {
            accept_guest();
        }
        if (n > 0 && tap_idx >= 0 && ps.fds[tap_idx].revents &&
            !tap_read()) {
            guest_gone();
        }
        if (n > 0 && vu_idx >= 0 && ps.fds[vu_idx].revents) {
            if (!vu_dispatch(&vudev) || !vu_running) {
                info("vhost-user: client connection closed, exiting");
                exit(EXIT_SUCCESS);
            }
        }
        /* the kicks the wait above did not report: a handle stays set */
        if (vu_watches && vu_running) {
            g_hash_table_iter_init(&it, vu_watches);
            while (g_hash_table_iter_next(&it, NULL, &v)) {
                VuWatch *w = v;

                if (w->handle && WaitForSingleObject(w->handle, 0) ==
                    WAIT_OBJECT_0) {
                    w->cb(&vudev, VU_WATCH_IN, w->data);
                    break;
                }
            }
        }
        if (learn_pending) {
            learn_pending = false;
            slirp_learn_guest();
        }
        timers_run();
    }
}

/* ------------------------------------------------------------------ */
/* start-up                                                            */

static void write_pidfile(const char *path, DWORD pid)
{
    FILE *f;

    if (!path) {
        return;
    }
    f = fopen(path, "w");
    if (!f) {
        die("Cannot write PID file %s: %s", path, strerror(errno));
    }
    fprintf(f, "%lu\n", (unsigned long)pid);
    fclose(f);
}

/*
 * The background: the same program again, with --foreground; it inherits
 * the connection of --fd.  We exit once it runs, as passt's parent does
 * after fork(), and the PID file has its PID.
 */
static void daemonize(int argc, char **argv)
{
    GString *cmd = g_string_new(NULL);
    STARTUPINFOEXW si = { 0 };
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    SIZE_T attrs_size = 0;
    HANDLE inherit[1];
    g_autofree gunichar2 *wcmd = NULL;
    wchar_t self[MAX_PATH];
    int i, ninherit = 0;

    GetModuleFileNameW(NULL, self, MAX_PATH);
    g_string_append_printf(cmd, "\"%s\" --foreground",
                           g_utf16_to_utf8((gunichar2 *)self, -1, NULL, NULL,
                                           NULL));
    for (i = 1; i < argc; i++) {
        if (strpbrk(argv[i], " \t\"") || !*argv[i]) {
            GString *a = g_string_new("\"");
            const char *p;

            for (p = argv[i]; *p; p++) {
                if (*p == '"') {
                    g_string_append_c(a, '\\');
                }
                g_string_append_c(a, *p);
            }
            g_string_append_c(a, '"');
            g_string_append_printf(cmd, " %s", a->str);
            g_string_free(a, TRUE);
        } else {
            g_string_append_printf(cmd, " %s", argv[i]);
        }
    }
    wcmd = g_utf8_to_utf16(cmd->str, -1, NULL, NULL, NULL);

    si.StartupInfo.cb = sizeof(si);
    if (conf.fd >= 0) {
        inherit[ninherit++] = (HANDLE)(intptr_t)conf.fd;
        SetHandleInformation(inherit[0], HANDLE_FLAG_INHERIT,
                             HANDLE_FLAG_INHERIT);
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrs_size);
        attrs = g_malloc(attrs_size);
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_size) ||
            !UpdateProcThreadAttribute(attrs, 0,
                                       PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       inherit, sizeof(HANDLE), NULL, NULL)) {
            die("Cannot start in background: error %lu", GetLastError());
        }
        si.lpAttributeList = attrs;
    }
    if (!CreateProcessW(NULL, (wchar_t *)wcmd, NULL, NULL, ninherit > 0,
                        (attrs ? EXTENDED_STARTUPINFO_PRESENT : 0) |
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                        NULL, NULL, &si.StartupInfo, &pi)) {
        die("Cannot start in background: error %lu", GetLastError());
    }
    write_pidfile(conf.pidfile, pi.dwProcessId);
    exit(EXIT_SUCCESS);
}

static void listen_socket(void)
{
    struct sockaddr_un un = { .sun_family = AF_UNIX };
    int i;

    if (!conf.socket_path) {
        /* the first free passt_N.socket in the temporary directory */
        for (i = 1; i < 64; i++) {
            g_autofree char *p = g_strdup_printf("%s\\passt_%d.socket",
                                                 g_get_tmp_dir(), i);

            if (!g_file_test(p, G_FILE_TEST_EXISTS)) {
                conf.socket_path = g_steal_pointer(&p);
                break;
            }
        }
        if (!conf.socket_path) {
            die("No free UNIX domain socket path");
        }
    }
    if (strlen(conf.socket_path) >= sizeof(un.sun_path)) {
        die("UNIX domain socket path too long: %s", conf.socket_path);
    }
    strcpy(un.sun_path, conf.socket_path);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0 ||
        bind(listen_fd, (struct sockaddr *)&un, sizeof(un)) < 0 ||
        listen(listen_fd, 1) < 0) {
        die("Cannot listen on %s: %s", conf.socket_path, strerror(errno));
    }
    WSAEventSelect(_get_osfhandle(listen_fd), net_event, FD_ACCEPT);
    info("UNIX domain socket bound at %s\n", conf.socket_path);
    info("You can now start qemu:\n"
         "    qemu-system-x86_64 ... -device virtio-net-pci,netdev=s0 "
         "-netdev stream,id=s0,server=off,addr.type=unix,addr.path=%s",
         conf.socket_path);
}

static void remove_socket(void)
{
    if (listen_fd >= 0 && conf.socket_path) {
        close(listen_fd);
        unlink(conf.socket_path);
    }
}

int main(int argc, char **argv)
{
    socket_init();
    parse_options(argc, argv);

    if (conf.log_file) {
        log_fp = fopen(conf.log_file, "a");
        if (!log_fp) {
            die("Cannot open log file %s: %s", conf.log_file,
                strerror(errno));
        }
    }
    if (conf.fd >= 0 && conf.socket_path) {
        die("Options --fd and --socket are mutually exclusive");
    }

    host_conf();
    if (conf.no_icmp) {
        info("ICMP: disabled (libslirp answers echo requests itself)");
    }

    /* everything checked: the work goes on in the background */
    if (!conf.foreground) {
        daemonize(argc, argv);
    }

    net_event = WSACreateEvent();
    pcap_open();
    slirp_start();

    if (conf.fd >= 0) {
        int fd = _open_osfhandle((intptr_t)conf.fd, _O_BINARY);

        if (fd < 0) {
            die("Invalid socket handle %lld", conf.fd);
        }
        SetHandleInformation((HANDLE)(intptr_t)conf.fd, HANDLE_FLAG_INHERIT,
                             0);
        if (conf.vhost_user) {
            vu_watches = g_hash_table_new_full(NULL, NULL, NULL, g_free);
            if (!vu_init(&vudev, 2, fd, vu_panic, NULL, vu_set_watch,
                         vu_remove_watch, &vu_iface)) {
                die("vhost-user: cannot set up the device");
            }
            vu_running = true;
            WSAEventSelect(_get_osfhandle(fd), net_event, FD_READ | FD_CLOSE);
        } else {
            tap_fd = fd;
            WSAEventSelect(_get_osfhandle(tap_fd), net_event,
                           FD_READ | FD_CLOSE);
        }
    } else if (conf.vhost_user) {
        die("--vhost-user needs --fd here");
    } else {
        listen_socket();
        atexit(remove_socket);
    }
    if (conf.foreground) {
        write_pidfile(conf.pidfile, GetCurrentProcessId());
    }

    main_loop();
    return 0;
}
