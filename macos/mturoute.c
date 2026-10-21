/*
mturoute for macOS

Port of mturoute 3.0 from the Windows ICMP helper API (IcmpSendEcho) to
BSD ICMP sockets, so it builds and runs natively on macOS (Apple Silicon
and Intel). The probing logic, options and output follow the original.

Original mturoute by Eli Fulkerson, June 2005 (www.elifulkerson.com),
with bugfixes from Ivan Pepelnjak, October 2007.

Originally modified from Ping.c, by Francois Gouget (fgouget@free.fr), which
was in turn based on the ping sample provided with the ICMP libraries
(author unknown), the FreeBSD ping interface, and the FreeBSD traceroute
interface.

How the macOS port sends probes (mirrors Apple's own /sbin/ping):
  * as a normal user: SOCK_DGRAM/IPPROTO_ICMP socket, DF via IP_DONTFRAG,
    TTL via IP_TTL. No sudo needed.
  * as root: SOCK_RAW/IPPROTO_ICMP socket with IP_HDRINCL, DF and TTL are
    written into a hand-built IP header.
Replies (echo reply, fragmentation needed, time exceeded, unreachable...)
are read back from the same socket and matched to the probe by ICMP
identifier/sequence, including the copy quoted inside ICMP error messages.
*/

#if defined(__linux__)
#define _DEFAULT_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME                "mturoute"
#define APP_VERSION             "3.0-macos.1"

// predefined constants

#define ICMP_HEADER_SIZE        8       // Don't change this
#define IP_HEADER_SIZE          20      // Don't change this either
#define MAX_PACKET              65535

// option defaults

#define DEFAULT_OPT_I_VALUE     1       // Wait 1 second between ICMP packets
#define DEFAULT_OPT_M_VALUE     30      // Max hops in traceroute mode
#define DEFAULT_OPT_S_VALUE     56      // 56 bytes of data -> 64 byte ICMP packet
#define DEFAULT_OPT_W_VALUE     3000    // Wait for a reply for X milliseconds
#define OPT_P_MAX_SIZE          16      // Patterns are at most 16 bytes long
#define DEFAULT_OPT_R_VALUE     3       // Retry up to three times
#define DEFAULT_PAYLOAD_VALUE   10000   // somewhat low default to speed convergence
#define DEFAULT_OPT_D_VALUE     0       // Debugging display off/on
#define DEFAULT_OPT_REDACT_VALUE 0      // auto-redaction of IP addresses is off
#define PROBE_TTL               64      // TTL used for the MTU probes themselves

// ICMP types/codes we care about
#define T_ECHOREPLY     0
#define T_UNREACH       3
#define T_SOURCEQUENCH  4
#define T_ECHO          8
#define T_TIMXCEED      11
#define T_PARAMPROB     12

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/*
 * Probe outcomes. These replace the Windows IP_* status codes returned by
 * IcmpSendEcho. 0 means "the echo request was answered".
 */
enum {
    ST_OK = 0,
    ST_TOO_BIG,             // ICMP frag needed / local EMSGSIZE
    ST_TIMEOUT,
    ST_NET_UNREACH,
    ST_HOST_UNREACH,
    ST_PROTO_UNREACH,
    ST_PORT_UNREACH,
    ST_ADMIN_PROHIBITED,
    ST_TTL_EXPIRED,
    ST_REASSEMBLY_EXPIRED,
    ST_PARAM_PROBLEM,
    ST_SOURCE_QUENCH,
    ST_SEND_ERROR,
    ST_OTHER
};

static const char *status_name(int st) {
    switch (st) {
    case ST_OK:                 return "OK";
    case ST_TOO_BIG:            return "PACKET_TOO_BIG";
    case ST_TIMEOUT:            return "REQ_TIMED_OUT";
    case ST_NET_UNREACH:        return "DEST_NET_UNREACHABLE";
    case ST_HOST_UNREACH:       return "DEST_HOST_UNREACHABLE";
    case ST_PROTO_UNREACH:      return "DEST_PROT_UNREACHABLE";
    case ST_PORT_UNREACH:       return "DEST_PORT_UNREACHABLE";
    case ST_ADMIN_PROHIBITED:   return "ADMIN_PROHIBITED";
    case ST_TTL_EXPIRED:        return "TTL_EXPIRED_TRANSIT";
    case ST_REASSEMBLY_EXPIRED: return "TTL_EXPIRED_REASSEM";
    case ST_PARAM_PROBLEM:      return "PARAM_PROBLEM";
    case ST_SOURCE_QUENCH:      return "SOURCE_QUENCH";
    case ST_SEND_ERROR:         return "SEND_ERROR";
    default:                    return "UNKNOWN";
    }
}

/**
 * A bit field for storing boolean options.
 */
static unsigned short options = 0;

#define F_INTERVAL      0x0002
#define F_MAXTTL        0x0004
#define F_SLOW          0x0008
#define F_PATTERN       0x0010
#define F_QUIET         0x0020
#define F_IPV6          0x0040
#define F_TRACE         0x0080
#define F_TIMEOUT       0x0100
#define F_RANDOMFILL    0x0200
#define F_FRAGMENT      0x0400
#define F_PAYLOAD       0x0800

static double opt_i = DEFAULT_OPT_I_VALUE;
static int opt_m = DEFAULT_OPT_M_VALUE;
static int opt_s = DEFAULT_OPT_S_VALUE;
static int opt_w = DEFAULT_OPT_W_VALUE;
static int opt_r = DEFAULT_OPT_R_VALUE;
static int opt_d = DEFAULT_OPT_D_VALUE;
static int opt_p_length;                       // pattern length
static unsigned char opt_p_pattern[OPT_P_MAX_SIZE];
static int opt_payload = DEFAULT_PAYLOAD_VALUE;
static int opt_redact = DEFAULT_OPT_REDACT_VALUE;
static int opt_redact_count = 0;

static int number_of_icmp_timeouts = 0;  // number of times we've waited for an icmp timeout
static int opt_timeout_explicit = 0;     // timeout explicitly specified; don't change it

static int icmp_data_size = 0;
static unsigned char *icmp_data = NULL;

/* socket state */
static int sock = -1;
static int sock_is_raw = 0;      // SOCK_RAW (root) vs SOCK_DGRAM (unprivileged)
static int use_hdrincl = 0;      // build the IP header ourselves (macOS, root)
static uint16_t ident;
static uint16_t seqno = 0;
static int cur_ttl = -1;
static int cur_df = -1;

static unsigned char send_buffer[MAX_PACKET + 128];
static unsigned char recv_buffer[MAX_PACKET + 128];

typedef struct {
    int status;
    struct in_addr from;    // who answered
    int next_hop_mtu;       // from "fragmentation needed", 0 if not provided
    double rtt_ms;
} probe_result;

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void sleep_seconds(double s) {
    struct timespec ts;
    if (s <= 0) return;
    ts.tv_sec = (time_t)s;
    ts.tv_nsec = (long)((s - (double)ts.tv_sec) * 1e9);
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) { }
}

static uint16_t in_cksum(const unsigned char *buf, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)((buf[i] << 8) | buf[i + 1]);
    }
    if (len & 1) {
        sum += (uint32_t)(buf[len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;  // in network byte order when stored big-endian
}

static void put_be16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

static uint16_t get_be16(const unsigned char *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * Converts a string to an IP address. The address may be specified
 * either as a host name or as the IP address in "dotted" format.
 * @return 0 on success, -1 otherwise
 */
static int HostString2Addr(const char *host_string, struct in_addr *out) {
    struct addrinfo hints, *res = NULL;
    int rc;

    if (inet_pton(AF_INET, host_string, out) == 1) {
        return 0;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    rc = getaddrinfo(host_string, NULL, &hints, &res);
    if (rc != 0 || res == NULL) {
        fprintf(stderr, "%s: unknown host %s\n", APP_NAME, host_string);
        return -1;
    }
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

/*
 * Returns a pointer to a string suitable for representing the host's address.
 *
 * ip address redaction: opt_redact_count increments with every hop in the
 * traceroute, which lets us assign a specific text value to each IP address
 * without revealing it, so people can paste output without leaking secrets.
 */
static const char *HostAddr2String(struct in_addr addr) {
    static char host_string[INET_ADDRSTRLEN + 1];

    if (opt_redact == 1) {
        char byte = (char)(opt_redact_count + 96);
        snprintf(host_string, sizeof(host_string), "%c.%c.%c.%c", byte, byte, byte, byte);
        return host_string;
    }
    if (inet_ntop(AF_INET, &addr, host_string, sizeof(host_string)) == NULL) {
        snprintf(host_string, sizeof(host_string), "?");
    }
    return host_string;
}

/*
 * Parses the pattern given by the user and places it in the pattern
 * buffer in a form suitable for further use.
 * @return 0 if successful, -1 otherwise
 */
static int GetPattern(const char *pattern) {
    size_t i, l;
    char subpattern[3];
    unsigned int value;

    l = strlen(pattern);
    if (l == 0 || l > 2 * OPT_P_MAX_SIZE || (l % 2 != 0)) {
        return -1;
    }
    i = 0;
    opt_p_length = 0;
    subpattern[2] = '\0';
    while (pattern[i] != '\0') {
        subpattern[0] = pattern[i++];
        subpattern[1] = pattern[i++];
        if (sscanf(subpattern, "%x", &value) != 1) {
            return -1;
        }
        opt_p_pattern[opt_p_length++] = (unsigned char)value;
    }
    return 0;
}

/*
 * Builds the data field to be sent with the ICMP packet.
 */
static void GenerateData(int size) {
    int i;

    if (icmp_data_size != size || icmp_data == NULL) {
        unsigned char *p = realloc(icmp_data, size > 0 ? (size_t)size : 1);
        if (p == NULL) {
            fprintf(stderr, "%s: out of memory\n", APP_NAME);
            exit(1);
        }
        icmp_data = p;
        icmp_data_size = size;
    }

    if (options & F_PATTERN) {
        // Fill the buffer with the pattern
        i = 0;
        while (i < icmp_data_size) {
            memcpy(icmp_data + i, opt_p_pattern, (size_t)MIN(opt_p_length, icmp_data_size - i));
            i += opt_p_length;
        }
        return;
    }

    if (options & F_RANDOMFILL) {
        for (i = 0; i < icmp_data_size; i++) {
            icmp_data[i] = (unsigned char)(rand() & 0xff);
        }
        return;
    }

    // Default case: just put some predictable data in the packet.
    for (i = 0; i < icmp_data_size; i++) {
        icmp_data[i] = (unsigned char)i;
    }
}

/* ------------------------------------------------------------------ */
/* socket layer (replaces IcmpCreateFile / IcmpSendEcho)              */
/* ------------------------------------------------------------------ */

static int open_icmp_socket(void) {
    int bufsize = MAX_PACKET + 128;

    /* Root gets a raw socket (like /sbin/ping); everyone else a datagram ICMP socket. */
    sock = -1;
    if (geteuid() == 0) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock >= 0) {
            sock_is_raw = 1;
        }
    }
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        sock_is_raw = 0;
    }
    if (sock < 0) {
        perror(APP_NAME ": socket");
        fprintf(stderr, "%s: could not open an ICMP socket (try running with sudo).\n", APP_NAME);
        return -1;
    }

#if defined(__APPLE__) && defined(IP_HDRINCL)
    if (sock_is_raw) {
        int on = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == 0) {
            use_hdrincl = 1;
        }
    }
#endif

    (void)setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

#if defined(__linux__)
    if (!sock_is_raw) {
        fprintf(stderr, "%s: warning: unprivileged ICMP socket on Linux does not report ICMP errors;"
                        " run with sudo for accurate results.\n", APP_NAME);
    }
#endif

    if (opt_d) {
        printf("socket: %s%s\n", sock_is_raw ? "SOCK_RAW" : "SOCK_DGRAM",
               use_hdrincl ? " + IP_HDRINCL" : "");
    }
    return 0;
}

static int set_ttl(int ttl) {
    if (use_hdrincl || ttl == cur_ttl) {
        return 0;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        if (opt_d) perror("setsockopt(IP_TTL)");
        return -1;
    }
    cur_ttl = ttl;
    return 0;
}

static int set_dontfrag(int df) {
    if (use_hdrincl || df == cur_df) {
        return 0;
    }
#if defined(IP_DONTFRAG)
    {
        int v = df ? 1 : 0;
        if (setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &v, sizeof(v)) < 0) {
            if (opt_d) perror("setsockopt(IP_DONTFRAG)");
            return -1;
        }
    }
#elif defined(IP_MTU_DISCOVER)
    {
#if defined(IP_PMTUDISC_PROBE)
        int v = df ? IP_PMTUDISC_PROBE : IP_PMTUDISC_DONT;
#else
        int v = df ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
#endif
        if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof(v)) < 0) {
            if (opt_d) perror("setsockopt(IP_MTU_DISCOVER)");
            return -1;
        }
    }
#else
    if (df) {
        static int warned = 0;
        if (!warned) {
            fprintf(stderr, "%s: warning: cannot set the DF bit on this platform\n", APP_NAME);
            warned = 1;
        }
    }
#endif
    cur_df = df;
    return 0;
}

/*
 * Check whether a received packet answers the probe (dst, seq).
 * Fills res and returns 1 on a match, 0 otherwise.
 */
static int match_reply(const unsigned char *pkt, ssize_t n, struct in_addr from,
                       struct in_addr dst, uint16_t seq, probe_result *res) {
    const unsigned char *icmp = pkt;
    ssize_t len = n;
    int type, code;
    int check_id = 1;

#if defined(__linux__)
    /* Linux rewrites the ICMP identifier on unprivileged ping sockets. */
    if (!sock_is_raw) check_id = 0;
#endif

    /* Raw sockets (and macOS datagram ICMP sockets) deliver the IP header too. */
    if (len >= 20 && (pkt[0] >> 4) == 4) {
        int hl = (pkt[0] & 0x0f) * 4;
        if (hl < 20 || hl > len) return 0;
        icmp = pkt + hl;
        len -= hl;
    }
    if (len < 8) return 0;

    type = icmp[0];
    code = icmp[1];

    if (type == T_ECHOREPLY) {
        if (get_be16(icmp + 6) != seq) return 0;
        if (check_id && get_be16(icmp + 4) != ident) return 0;
        if (from.s_addr != dst.s_addr) return 0;
        res->status = ST_OK;
        res->from = from;
        return 1;
    }

    if (type == T_UNREACH || type == T_TIMXCEED || type == T_PARAMPROB || type == T_SOURCEQUENCH) {
        const unsigned char *inner = icmp + 8;
        ssize_t ilen = len - 8;
        int ihl;
        struct in_addr idst;

        if (ilen < 20 || (inner[0] >> 4) != 4) return 0;
        ihl = (inner[0] & 0x0f) * 4;
        if (ihl < 20 || ilen < ihl + 8) return 0;
        if (inner[9] != IPPROTO_ICMP) return 0;
        memcpy(&idst, inner + 16, sizeof(idst));
        if (idst.s_addr != dst.s_addr) return 0;
        if (inner[ihl] != T_ECHO) return 0;
        if (get_be16(inner + ihl + 6) != seq) return 0;
        if (check_id && get_be16(inner + ihl + 4) != ident) return 0;

        res->from = from;
        res->next_hop_mtu = 0;
        switch (type) {
        case T_UNREACH:
            switch (code) {
            case 0: case 6: case 11:  res->status = ST_NET_UNREACH; break;
            case 1: case 7: case 12:  res->status = ST_HOST_UNREACH; break;
            case 2:                   res->status = ST_PROTO_UNREACH; break;
            case 3:                   res->status = ST_PORT_UNREACH; break;
            case 4:
                res->status = ST_TOO_BIG;
                res->next_hop_mtu = get_be16(icmp + 6);
                break;
            case 9: case 10: case 13: res->status = ST_ADMIN_PROHIBITED; break;
            default:                  res->status = ST_HOST_UNREACH; break;
            }
            break;
        case T_TIMXCEED:
            res->status = (code == 1) ? ST_REASSEMBLY_EXPIRED : ST_TTL_EXPIRED;
            break;
        case T_PARAMPROB:
            res->status = ST_PARAM_PROBLEM;
            break;
        default:
            res->status = ST_SOURCE_QUENCH;
            break;
        }
        return 1;
    }
    return 0;
}

/*
 * Send one ICMP echo request carrying icmp_data[0..payload) to dst and wait
 * up to timeout_ms for the matching answer. Equivalent of IcmpSendEcho().
 */
static int send_probe(struct in_addr dst, int payload, int ttl, int dont_frag,
                      int timeout_ms, probe_result *res) {
    struct sockaddr_in to;
    unsigned char *icmp;
    size_t icmp_len = (size_t)ICMP_HEADER_SIZE + (size_t)payload;
    size_t total;
    ssize_t sent;
    uint16_t seq;
    double start, deadline;

    memset(res, 0, sizeof(*res));
    res->status = ST_TIMEOUT;

    if (icmp_len + IP_HEADER_SIZE > MAX_PACKET) {
        res->status = ST_TOO_BIG;
        return res->status;
    }

    set_ttl(ttl);
    set_dontfrag(dont_frag);

    seq = ++seqno;

    if (use_hdrincl) {
        /* macOS raw IP: ip_len and ip_off are in HOST byte order (as in Apple's ping). */
        unsigned char *ip = send_buffer;
        uint16_t ip_len = (uint16_t)(IP_HEADER_SIZE + icmp_len);
        uint16_t ip_off = dont_frag ? 0x4000 : 0;
        memset(ip, 0, IP_HEADER_SIZE);
        ip[0] = 0x45;                       // version 4, header length 5 words
        memcpy(ip + 2, &ip_len, 2);
        memcpy(ip + 6, &ip_off, 2);
        ip[8] = (unsigned char)ttl;
        ip[9] = IPPROTO_ICMP;
        memcpy(ip + 16, &dst, 4);           // source 0.0.0.0: kernel fills it in
        icmp = send_buffer + IP_HEADER_SIZE;
        total = IP_HEADER_SIZE + icmp_len;
    } else {
        icmp = send_buffer;
        total = icmp_len;
    }

    icmp[0] = T_ECHO;
    icmp[1] = 0;
    put_be16(icmp + 2, 0);
    put_be16(icmp + 4, ident);
    put_be16(icmp + 6, seq);
    if (payload > 0) {
        memcpy(icmp + ICMP_HEADER_SIZE, icmp_data, (size_t)payload);
    }
    put_be16(icmp + 2, in_cksum(icmp, icmp_len));

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
#if defined(__APPLE__)
    to.sin_len = sizeof(to);
#endif
    to.sin_addr = dst;

    start = now_ms();
    sent = sendto(sock, send_buffer, total, 0, (struct sockaddr *)&to, sizeof(to));
    if (sent < 0) {
        int e = errno;
        if (opt_d) {
            printf("send_probe: sendto(%d bytes) failed: %s\n", (int)total, strerror(e));
        }
        if (e == EMSGSIZE) {
            res->status = ST_TOO_BIG;           // bigger than the local interface / route MTU
        } else if (e == ENETUNREACH) {
            res->status = ST_NET_UNREACH;
        } else if (e == EHOSTUNREACH || e == EHOSTDOWN) {
            res->status = ST_HOST_UNREACH;
        } else {
            res->status = ST_SEND_ERROR;
        }
        return res->status;
    }

    deadline = start + timeout_ms;
    for (;;) {
        struct pollfd pfd;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n;
        int remaining = (int)(deadline - now_ms());
        int pr;

        if (remaining <= 0) break;
        pfd.fd = sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, remaining);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) break;

        n = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (opt_d > 1) printf("send_probe: recvfrom: %s\n", strerror(errno));
            continue;
        }
        if (match_reply(recv_buffer, n, from.sin_addr, dst, seq, res)) {
            res->rtt_ms = now_ms() - start;
            if (opt_d > 1) {
                printf("send_probe: %s from %s after %.1f ms\n", status_name(res->status),
                       inet_ntoa(res->from), res->rtt_ms);
            }
            return res->status;
        }
    }
    res->status = ST_TIMEOUT;
    return res->status;
}

/* ------------------------------------------------------------------ */
/* mturoute logic (ported from the original)                          */
/* ------------------------------------------------------------------ */

static int doMTU(struct in_addr target_addr, int MTU) {
    int status = ST_TIMEOUT;
    int maxRetry = opt_r;
    int df = !(options & F_FRAGMENT);
    probe_result r;

    while (maxRetry > 0) {
        GenerateData(MTU);
        status = send_probe(target_addr, MTU, PROBE_TTL, df, opt_w, &r);

        if (opt_d) {
            printf("doMTU: got status %s for mtu %d\n", status_name(status), MTU);
        }

        if (status == ST_TOO_BIG) {
            if (opt_d && r.next_hop_mtu) {
                printf("doMTU: %s reports next-hop MTU %d\n", inet_ntoa(r.from), r.next_hop_mtu);
            }
            return ST_TOO_BIG;
        }

        if (status == ST_TIMEOUT) {
            printf(".");
            maxRetry--;
            number_of_icmp_timeouts++;
            if (opt_d) {
                printf("doMTU: request timeout at mtu %d, %d tries left\n", MTU, maxRetry);
            }
            continue;
        }

        /* Ivan's fix: "network unreachable" from an ACL still means the packet got that far. */
        if (status == ST_NET_UNREACH) {
            printf("u");
            return ST_OK;
        }

        if (opt_d) {
            printf("doMTU: returning status %s\n", status_name(status));
        }
        return status;
    }

    if (opt_d) {
        printf("doMTU: Timed all the way out.\n");
    }

    if (opt_timeout_explicit == 0 && !(options & F_SLOW)) {
        if (opt_d) {
            printf("doMTU:  Assuming ICMP responses will not be coming.  Speeding things up.\n");
        }
        opt_w = 1000;
        opt_r = 1;
    }

    return status;
}

static void output_parameters(void) {
    if (!(options & F_FRAGMENT)) {
        printf("* ICMP Fragmentation is not permitted. *\n");
    } else {
        printf("* ICMP Fragmentation is permitted. *\n");
    }

    if (options & F_SLOW) {
        printf("* Speed optimization is disabled *\n");
    } else {
        printf("* Speed optimization is enabled. *\n");
    }

    printf("* Maximum payload is %d bytes. *\n", opt_payload);
}

static void formatResults(int success, int display, int current_check) {
    if (success == ST_OK) {
        if (display == 1 || opt_d) {
            printf("+ ICMP payload of %d bytes succeeded.\n", current_check);
        } else {
            printf("+");
        }
        return;
    }

    if (display == 1 || opt_d) {
        if (opt_d) {
            printf("icmp return code %s\n", status_name(success));
        }
        switch (success) {
        case ST_TOO_BIG:
            printf("- ICMP payload of %d bytes is too big.\n", current_check);
            break;
        case ST_TIMEOUT:
            printf("? ICMP payload of %d bytes failed mysteriously.. (no ICMP response)\n", current_check);
            break;
        default:
            printf("- ICMP payload of %d bytes failed. (IP_%s)\n", current_check, status_name(success));
            break;
        }
    } else {
        printf("-");
    }
}

static int doSingleMTU(struct in_addr target_addr, int display, int last_cycle_result) {
    int min_mtu = 92;
    int max_mtu;
    int orig_max_mtu;
    int orig_min_mtu;
    int current_check;
    int success = 1;
    int precheck;
    int last_checked = 0;
    int already_solved = -1;

    max_mtu = opt_payload;

    orig_min_mtu = min_mtu;
    orig_max_mtu = max_mtu;

    if (display == 1) {
        output_parameters();
    }

    if (!(options & F_SLOW)) {
        /* Assume that a "correct" mtu, in most cases, is either 1500 or the result
           from the last attempt, and check that first */
        if (opt_d) {
            printf("Optimizer: pre-checking %d bytes\n", last_cycle_result);
        }
        precheck = doMTU(target_addr, last_cycle_result);
        formatResults(precheck, display, last_cycle_result);

        if (precheck == ST_OK) {
            if (opt_d) {
                printf("Optimizer: pre-checking %d bytes\n", last_cycle_result + 1);
            }
            precheck = doMTU(target_addr, last_cycle_result + 1);
            formatResults(precheck, display, last_cycle_result + 1);

            if (precheck != ST_OK) {
                // Already solved: skip the scan entirely.
                already_solved = last_cycle_result;
            }
        } else {
            // we failed at "last_cycle_result", so it's the working maximum
            max_mtu = last_cycle_result;
            last_checked = last_cycle_result;

            /* Pregame with a very small request. If it fails, don't bother with
               the larger ones, otherwise we wait for a lot of timeouts. */
            if (opt_d) {
                printf("Optimizer: pre-checking %d bytes\n", min_mtu);
            }
            precheck = doMTU(target_addr, min_mtu);
            formatResults(precheck, display, min_mtu);
            if (precheck != ST_OK) {
                // The minimum didn't even work, so skip the middle man
                max_mtu = min_mtu;
                last_checked = 0;
            }
        }
    }

    while (min_mtu != max_mtu) {
        current_check = (max_mtu + min_mtu) / 2;

        // avoid "1472 Ok! 1473 bad 1472 Ok!" once converged
        if (last_checked - 1 == min_mtu) {
            last_checked = current_check;
            break;
        }

        if (last_checked == current_check) {
            break;
        }

        if (already_solved != -1) {
            last_checked = already_solved;
            break;
        }

        success = doMTU(target_addr, current_check);
        formatResults(success, display, current_check);

        if (success == ST_OK) {
            min_mtu = current_check;
        } else {
            max_mtu = current_check;
        }

        last_checked = current_check;
        sleep_seconds(opt_i);
    }

    if (last_checked + 1 >= orig_max_mtu && display == 1) {
        printf("Estimated Max: %d bytes or higher.\n", max_mtu);
    } else if (last_checked - 1 <= orig_min_mtu && display == 1) {
        printf("\nTarget is not responding to pings.\n");
    } else if (display == 1) {
        if (!(options & F_FRAGMENT)) {
            printf("Path MTU: %d bytes.\n", last_checked + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
        } else {
            printf("Max ping: %d bytes.\n", last_checked + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
        }
    }
    return last_checked + ICMP_HEADER_SIZE + IP_HEADER_SIZE;
}

/**
 * Sends ICMP echo requests with increasing TTLs to discover the hosts the
 * packets are routed through, then measures the MTU to each of them.
 */
static void doManyMTU(struct in_addr target_addr, const char *target_string) {
    int status;
    int hop, probe, nb_probes = 3;
    struct in_addr gateway_addr;
    int have_gateway;
    int foundMTU;
    int last_cycle_result = 1472;  // used for speed optimizations
    probe_result r;

    if (opt_redact == 1) {
        printf("mturoute to [redacted], %d hops max, variable sized packets\n", opt_m);
    } else {
        printf("mturoute to %s, %d hops max, variable sized packets\n", target_string, opt_m);
    }
    output_parameters();

    for (hop = 1; hop <= opt_m; hop++) {
        printf("%2d  ", hop);
        have_gateway = 0;
        gateway_addr.s_addr = INADDR_NONE;

        for (probe = 0; probe < nb_probes; probe++) {
            GenerateData(opt_s);
            status = send_probe(target_addr, opt_s, hop, 0, opt_w, &r);

            if (status == ST_TIMEOUT) {
                if (probe == nb_probes - 1 && !have_gateway) {
                    printf("No response from traceroute for this TTL.  Tried %d time%s\n",
                           probe + 1, probe > 0 ? "s" : "");
                }
                continue;
            }
            if (status == ST_SEND_ERROR || r.from.s_addr == 0) {
                fprintf(stderr, "An error (%s) occurred while sending the ICMP Echo Request to %s\n",
                        status_name(status), target_string);
                if (probe == nb_probes - 1 && !have_gateway) {
                    printf("\n");
                }
                continue;
            }

            if (!have_gateway) {
                gateway_addr = r.from;
                have_gateway = 1;
                opt_redact_count++;  // different redacted strings (a.a.a.a, b.b.b.b etc)

                foundMTU = doSingleMTU(gateway_addr, 0, last_cycle_result);
                if (foundMTU != ICMP_HEADER_SIZE + IP_HEADER_SIZE) {
                    printf("  host: %s  max: %d bytes \n", HostAddr2String(gateway_addr), foundMTU);
                    last_cycle_result = foundMTU - (ICMP_HEADER_SIZE + IP_HEADER_SIZE);
                } else {
                    printf("  host: %s not responding\n", HostAddr2String(gateway_addr));
                }
            } else if (gateway_addr.s_addr != r.from.s_addr) {
                printf("*%d (An additional device responded: %s)\n", hop, HostAddr2String(r.from));
            }
        }

        if (have_gateway && gateway_addr.s_addr == target_addr.s_addr) {
            break;
        }
    }
}

static void usage(void) {
    fprintf(stderr, "*****************************************************************\n");
    fprintf(stderr, "  mturoute - written by Eli Fulkerson, June 2005                 \n");
    fprintf(stderr, "             fixes by Ivan Pepelnjak, October 2007               \n");
    fprintf(stderr, "             macOS port, 2026                                    \n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  v%s - %s - %s\n", APP_VERSION, __DATE__, __TIME__);
    fprintf(stderr, "  http://www.elifulkerson.com/projects/mturoute.php (original)   \n");
    fprintf(stderr, "*****************************************************************\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: mturoute [-t] [-f] [-m MAX_PAYLOAD_SIZE] host \n");
    fprintf(stderr, "Flags:\n");
    fprintf(stderr, "   -t : Toggles 'traceroute' mode.  (Default is off)\n");
    fprintf(stderr, "   -f : Allow fragmentation.  This will return the max ping size that the\n");
    fprintf(stderr, "        target host will respond to, but not necessarily the MTU.\n");
    fprintf(stderr, "   -w : Set the number of milliseconds to wait for a response (default 3000).\n");
    fprintf(stderr, "   -r : Set the maximum number of probe retries on timeout (default = 3).\n");
    fprintf(stderr, "   -i : Set the interval in seconds between two echo requests (default 1).\n");
    fprintf(stderr, "   -d : Increases the debugging level. Reports ICMP status/failures.\n");
    fprintf(stderr, "   -m : Sets a maximum payload size to test. (Default is 10000)\n");
    fprintf(stderr, "   -H : Sets the maximum number of hops in traceroute mode. (Default is 30)\n");
    fprintf(stderr, "   -v : Print version info and exit.\n");
    fprintf(stderr, "   -z : Fill ICMP packets with random data.\n");
    fprintf(stderr, "   -p : Fill ICMP packets with a specified hex pattern (e.g. -p ff00).\n");
    fprintf(stderr, "   -s : Skip speed optimizations.\n");
    fprintf(stderr, "   -x : Redact IP addresses in output.\n");
    fprintf(stderr, "-h,-? : Print usage information and exit.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Runs without sudo on macOS; with sudo it uses a raw socket like /sbin/ping.\n");
    fprintf(stderr, "Warning:  This utility generates a lot of ICMP traffic.\n");
}

/* Fetch the value for an option that takes an argument. */
static char *need_value(char ***argp) {
    char **arg = *argp;
    if (arg[1] == NULL) {
        fprintf(stderr, "%s: option %s needs a value\n\n", APP_NAME, arg[0]);
        return NULL;
    }
    *argp = arg + 1;
    return arg[1];
}

/**
 * @return 0 if successful, 2 for a usage error and 1 otherwise
 */
int main(int argc, char **argv) {
    int retcode = 0;
    char **arg;
    char *val;
    int did_target = 0;

    if (argc < 2) {
        usage();
        return 2;
    }

    /* Unbuffered output so the +/-/. progress marks appear immediately. */
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned int)time(NULL));
    ident = (uint16_t)(getpid() & 0xffff);

    arg = argv + 1;
    while (*arg != NULL) {
        if ((*arg)[0] == '-' && (*arg)[1] != '\0') {
            switch ((*arg)[1]) {
            case 'h':
            case '?':
                usage();
                return 2;

            case 'x':
                opt_redact = 1;
                break;

            case '6':
                fprintf(stderr, "%s: IPv6 is not supported yet.\n", APP_NAME);
                return 1;

            case 'd':
                opt_d++;
                break;

            case 'i':
                if ((val = need_value(&arg)) == NULL || sscanf(val, "%lf", &opt_i) != 1) {
                    usage();
                    return 2;
                }
                if (opt_i < 0) opt_i = DEFAULT_OPT_I_VALUE;
                options |= F_INTERVAL;
                break;

            case 'r':
                if ((val = need_value(&arg)) == NULL || sscanf(val, "%d", &opt_r) != 1) {
                    usage();
                    return 2;
                }
                if (opt_r < 0) opt_r = DEFAULT_OPT_R_VALUE;
                opt_timeout_explicit = 1;
                break;

            case 'p':
                if ((val = need_value(&arg)) == NULL || GetPattern(val) < 0) {
                    fprintf(stderr, "%s: incorrect pattern\n", APP_NAME);
                    usage();
                    return 2;
                }
                options = (unsigned short)((options & ~F_RANDOMFILL) | F_PATTERN);
                break;

            case 'q':
                options |= F_QUIET;
                break;

            case 'm':
                if ((val = need_value(&arg)) == NULL || sscanf(val, "%d", &opt_payload) != 1) {
                    usage();
                    return 2;
                }
                if (opt_payload <= 92 || opt_payload >= 65280) {
                    fprintf(stderr, "Maximum payload must be between 93 and 65279 (inclusive).\n\n");
                    return 2;
                }
                options |= F_PAYLOAD;
                break;

            case 'H':
                if ((val = need_value(&arg)) == NULL || sscanf(val, "%d", &opt_m) != 1 ||
                    opt_m < 1 || opt_m > 255) {
                    fprintf(stderr, "%s: max hops must be between 1 and 255\n\n", APP_NAME);
                    return 2;
                }
                options |= F_MAXTTL;
                break;

            case 't':
                options |= F_TRACE;
                break;

            case 's':
                options |= F_SLOW;
                break;

            case 'f':
                options |= F_FRAGMENT;
                break;

            case 'w':
                if ((val = need_value(&arg)) == NULL || sscanf(val, "%d", &opt_w) != 1) {
                    usage();
                    return 2;
                }
                if (opt_w < 0) opt_w = DEFAULT_OPT_W_VALUE;
                options |= F_TIMEOUT;
                opt_timeout_explicit = 1;
                break;

            case 'z':
                options = (unsigned short)((options & ~F_PATTERN) | F_RANDOMFILL);
                break;

            case 'v':
                printf("v%s - compiled: %s %s\n", APP_VERSION, __DATE__, __TIME__);
                return 0;

            default:
                fprintf(stderr, "%s: unknown option %s\n\n", APP_NAME, *arg);
                usage();
                return 2;
            }
        } else {
            struct in_addr host_addr;

            did_target = 1;
            if (sock < 0 && open_icmp_socket() < 0) {
                return 1;
            }
            if (HostString2Addr(*arg, &host_addr) < 0) {
                retcode = 1;
            } else if (options & F_TRACE) {
                doManyMTU(host_addr, *arg);
            } else {
                (void)doSingleMTU(host_addr, 1, 1472);
            }
        }
        arg++;
    }

    if (!did_target) {
        usage();
        retcode = 2;
    }

    if (sock >= 0) close(sock);
    free(icmp_data);
    return retcode;
}

/*
Original credits for "ping.c" (version history removed; ping.c is largely
gutted. Please blame any ugly code on the author of mturoute, not the
original author!  -Eli)

 *                      P I N G
 *
 * Using the Internet Control Message Protocol (ICMP) "ECHO" facility to:
 *  - provide network point-to-point statistics concerning packet loss
 *    and round time trip time
 *  - find the route packets take to reach a network host (and display
 *    network statistics about each host)
 *
 * Hack by Francois Gouget (fgouget@free.fr), based on:
 *  - the ping sample provided with the ICMP libraries (author unknown)
 *  - the FreeBSD ping interface
 *  - the FreeBSD traceroute interface
 *  - bing for these comments
 */
