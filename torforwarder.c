/*
 * Copyright (c) 2021, 2020 Ali Farzanrad <ali_farzanrad@riseup.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
1 file descriptor for stderr
1 file descriptor for listen
9 file descriptors for client connections
9 file descriptors for tor connections
total = 20 file descriptors
*/
enum {
	MaxPeers = 9,
	MaxFD = 2 * MaxPeers + 2,
	BufSize = 4096,
};

typedef int MaxFD_Assert[MaxFD <= FD_SETSIZE ? 1 : -1];
typedef int BufSize_Assert[BufSize >= 512 ? 1 : -1];

struct peer {
	int		 client_s;
	int		 tor_s;
	int		 inlen;
	int		 outlen;
	bool		 inend;
	bool		 outend;
	bool		 init;
	uint8_t		 inbuf[BufSize];	/* tor to client */
	uint8_t		 outbuf[BufSize];	/* client to tor */
} peers[MaxPeers];

struct translation_item {
	const char	*name;
	const char	*newname;
} translation_table[] = {
	/* TODO: add your translation addresses here */
	{"pop.riseup.net", "5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd.onion"},
	{"smtp.riseup.net", "5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd.onion"}
};

struct sockaddr_in local_addr = {
	.sin_family = AF_INET,
	.sin_addr = { .s_addr = htonl(0x7f000001) }
}, tor_addr = {
	.sin_family = AF_INET,
	.sin_addr = { .s_addr = htonl(0x7f000001) }
};
enum {
	translation_table_len = sizeof(translation_table)
	    / sizeof(translation_table[0])
};

/* TODO: default address and port to connect on raw TCP connections */
const char	 default_address[] = /* smtp.riseup.net */
    "5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd.onion";
const uint16_t	 default_port = 465;

int		 translation_item_cmp(const void *, const void *);
uint16_t	 strtoport(const char *, const char *);
int		 init_listener(const struct sockaddr_in *);
void		 main_loop(int);
void		 read_client(struct peer *);
void		 read_tor(struct peer *);
void		 write_client(struct peer *);
void		 write_tor(struct peer *);
void		 init_client(struct peer *, size_t);
void		 init_tor(struct peer *, size_t);
uint32_t	 tor_circuit(void);
void		 write_address(const struct peer *, uint8_t *, bool);
void		 shutdown_in(struct peer *);
void		 shutdown_out(struct peer *);
void		 shutdown_all(struct peer *);

int
main(const int argc, const char *const *const argv)
{
#ifdef __OpenBSD__
	if (pledge("stdio inet", NULL) < 0)
		return 1;
#endif
	qsort(translation_table, translation_table_len,
	    sizeof(translation_table[0]), translation_item_cmp);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	if (argc != 3)
		errx(1, "usage: %s local-port tor-port\n", argv[0]);
	local_addr.sin_port = strtoport("local", argv[1]);
	tor_addr.sin_port = strtoport("tor", argv[2]);

	for (int i = 0; i < MaxPeers; ++i)
		peers[i].client_s = peers[i].tor_s = -1;
	const int listen_s = init_listener(&local_addr);

	for (;;)
		main_loop(listen_s);
}

int
translation_item_cmp(const void *px, const void *py)
{
	const struct translation_item *x = px, *y = py;
	return strcmp(x->name, y->name);
}

void
main_loop(const int listen_s)
{
	fd_set	 rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	for (int i = 0; i < MaxPeers; ++i)
		if (peers[i].client_s < 0) {
			FD_SET(listen_s, &rfds);
			break;
		}
	for (int i = 0; i < MaxPeers; ++i) {
		const struct peer *const p = &peers[i];
		if (p->client_s >= 0 &&
		    p->outlen < (int)sizeof(p->outbuf) && !p->outend)
			FD_SET(p->client_s, &rfds);
		if (p->client_s >= 0 && p->inlen && !p->init)
			FD_SET(p->client_s, &wfds);
		if (p->tor_s >= 0 &&
		    p->inlen < (int)sizeof(p->inbuf) && !p->inend)
			FD_SET(p->tor_s, &rfds);
		if (p->tor_s >= 0 && p->outlen && !p->init)
			FD_SET(p->tor_s, &wfds);
	}
	if (select(MaxFD, &rfds, &wfds, NULL, NULL) == -1)
		err(1, "select");
	if (FD_ISSET(listen_s, &rfds)) {
		struct sockaddr	 addr;
		socklen_t	 addrlen = sizeof(addr);
		int client = accept(listen_s, &addr, &addrlen);
		if (client == -1)
			warn("accept");
		else if (client < 0 || client >= MaxFD) {
			warnx("bad socket");
			shutdown(client, SHUT_RDWR);
			close(client);
			client = -1;
		}
		for (int i = 0; i < MaxPeers; ++i)
			if (client >= 0 && peers[i].client_s < 0) {
				peers[i].client_s = client;
				peers[i].tor_s = -1;
				peers[i].inlen = 0;
				peers[i].outlen = 0;
				peers[i].inend = false;
				peers[i].outend = false;
				peers[i].init = true;
				client = -1;
			}
		if (client >= 0) {
			warnx("no free slot to accept!");
			shutdown(client, SHUT_RDWR);
			close(client);
			client = -1; /* unused assignment */
		}
	}
	for (int i = 0; i < MaxPeers; ++i) {
		struct peer	*const p = &peers[i];
		if (p->client_s >= 0 && FD_ISSET(p->client_s, &rfds))
			read_client(p);
		if (p->tor_s >= 0 && FD_ISSET(p->tor_s, &rfds))
			read_tor(p);
		if (p->client_s >= 0 && FD_ISSET(p->client_s, &wfds))
			write_client(p);
		if (p->tor_s >= 0 && FD_ISSET(p->tor_s, &wfds))
			write_tor(p);
	}
}

uint16_t
strtoport(const char *const name, const char *const arg)
{
	const char *errstr;
	uint16_t port = (uint16_t)strtonum(arg, 1, 65535, &errstr);
	if (errstr != NULL)
		errx(1, "%s port is %s: %s", name, errstr, arg);
	return htons(port);
}

int
init_listener(const struct sockaddr_in *addr)
{
	const int s = socket(PF_INET, SOCK_STREAM, 0);

	if (s == -1)
		err(1, "socket");
	if (s < 0 || s >= MaxFD)
		errx(1, "bad socket");
	if (bind(s, (const struct sockaddr *)addr, sizeof(*addr)))
		err(1, "bind");
	if (listen(s, 5))
		err(1, "listen");
	return s;
}

void
read_client(struct peer *const p)
{
	const size_t size = sizeof(p->outbuf) - p->outlen;
	const size_t nread = (size_t)recv(
	    p->client_s, p->outbuf + p->outlen, size, MSG_DONTWAIT);
	if (size < nread) {
		switch (nread == (size_t)-1 ? errno : 0) {
		case EAGAIN:
		case EINTR:
			return;
		default:
			(nread == (size_t)-1 ? warn : warnx)
			    ("%s: recv", __func__);
			shutdown_out(p);
			return;
		}
	}
	if (nread == 0) {
		shutdown_out(p);
		return;
	}
	p->outlen += (int)nread;
	if (p->init)
		init_client(p, nread);
}

void
read_tor(struct peer *const p)
{
	const size_t size = sizeof(p->inbuf) - p->inlen;
	const size_t nread = (size_t)recv(
	    p->tor_s, p->inbuf + p->inlen, size, MSG_DONTWAIT);
	if (size < nread) {
		switch (nread == (size_t)-1 ? errno : 0) {
		case EAGAIN:
		case EINTR:
			return;
		default:
			(nread == (size_t)-1 ? warn : warnx)
			    ("%s: recv", __func__);
			shutdown_in(p);
			return;
		}
	}
	if (nread == 0) {
		shutdown_in(p);
		return;
	}
	p->inlen += (int)nread;
	if (p->init)
		init_tor(p, nread);
}

void
write_client(struct peer *const p)
{
	if (p->inlen) {
		const size_t nwrite = (size_t)send(
		    p->client_s, p->inbuf, (size_t)p->inlen,
		    MSG_DONTWAIT);
		if ((size_t)p->inlen < nwrite) {
			switch (nwrite == (size_t)-1 ? errno : 0) {
			case EAGAIN:
			case EINTR:
				return;
			default:
				(nwrite == (size_t)-1 ? warn : warnx)
				    ("%s: send", __func__);
				p->inlen = 0;
				shutdown_in(p);
				return;
			}
		}
		p->inlen -= (int)nwrite;
		memmove(p->inbuf, p->inbuf + nwrite, (size_t)p->inlen);
	}
	if (p->inend)
		shutdown_in(p);
}

void
write_tor(struct peer *const p)
{
	if (p->outlen) {
		const size_t nwrite = (size_t)send(
		    p->tor_s, p->outbuf, (size_t)p->outlen,
		    MSG_DONTWAIT);
		if ((size_t)p->outlen < nwrite) {
			switch (nwrite == (size_t)-1 ? errno : 0) {
			case EAGAIN:
			case EINTR:
				return;
			default:
				(nwrite == (size_t)-1 ? warn : warnx)
				    ("%s: send", __func__);
				p->outlen = 0;
				shutdown_out(p);
				return;
			}
		}
		p->outlen -= (int)nwrite;
		memmove(p->outbuf, p->outbuf + nwrite, (size_t)p->outlen);
	}
	if (p->outend)
		shutdown_out(p);
}

void
init_client(struct peer *const p, const size_t nread)
{
#define send_or_die(buf, len, ...) do { \
		size_t nsend = (size_t)send(p->client_s, buf, len, \
		    MSG_DONTWAIT); \
		if (nsend != (size_t)(len)) { \
			(nsend == (size_t)-1 ? warn : warnx) \
			    (__VA_ARGS__); \
			shutdown_all(p); \
			return; \
		} \
	} while (0)

	const uint8_t	*in = p->outbuf;
	const uint8_t	*e2 = in + p->outlen, *e1 = e2 - nread;
	if (in < e2 && *in != 5) {
		if (in >= e1)
			init_tor(p, 0);
		return;
	}
	const int	 nauth = in[1];
	if (e2 < in + nauth + 2)
		return;
	if (e1 < in + nauth + 2) {
		bool		 isok = false;
		for (int i = 0; i < nauth; ++i)
			if (in[i + 2] == 0) {
				isok = true;
				break;
			}
		if (!isok) {
			warnx("bad auth");
			shutdown_all(p);
			return;
		}
		send_or_die(((const uint8_t[]){ 5, 0 }), 2,
			    "could not send auth accept");
	}
	in += nauth + 2;
	const int	 reqlen = in[3] == 3 ? in[4] + 7 : 4;
	if (e2 < in + reqlen)
		return;
	if (e1 < in + reqlen) {
		if (in[0] != 5 || in[1] != 1 || in[2] || reqlen < 6) {
			warnx("bad request");
			shutdown_all(p);
			return;
		}
		init_tor(p, 0);
	}
#undef send_or_die
}

void
init_tor(struct peer *const p, const size_t nread)
{
#define send_or_die(buf, len, ...) do { \
		size_t nsend = (size_t)send(p->tor_s, buf, len, \
		    MSG_DONTWAIT); \
		if (nsend != (size_t)(len)) { \
			(nsend == (size_t)-1 ? warn : warnx) \
			    (__VA_ARGS__); \
			shutdown_all(p); \
			return; \
		} \
	} while (0)

	if (p->tor_s == -1) {
		p->tor_s = socket(PF_INET, SOCK_STREAM, 0);
		if (p->tor_s < 0 || p->tor_s >= MaxFD) {
			if (p->tor_s == -1)
				warn("socket");
			else
				warnx("bad socket");
			shutdown_all(p);
			return;
		}
		if (connect(p->tor_s, (const struct sockaddr *)
		    &tor_addr, (socklen_t)sizeof(tor_addr)) != 0) {
			warn("connect");
			shutdown_all(p);
			return;
		}
		send_or_die(((const uint8_t[]){ 5, 1, 2 }), 3,
			    "could not send auth type");
		return;
	}
	const uint8_t	*in = p->inbuf;
	const uint8_t	*e2 = in + p->inlen, *e1 = e2 - nread;
	if (e2 < in + 2)
		return;
	if (e1 < in + 2) {
		if (in[0] != 5 || in[1] != 2) {
			warnx("bad greeting or auth");
			shutdown_all(p);
			return;
		}
		const uint32_t circuit = tor_circuit();
		uint8_t		 buf[11];
		buf[0] = 1; /* UserPass Version 1 */
		buf[1] = 4; /* Username Length */
		buf[2] = (uint8_t)('a' + (circuit & 15));
		buf[3] = (uint8_t)('a' + ((circuit >> 4) & 15));
		buf[4] = (uint8_t)('a' + ((circuit >> 8) & 15));
		buf[5] = (uint8_t)('a' + ((circuit >> 12) & 15));
		buf[6] = 4; /* Password Length */
		buf[7] = (uint8_t)('a' + ((circuit >> 16) & 15));
		buf[8] = (uint8_t)('a' + ((circuit >> 20) & 15));
		buf[9] = (uint8_t)('a' + ((circuit >> 24) & 15));
		buf[10] = (uint8_t)('a' + ((circuit >> 28) & 15));
		send_or_die(buf, sizeof(buf), "could not send auth");
	}
	in += 2;
	if (e2 < in + 2)
		return;
	if (e1 < in + 2) {
		if (in[0] != 1 || in[1] != 0) {
			warnx("bad auth response");
			shutdown_all(p);
			return;
		}
		uint8_t		 buf[256 + 6];
		buf[0] = 5; /* SOCKS Version */
		buf[1] = 1; /* TCP Connection */
		buf[2] = 0; /* RSV */
		buf[3] = 3; /* Domain Name Address Type */
		write_address(p, buf + 4, true);
		const size_t	 size = buf[4] + 7;
		send_or_die(buf, size, "could not send request");
	}
	in += 2;
	const int	 reslen = in[3] == 1 ? 10 : in[3] == 4 ? 22 :
			    in[3] == 3 ? in[4] + 7 : 4;
	if (e2 < in + reslen)
		return;
	if (in[0] != 5 || in[1] != 0 || in[2] != 0 || reslen < 6) {
		warnx("bad req response");
		shutdown_all(p);
		return;
	}
	in += reslen;
	const size_t	 inlen = (p->inbuf + p->inlen) - in;
	p->init = false;
	if (p->outbuf[0] == 5) {
		uint8_t		*out = p->inbuf;
		*out++ = 5; /* SOCKS Version */
		*out++ = 0; /* Request Granted */
		*out++ = 0; /* RSV */
		*out++ = 1; /* Domain Name Address Type (IPv4) */
		*out++ = 0;
		*out++ = 0;
		*out++ = 0;
		*out++ = 0;
		*out++ = 0;
		*out++ = 0;
		if (in < out) {
			warnx("FATAL");
			shutdown_all(p);
			return;
		}
		memmove(out, in, inlen);
		out += inlen;
		p->inlen = (int)(out - p->inbuf);
		const int	 nauth = p->outbuf[1];
		const int	 len = nauth + p->outbuf[nauth + 6] + 9;
		memmove(p->outbuf, p->outbuf + len, p->outlen - len);
		p->outlen -= len;
	} else {
		memmove(p->inbuf, in, inlen);
		p->inlen = (int)inlen;
	}
#undef send_or_die
}

uint32_t
tor_circuit(void)
{
	static uint32_t	 rand = 0;
	static time_t	 time = 0;
	struct timespec	 now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		err(1, "clock_gettime");
	if ((rand == 0 && time == 0 /* first time */) ||
	/* TODO: how long should we use our last tor circuit? */
	    now.tv_sec - time >= 60)
		rand = arc4random();
	time = now.tv_sec;
	return rand;
}

void
write_address(const struct peer *const p, uint8_t *out, const bool tran)
{
	const uint8_t	*in = p->outbuf;
	char		 name[256];
	if (*in != 5) {
		*out = (uint8_t)strlen(default_address);
		memcpy(out + 1, default_address, *out);
		out += *out + 1;
		*out++ = default_port >> 8;
		*out++ = default_port & 0xff;
		return;
	}
	const int	 nauth = in[1];
	in += nauth + 6;
	memcpy(name, in + 1, *in);
	name[*in] = 0;
	if (tran) {
		for (int low = 0, high = translation_table_len;
		    low < high; ) {
			const int mid = low + ((high - low) >> 1);
			const int cmp = strcmp(
			    translation_table[mid].name, name);
			if (cmp < 0)
				low = mid + 1;
			else if (cmp > 0)
				high = mid;
			else {
				const char *const newname =
				    translation_table[mid].newname;
				*out = (uint8_t)strlen(newname);
				memcpy(out + 1, newname, *out);
				out += *out + 1;
				memcpy(out, in + *in + 1, 2);
				return;
			}
		}
	}
	memcpy(out, in, *in + 3); /* copy name + port */
}

void
shutdown_in(struct peer *const p)
{
	p->inend = true;
	if (!p->inlen) {
		if (p->client_s != -1)
			shutdown(p->client_s, SHUT_WR);
		if ((!p->outlen && p->outend) || p->init)
			shutdown_all(p);
	}
}

void
shutdown_out(struct peer *const p)
{
	p->outend = true;
	if (!p->outlen) {
		if (p->tor_s != -1)
			shutdown(p->tor_s, SHUT_WR);
		if (!p->inlen && p->inend)
			shutdown_all(p);
	}
}

void
shutdown_all(struct peer *const p)
{
	if (p->client_s != -1) {
		shutdown(p->client_s, SHUT_RDWR);
		close(p->client_s);
		p->client_s = -1;
	}
	if (p->tor_s != -1) {
		shutdown(p->tor_s, SHUT_RDWR);
		close(p->tor_s);
		p->tor_s = -1;
	}
	p->client_s = p->tor_s = -1;
}
