/*
 * Copyright (C) 2015-2024 IoT.bzh Company
 * Author: José Bollo <jose.bollo@iot.bzh>
 *
 * $RP_BEGIN_LICENSE$
 * Commercial License Usage
 *  Licensees holding valid commercial IoT.bzh licenses may use this file in
 *  accordance with the commercial license agreement provided with the
 *  Software or, alternatively, in accordance with the terms contained in
 *  a written agreement between you and The IoT.bzh Company. For licensing terms
 *  and conditions see https://www.iot.bzh/terms-conditions. For further
 *  information use the contact form at https://www.iot.bzh/contact.
 *
 * GNU General Public License Usage
 *  Alternatively, this file may be used under the terms of the GNU General
 *  Public license version 3. This license is as published by the Free Software
 *  Foundation and appearing in the file LICENSE.GPLv3 included in the packaging
 *  of this file. Please review the following information to ensure the GNU
 *  General Public License requirements will be met
 *  https://www.gnu.org/licenses/gpl-3.0.html.
 * $RP_END_LICENSE$
 */

#include "../libafb-config.h"

#define WITH_GNUTLS 1
#if WITH_GNUTLS

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <rp-utils/rp-verbose.h>

#include "sys/ev-mgr.h"

#include "sys/x-errno.h"

static int initialized;

static gnutls_certificate_credentials_t xcred;

static int initialize()
{
	int rc;

	/* lazy initialization */
	rc = initialized;
	if (rc != 0)
		return rc;

	/* check version */
	if (gnutls_check_version("3.4.6") == NULL) {
		RP_ERROR("GnuTLS 3.4.6 or later is required");
		return initialized = X_ENOTSUP;
	}

        /* X509 stuff */
        rc = gnutls_certificate_allocate_credentials(&xcred);
	if (rc < 0)
		return initialized = X_ENOMEM;

        /* sets the system trusted CAs for Internet PKI */
        rc = gnutls_certificate_set_x509_system_trust(xcred);
	if (rc < 0)
		return initialized = X_ECANCELED;

        /* If client holds a certificate it can be set using the following:
         *
         gnutls_certificate_set_x509_key_file (xcred, "cert.pem", "key.pem",
         GNUTLS_X509_FMT_PEM);
         */

	return initialized = 1;
}

enum state
{
	state_handshake,
	state_established,
	state_bye,
	state_dead
};

#define BUFSZ 1024

struct tls_flow
{
	struct ev_fd *efd;
	int fd;
	unsigned clen;
	char buffer[BUFSZ];
};

struct tls
{
        gnutls_session_t session;
	enum state state;
	struct tls_flow crypt;
	struct tls_flow plain;
	char hostname[];
};

static void bye_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure);
static void crypt_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure);
static void plain_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure);
static void handshake_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure);

static void terminate(struct tls *tls, const char *error)
{
	if (tls->state == state_dead)
		return;

	if (tls->state == state_established) {
		tls->state = state_bye;
		ev_fd_set_events(tls->crypt.efd, EPOLLIN);
		ev_fd_set_handler(tls->crypt.efd, bye_cb, tls);
		gnutls_bye (tls->session, GNUTLS_SHUT_WR);
		return;
	}

	tls->state = state_dead;
	ev_fd_unref(tls->crypt.efd);
	ev_fd_unref(tls->plain.efd);
        gnutls_deinit(tls->session);
	free(tls);
}

static void do_write(struct tls *tls, struct tls_flow *in, struct tls_flow *out)
{
	unsigned len, off;
	ssize_t ssz;

	len = in->clen;
	ssz = !len
		? 0
		: out == &tls->crypt
			? gnutls_record_send(tls->session, in->buffer, len)
			: write(out->fd, in->buffer, len);
	if (ssz > 0) {
		off = (unsigned)ssz;
		len -= off;
		in->clen = len;
		if (len)
			memmove(in->buffer, &in->buffer[off], len);
	}
	ev_fd_set_events(out->efd, len ? EPOLLIN|EPOLLOUT : EPOLLIN);
}

static void do_read_write(struct tls *tls, struct tls_flow *in, struct tls_flow *out)
{
	ssize_t ssz;
	unsigned len, loop = 1;

	while(loop) {
		len = in->clen;
		if (len < sizeof in->buffer) {
			if (in == &tls->crypt) {
				ssz = gnutls_record_recv(tls->session, &in->buffer[len], sizeof in->buffer - len);
				loop = ssz > 0 || ssz == GNUTLS_E_INTERRUPTED;
			}
			else {
				ssz = read(in->fd, &in->buffer[len], sizeof in->buffer - len);
				loop = ssz > 0 || (ssz < 0 && errno == EINTR);
			}
			if (ssz > 0) {
				len += (unsigned)ssz;
				in->clen = len;
			}
			else
				len += loop; /* ensure an extra loop if INTR */
		}
		if (in->clen)
			do_write(tls, in, out);
		loop = loop && len > in->clen;
	}
}

static void do_decrypt(struct tls *tls)
{
	do_read_write(tls, &tls->crypt, &tls->plain);
}

static void do_crypt(struct tls *tls)
{
	do_read_write(tls, &tls->plain, &tls->crypt);
}

static void do_decrypt_next(struct tls *tls)
{
	do_write(tls, &tls->crypt, &tls->plain);
}

static void do_crypt_next(struct tls *tls)
{
	do_write(tls, &tls->plain, &tls->crypt);
}

static void bye_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure)
{
	struct tls *tls = closure;

	if (revents & EPOLLIN) {
		do_decrypt(tls);
	}
}

/* callback of external crypt side */
static void crypt_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure)
{
	struct tls *tls = closure;

	if (revents & EPOLLHUP) {
		terminate(tls, 0);
		return;
	}
	if (revents & EPOLLOUT) {
		do_crypt_next(tls);
	}
	if (revents & EPOLLIN) {
		do_decrypt(tls);
	}
}

/* callback of internal plain side */
static void plain_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure)
{
	struct tls *tls = closure;

	if (revents & EPOLLHUP) {
		terminate(tls, 0);
		return;
	}
	if (revents & EPOLLOUT) {
		do_decrypt_next(tls);
	}
	if (revents & EPOLLIN) {
		do_crypt(tls);
	}
}

static int do_handshake(struct tls *tls)
{
	int rc;

        rc = gnutls_handshake(tls->session);
	if (rc != GNUTLS_E_SUCCESS) {
                if (!gnutls_error_is_fatal(rc))
                        return 0;
                terminate(tls, "fatal handshake");
                return X_ECANCELED;
	}

	tls->state = state_established;
	ev_fd_set_events(tls->crypt.efd, EPOLLIN);
	ev_fd_set_events(tls->plain.efd, EPOLLIN);
	ev_fd_set_handler(tls->crypt.efd, crypt_cb, tls);
        return 0;
}

static void handshake_cb(struct ev_fd *efd, int fd, uint32_t revents, void *closure)
{
	struct tls *tls = closure;

	if (revents & EPOLLHUP) {
		terminate(tls, 0);
		return;
	}

	gnutls_handshake(tls->session);
}

int tls_upgrade_client(struct ev_mgr *mgr, int sd, const char *hostname)
{
	int rc, pairfd[2];
	struct tls *tls;

	/* initialization */
	rc = initialize();
	if (rc < 0)
		goto error;

	/* create the underlying socket pair */
	rc = socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, pairfd);
	if (rc < 0) {
		rc = X_EBUSY;
		goto error;
	}

	/* allocates the struct */
	tls = malloc(sizeof *tls + (hostname ? 1 + strlen(hostname) : 0));
	if (!tls) {
		rc = X_ENOMEM;
		goto error2;
	}

        /* Initialize TLS session */
	rc = gnutls_init(&tls->session, GNUTLS_CLIENT);
	if (rc != GNUTLS_E_SUCCESS) {
		rc = X_ECANCELED;
		goto error3;
	}
	rc = gnutls_set_default_priority(tls->session);
	if (rc == GNUTLS_E_SUCCESS) {
		rc = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE, xcred);
		if (rc == GNUTLS_E_SUCCESS && hostname) {
			strcpy(tls->hostname, hostname);
			gnutls_session_set_verify_cert(tls->session, tls->hostname, 0);
		}
	}
	if (rc != GNUTLS_E_SUCCESS) {
		rc = X_ECANCELED;
		goto error4;
	}
        gnutls_handshake_set_timeout(tls->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
        gnutls_transport_set_int(tls->session, sd);

        /* Perform the TLS handshake */
	fcntl(sd, F_SETFL, O_NONBLOCK);
	tls->state = state_handshake;
	tls->crypt.clen = tls->plain.clen = 0;
	tls->crypt.fd = sd;
	tls->plain.fd = pairfd[1];
	rc = ev_mgr_add_fd(mgr, &tls->plain.efd, pairfd[1], 0, plain_cb, tls, 1, 1);
	if (rc >= 0) {
		rc = ev_mgr_add_fd(mgr, &tls->crypt.efd, sd, EPOLLIN, handshake_cb, tls, 1, 1);
		if (rc >= 0) {
                        rc = do_handshake(tls);
        		if (rc >= 0)
        			return pairfd[0];
                        close(pairfd[0]);
                        return rc;
                }
		ev_fd_unref(tls->plain.efd);
	}

error4:
        gnutls_deinit(tls->session);
error3:
	free(tls);
error2:
	close(pairfd[1]);
	close(pairfd[0]);
error:
	return rc;
}


#endif
