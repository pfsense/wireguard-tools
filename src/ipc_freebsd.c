/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Rubicon Communications, LLC (Netgate)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef BSD_INTERNAL
#include <sys/param.h>
#include <sys/nv.h>
#include <assert.h>
#include <err.h>

#define	satosin(sa)	((struct sockaddr_in *)(sa))
#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))

typedef enum {
	WGC_PEER_ADD = 0x1,
	WGC_PEER_DEL = 0x2,
	WGC_PEER_UPDATE = 0x3,
	WGC_PEER_LIST = 0x4,
	WGC_GET = 0x5,
	WGC_SET = 0x6,
} wg_cmd_t;

struct allowedip {
	struct sockaddr a_addr;
	struct sockaddr a_mask;
};

static void
in_len2mask(struct in_addr *mask, u_int len)
{
	u_int i;
	u_char *p;

	p = (u_char *)mask;
	memset(mask, 0, sizeof(*mask));
	for (i = 0; i < len / NBBY; i++)
		p[i] = 0xff;
	if (len % NBBY)
		p[i] = (0xff00 >> (len % NBBY)) & 0xff;
}

static u_int
in_mask2len(struct in_addr *mask)
{
	u_int x, y;
	u_char *p;

	p = (u_char *)mask;
	for (x = 0; x < sizeof(*mask); x++) {
		if (p[x] != 0xff)
			break;
	}
	y = 0;
	if (x < sizeof(*mask)) {
		for (y = 0; y < NBBY; y++) {
			if ((p[x] & (0x80 >> y)) == 0)
				break;
		}
	}
	return x * NBBY + y;
}

static void
in6_prefixlen2mask(struct in6_addr *maskp, int len)
{
	static const u_char maskarray[NBBY] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
	int bytelen, bitlen, i;

	/* sanity check */
	if (len < 0 || len > 128) {
		errx(1, "in6_prefixlen2mask: invalid prefix length(%d)\n",
		    len);
		return;
	}

	memset(maskp, 0, sizeof(*maskp));
	bytelen = len / NBBY;
	bitlen = len % NBBY;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

static int
in6_mask2len(struct in6_addr *mask, u_char *lim0)
{
	int x = 0, y;
	u_char *lim = lim0, *p;

	/* ignore the scope_id part */
	if (lim0 == NULL || (uint64_t)(lim0 - (u_char *)mask) > sizeof(*mask))
		lim = (u_char *)mask + sizeof(*mask);
	for (p = (u_char *)mask; p < lim; x++, p++) {
		if (*p != 0xff)
			break;
	}
	y = 0;
	if (p < lim) {
		for (y = 0; y < NBBY; y++) {
			if ((*p & (0x80 >> y)) == 0)
				break;
		}
	}

	/*
	 * when the limit pointer is given, do a stricter check on the
	 * remaining bits.
	 */
	if (p < lim) {
		if (y != 0 && (*p & (0x00ff >> y)) != 0)
			return -1;
		for (p = p + 1; p < lim; p++)
			if (*p != 0)
				return -1;
	}

	return x * NBBY + y;
}

static nvlist_t *
pack_peer(struct wgpeer *peer)
{
	nvlist_t *nvl_peer = nvlist_create(0);
	int aip_count = 0;
	struct allowedip *aips, *paips;
	struct wgallowedip *aip;

	if (nvl_peer == NULL)
		return (NULL);
	for_each_wgallowedip(peer, aip) {
		aip_count++;
	}
	if (aip_count) {
		paips = aips = calloc(sizeof(*aips), aip_count);
		if (aips == NULL) {
			nvlist_destroy(nvl_peer);
			return (NULL);
		}
	}
	nvlist_add_binary(nvl_peer, "public-key", peer->public_key, WG_KEY_LEN);
	if (peer->flags & WGPEER_HAS_PRESHARED_KEY)
		nvlist_add_binary(nvl_peer, "pre-shared-key", peer->preshared_key, WG_KEY_LEN);
	if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
		nvlist_add_number(nvl_peer, "persistent-keepalive-interval", peer->persistent_keepalive_interval);
	if ((peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) &&
		    peer->endpoint.addr.sa_len <= sizeof(struct sockaddr))
		nvlist_add_binary(nvl_peer, "endpoint", &peer->endpoint.addr, sizeof(struct sockaddr));
	nvlist_add_bool(nvl_peer, "replace-allowedips", !!(peer->flags & WGPEER_REPLACE_ALLOWEDIPS));
	nvlist_add_bool(nvl_peer, "peer-remove", !!(peer->flags & WGPEER_REMOVE_ME));
	for_each_wgallowedip(peer, aip) {
		void *data = &paips->a_mask.sa_data;
		void *addr;

		paips->a_addr.sa_family = aip->family;
		if (aip->family == AF_INET) {
			in_len2mask((struct in_addr *)data, aip->cidr);
			addr = &satosin(&paips->a_addr)->sin_addr;
			memcpy(addr, &aip->ip4, sizeof(aip->ip4));
			paips->a_addr.sa_len = sizeof(struct sockaddr_in);
		} else if (aip->family == AF_INET6) {
			in6_prefixlen2mask((struct in6_addr *)data, aip->cidr);
			addr = &satosin6(&paips->a_addr)->sin6_addr;
			memcpy(addr, &aip->ip6, sizeof(aip->ip6));
			paips->a_addr.sa_len = sizeof(struct sockaddr_in6);

		} else
			errx(1, "invalid address family");
		paips++;
	}
	nvlist_add_binary(nvl_peer, "allowed-ips",  aips, sizeof(*aips) *aip_count);
	return (nvl_peer);
}

static struct wgpeer *
unpack_peer(const nvlist_t *nvl_peer)
{
	const void *key;
	const struct allowedip *aips;
	const struct sockaddr *endpoint;
	struct timespec *ts;
	struct wgpeer *peer;
	struct wgallowedip *aip;
	size_t size;
	int count, val;

	if ((peer = calloc(sizeof(*peer), 1)) == NULL)
		return (NULL);
	if (nvlist_exists_binary(nvl_peer, "public-key")) {
		key = nvlist_get_binary(nvl_peer, "public-key", &size);
		memcpy(peer->public_key, key, sizeof(peer->public_key));
		peer->flags |= WGPEER_HAS_PUBLIC_KEY;
	}
	if (nvlist_exists_binary(nvl_peer, "pre-shared-key")) {
		key = nvlist_get_binary(nvl_peer, "pre-shared-key", &size);
		memcpy(peer->preshared_key, key, sizeof(peer->preshared_key));
		peer->flags |= WGPEER_HAS_PRESHARED_KEY;
	}
	if (nvlist_exists_number(nvl_peer, "persistent-keepalive-interval")) {
		val = nvlist_get_number(nvl_peer, "persistent-keepalive-interval");
		peer->persistent_keepalive_interval = val;
		peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
	}
	if (nvlist_exists_binary(nvl_peer, "endpoint")) {
		endpoint = nvlist_get_binary(nvl_peer, "endpoint", &size);
		if (size <= sizeof(peer->endpoint.addr))
			memcpy(&peer->endpoint.addr, endpoint, endpoint->sa_len);
	}
	if (nvlist_exists_number(nvl_peer, "rx_bytes"))
		peer->rx_bytes = nvlist_get_number(nvl_peer, "rx_bytes");
	if (nvlist_exists_number(nvl_peer, "tx_bytes"))
		peer->tx_bytes = nvlist_get_number(nvl_peer, "tx_bytes");
	if (nvlist_exists_binary(nvl_peer, "last_handshake")) {
		*&peer->last_handshake_time = *(struct timespec64 *)nvlist_get_binary(nvl_peer, "last_handshake", &size);
		assert(size == sizeof(*ts));
	}

	if (!nvlist_exists_binary(nvl_peer, "allowed-ips"))
		return (peer);
	aips = nvlist_get_binary(nvl_peer, "allowed-ips", &size);
	if (size == 0 || size % sizeof(struct allowedip) != 0) {
		errx(1, "size %zu not integer multiple of allowedip", size);
	}

	count = size / sizeof(struct allowedip);
	aip = calloc(sizeof(*aip), count);
	if (aip == NULL)
		return (peer);
	
	for (int i = 0; i < count; i++, aip++, aips++) {
		sa_family_t family;
		void *bitmask;
		struct sockaddr *sa;
	
		if (peer->first_allowedip == NULL)
			peer->first_allowedip = aip;
		else
			peer->last_allowedip->next_allowedip = aip;
		peer->last_allowedip = aip;

		sa = __DECONST(void *, &aips->a_addr);
		bitmask = __DECONST(void *, &aips->a_mask.sa_data);
		aip->family = family = aips->a_addr.sa_family;
	
		if (family == AF_INET) {
			aip->cidr = in_mask2len(bitmask);
			memcpy(&aip->ip4, &satosin(sa)->sin_addr, sizeof(aip->ip4));
		} else if (family == AF_INET6) {
			aip->cidr = in6_mask2len(bitmask, NULL);
			memcpy(&aip->ip6, &satosin6(sa)->sin6_addr, sizeof(aip->ip6));
		} else
			errx(1, "bad family in peer %d\n", family);
	}
	return (peer);
}

static int
get_nvl_out_size(int sock, const char *ifname, u_long op, size_t *size)
{
	struct ifdrv ifd;
	int err;

	memset(&ifd, 0, sizeof(ifd));

	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = 0;
	ifd.ifd_data = NULL;

	err = ioctl(sock, SIOCGDRVSPEC, &ifd);
	if (err)
		return (errno);
	*size = ifd.ifd_len;
	return (0);
}

static int
do_cmd(int sock, const char *ifname, u_long op, void *arg, size_t argsize, int set)
{
	struct ifdrv ifd;

	memset(&ifd, 0, sizeof(ifd));

	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;

	return (ioctl(sock, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd));
}

static int
is_match(const char *name)
{
	if (strncmp("wg", name, 2))
		return (ENOENT);
	if (strlen(name) < 3)
		return (ENOENT);
	if (!isdigit(name[2]))
		return (ENOENT);
	return (0);
}

static int
kernel_get_device(struct wgdevice **device, const char *ifname)
{
	size_t size;
	void *packed;
	nvlist_t *nvl;
	const nvlist_t * const *nvl_peerlist;
	const void *key;
	struct wgdevice *dev;
	struct wgpeer *peer;
	size_t peercount;
	int rc, s = get_dgram_socket();

	*device = NULL;
	dev = NULL;
	packed = NULL;
	nvl = NULL;
	if (s < 0)
		return -errno;
	rc = is_match(ifname);
	if (rc)
		return (-rc);
	if ((rc = get_nvl_out_size(s, ifname, WGC_GET, &size)))
		return (-rc);

	if ((packed = malloc(size)) == NULL)
		return (-ENOMEM);
	if ((rc = do_cmd(s, ifname , WGC_GET, packed, size, 0))) {
		errno = -rc;
		goto out;
	}
	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		goto out;

	strcpy(dev->name, ifname);
	nvl = nvlist_unpack(packed, size, 0);

	if (nvlist_exists_number(nvl, "listen-port")) {
		dev->listen_port = nvlist_get_number(nvl, "listen-port");
		dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
	}
	if (nvlist_exists_binary(nvl, "public-key")) {
		key = nvlist_get_binary(nvl, "public-key", &size);
		memcpy(dev->public_key, key, sizeof(dev->public_key));
		dev->flags |= WGDEVICE_HAS_PUBLIC_KEY;
	}
	if (nvlist_exists_binary(nvl, "private-key")) {
		key = nvlist_get_binary(nvl, "private-key", &size);
		memcpy(dev->private_key, key, sizeof(dev->private_key));
		dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
	}
	if (!nvlist_exists_nvlist_array(nvl, "peer-list"))
		goto success;
	nvl_peerlist = nvlist_get_nvlist_array(nvl, "peer-list", &peercount);
	for (int i = 0; i < (int)peercount; i++, nvl_peerlist++) {
		peer = unpack_peer(*nvl_peerlist);
		if (peer == NULL)
			goto success;
		if (dev->first_peer == NULL)
			dev->first_peer = peer;
		else
			dev->last_peer->next_peer = peer;
		dev->last_peer = peer;
	}
success:
	*device = dev;
out:
	free(packed);
	nvlist_destroy(nvl);
	return (-rc);
}


static int
kernel_set_device(struct wgdevice *dev)
{
	struct wgpeer *peer;
	nvlist_t *nvl, **nvl_array;
	void *packed;
	int i, peer_count = 0;
	size_t size;
	int rc, s = get_dgram_socket();

	for_each_wgpeer(dev, peer) {
		peer_count++;
	}
	nvl = nvlist_create(0);
	if (peer_count) {
		nvl_array = calloc(sizeof(void *), peer_count);
		if (nvl_array == NULL)
			return (-ENOMEM);
	}
	if ((nvl = nvlist_create(0)) == NULL) {
		free(nvl_array);
		return (-ENOMEM);
	}
	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY)
		nvlist_add_binary(nvl, "private-key", dev->private_key, WG_KEY_LEN);
	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT)
		nvlist_add_number(nvl, "listen-port", dev->listen_port);
	if (dev->flags & WGDEVICE_HAS_FWMARK)
		nvlist_add_number(nvl, "user-cookie", dev->fwmark);
	nvlist_add_bool(nvl, "replace-peers", !!(dev->flags & WGDEVICE_REPLACE_PEERS));

	i = 0;
	for_each_wgpeer(dev, peer) {
		assert(i < peer_count);
		nvl_array[i] = pack_peer(peer);
		if (nvl_array[i] == NULL)
			break;
		i++;
	}
	if (i > 0)
		nvlist_add_nvlist_array(nvl, "peer-list", (const nvlist_t * const *)nvl_array, i);
	packed = nvlist_pack(nvl, &size);
	if (do_cmd(s, dev->name, WGC_SET, packed, size, true)) {
		rc = -errno;
		goto out;
	}
	rc = 0;
out:
	free(packed);
	return (rc);
}
#endif
