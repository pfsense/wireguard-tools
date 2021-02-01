// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Rubicon Communications, LLC (Netgate)
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 */

#include <sys/param.h>
#include <sys/nv.h>
#include <sys/sockio.h>
#include <assert.h>
#include <err.h>

#define IPC_SUPPORTS_KERNEL_INTERFACE

#define	satosin(sa)	((struct sockaddr_in *)(sa))
#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))

typedef enum {
	/* TODO: these should be 0x1 and 0x2, since no other commands should be defined. */
	WGC_GET = 0x5,
	WGC_SET = 0x6,
} wg_cmd_t;

struct allowedip {
	struct sockaddr_storage a_addr;
	struct sockaddr_storage a_mask;
};

static void in_len2mask(struct in_addr *mask, unsigned int len)
{
	unsigned int i;
	uint8_t *p;

	p = (uint8_t *)mask;
	memset(mask, 0, sizeof(*mask));
	for (i = 0; i < len / NBBY; i++)
		p[i] = 0xff;
	if (len % NBBY)
		p[i] = (0xff00 >> (len % NBBY)) & 0xff;
}

static unsigned int in_mask2len(struct in_addr *mask)
{
	unsigned int x, y;
	uint8_t *p;

	p = (uint8_t *)mask;
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

static void in6_prefixlen2mask(struct in6_addr *maskp, unsigned int len)
{
	static const uint8_t maskarray[NBBY] = { 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
	int bytelen, bitlen, i;

	if (len > 128)
		return;

	memset(maskp, 0, sizeof(*maskp));
	bytelen = len / NBBY;
	bitlen = len % NBBY;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

static int in6_mask2len(struct in6_addr *mask, uint8_t *lim0)
{
	int x = 0, y;
	uint8_t *lim = lim0, *p;

	/* Ignore the scope_id part. */
	if (lim0 == NULL || (uint64_t)(lim0 - (uint8_t *)mask) > sizeof(*mask))
		lim = (uint8_t *)mask + sizeof(*mask);
	for (p = (uint8_t *)mask; p < lim; ++x, ++p) {
		if (*p != 0xff)
			break;
	}
	y = 0;
	if (p < lim) {
		for (y = 0; y < NBBY; ++y) {
			if ((*p & (0x80 >> y)) == 0)
				break;
		}
	}

	/* When the limit pointer is given, do a stricter check on the remaining bits. */
	if (p < lim) {
		if (y != 0 && (*p & (0x00ff >> y)) != 0)
			return -1;
		for (p = p + 1; p < lim; ++p)
			if (*p != 0)
				return -1;
	}

	return x * NBBY + y;
}

static nvlist_t *pack_peer(struct wgpeer *peer)
{
	nvlist_t *nvl_peer = nvlist_create(0);
	int aip_count = 0;
	struct allowedip *aips, *paips;
	struct wgallowedip *aip;

	if (!nvl_peer)
		return NULL;
	for_each_wgallowedip(peer, aip)
		aip_count++;
	if (aip_count) {
		paips = aips = calloc(sizeof(*aips), aip_count);
		if (!aips) {
			nvlist_destroy(nvl_peer);
			return NULL;
		}
	}
	nvlist_add_binary(nvl_peer, "public-key", peer->public_key, WG_KEY_LEN);
	if (peer->flags & WGPEER_HAS_PRESHARED_KEY)
		nvlist_add_binary(nvl_peer, "pre-shared-key", peer->preshared_key, WG_KEY_LEN); /* TODO: preshared-key instead of pre-shared-key */
	if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
		nvlist_add_number(nvl_peer, "persistent-keepalive-interval", peer->persistent_keepalive_interval);
	if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
		nvlist_add_binary(nvl_peer, "endpoint", &peer->endpoint.addr, peer->endpoint.addr.sa_len);
	nvlist_add_bool(nvl_peer, "replace-allowedips", !!(peer->flags & WGPEER_REPLACE_ALLOWEDIPS));
	nvlist_add_bool(nvl_peer, "peer-remove", !!(peer->flags & WGPEER_REMOVE_ME));
	for_each_wgallowedip(peer, aip) {
		void *addr;

		paips->a_addr.ss_family = aip->family;
		if (aip->family == AF_INET) {
			in_len2mask((struct in_addr *)&((struct sockaddr *)&paips->a_mask)->sa_data, aip->cidr);
			addr = &satosin(&paips->a_addr)->sin_addr;
			memcpy(addr, &aip->ip4, sizeof(aip->ip4));
			paips->a_addr.ss_len = sizeof(struct sockaddr_in);
		} else if (aip->family == AF_INET6) {
			in6_prefixlen2mask((struct in6_addr *)&((struct sockaddr *)&paips->a_mask)->sa_data, aip->cidr);
			addr = &satosin6(&paips->a_addr)->sin6_addr;
			memcpy(addr, &aip->ip6, sizeof(aip->ip6));
			paips->a_addr.ss_len = sizeof(struct sockaddr_in6);

		}
		paips++;
	}
	nvlist_add_binary(nvl_peer, "allowed-ips", aips, sizeof(*aips) *aip_count);
	return nvl_peer;
}

static struct wgpeer *unpack_peer(const nvlist_t *nvl_peer)
{
	const void *key;
	const struct allowedip *aips;
	const struct sockaddr *endpoint;
	struct wgpeer *peer;
	struct wgallowedip *aip;
	size_t size;
	int count, val;

	if (!(peer = calloc(sizeof(*peer), 1)))
		return NULL;
	if (nvlist_exists_binary(nvl_peer, "public-key")) {
		key = nvlist_get_binary(nvl_peer, "public-key", &size);
		memcpy(peer->public_key, key, sizeof(peer->public_key));
		peer->flags |= WGPEER_HAS_PUBLIC_KEY;
	}
	if (nvlist_exists_binary(nvl_peer, "pre-shared-key")) { /* TODO: preshared-key instead of pre-shared-key */
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
		if (size <= sizeof(peer->endpoint))
			memcpy(&peer->endpoint.addr, endpoint, size);
	}
	if (nvlist_exists_number(nvl_peer, "rx_bytes"))
		peer->rx_bytes = nvlist_get_number(nvl_peer, "rx_bytes");
	if (nvlist_exists_number(nvl_peer, "tx_bytes"))
		peer->tx_bytes = nvlist_get_number(nvl_peer, "tx_bytes");
	if (nvlist_exists_binary(nvl_peer, "last_handshake"))
		peer->last_handshake_time = *(struct timespec64 *)nvlist_get_binary(nvl_peer, "last_handshake", &size);

	if (!nvlist_exists_binary(nvl_peer, "allowed-ips"))
		return peer;
	aips = nvlist_get_binary(nvl_peer, "allowed-ips", &size);
	if (size == 0 || size % sizeof(struct allowedip) != 0)
		return peer;

	count = size / sizeof(struct allowedip);
	aip = calloc(sizeof(*aip), count);
	if (!aip)
		return peer;

	for (int i = 0; i < count; ++i, ++aip, ++aips) {
		sa_family_t family;
		void *bitmask;
		struct sockaddr *sa;

		if (peer->first_allowedip == NULL)
			peer->first_allowedip = aip;
		else
			peer->last_allowedip->next_allowedip = aip;
		peer->last_allowedip = aip;

		sa = __DECONST(void *, &aips->a_addr);
		bitmask = __DECONST(void *,
		    ((const struct sockaddr *)&aips->a_mask)->sa_data);
		aip->family = family = aips->a_addr.ss_family;

		if (family == AF_INET) {
			aip->cidr = in_mask2len(bitmask);
			memcpy(&aip->ip4, &satosin(sa)->sin_addr, sizeof(aip->ip4));
		} else if (family == AF_INET6) {
			aip->cidr = in6_mask2len(bitmask, NULL);
			memcpy(&aip->ip6, &satosin6(sa)->sin6_addr, sizeof(aip->ip6));
		}
	}
	return peer;
}

static bool get_nvl_out_size(int sock, const char *ifname, u_long op, size_t *size)
{
	struct ifdrv ifd = { .ifd_cmd = op };

	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	if (ioctl(sock, SIOCGDRVSPEC, &ifd))
		return false;
	*size = ifd.ifd_len;
	return true;
}

static bool do_cmd(int sock, const char *ifname, u_long op, void *arg, size_t argsize, int set)
{
	struct ifdrv ifd = { .ifd_cmd = op, .ifd_len = argsize, .ifd_data = arg };

	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	return !ioctl(sock, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd);
}

static bool is_match(const char *name)
{
	errno = ENOENT;
	if (strncmp("wg", name, 2))
		return false;
	if (strlen(name) < 3)
		return false;
	if (!isdigit(name[2]))
		return false;
	errno = 0;
	return true;
}

static int get_dgram_socket(void)
{
	static int sock = -1;
	if (sock < 0)
		sock = socket(AF_INET, SOCK_DGRAM, 0);
	return sock;
}

static int kernel_get_wireguard_interfaces(struct string_list *list)
{
	struct ifgroupreq ifgr = { .ifgr_name = "wg" };
	struct ifg_req *ifg;
	int s = get_dgram_socket(), ret = 0;

	if (s < 0)
		return -errno;

	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0)
		return errno == ENOENT ? 0 : -errno;

	ifgr.ifgr_groups = calloc(1, ifgr.ifgr_len);
	if (!ifgr.ifgr_groups)
		return -errno;
	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0) {
		ret = -errno;
		goto out;
	}

	for (ifg = ifgr.ifgr_groups; ifg && ifgr.ifgr_len > 0; ++ifg) {
		if ((ret = string_list_add(list, ifg->ifgrq_member)) < 0)
			goto out;
		ifgr.ifgr_len -= sizeof(struct ifg_req);
	}

out:
	free(ifgr.ifgr_groups);
	return ret;
}

static int kernel_get_device(struct wgdevice **device, const char *ifname)
{
	size_t size;
	void *packed = NULL;
	nvlist_t *nvl = NULL;
	const nvlist_t * const *nvl_peerlist;
	const void *key;
	struct wgdevice *dev = NULL;
	struct wgpeer *peer;
	size_t peercount;
	int rc = 0, s = get_dgram_socket();

	*device = NULL;
	if (s < 0)
		return -errno;
	if (!is_match(ifname))
		return -errno;
	if (!get_nvl_out_size(s, ifname, WGC_GET, &size))
		return -errno;

	if (!(packed = malloc(size)))
		return -errno;
	if (!do_cmd(s, ifname , WGC_GET, packed, size, 0)) {
		rc = -errno;
		goto out;
	}
	if (!(dev = calloc(1, sizeof(*dev))))
		goto out;

	strlcpy(dev->name, ifname, sizeof(dev->name));
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
	for (size_t i = 0; i < peercount; ++i, ++nvl_peerlist) {
		peer = unpack_peer(*nvl_peerlist);
		if (!peer)
			goto success;
		if (!dev->first_peer)
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
	return -rc;
}


static int kernel_set_device(struct wgdevice *dev)
{
	struct wgpeer *peer;
	nvlist_t *nvl, **nvl_array;
	void *packed;
	int i, peer_count = 0;
	size_t size;
	int rc, s = get_dgram_socket();

	for_each_wgpeer(dev, peer)
		peer_count++;
	nvl = nvlist_create(0);
	if (peer_count) {
		nvl_array = calloc(sizeof(void *), peer_count);
		if (!nvl_array)
			return -errno;
	}
	if (!(nvl = nvlist_create(0))) {
		free(nvl_array);
		return -errno;
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
		nvl_array[i] = pack_peer(peer);
		if (!nvl_array[i])
			break;
		++i;
	}
	if (i > 0)
		nvlist_add_nvlist_array(nvl, "peer-list", (const nvlist_t * const *)nvl_array, i);
	packed = nvlist_pack(nvl, &size);
	if (!do_cmd(s, dev->name, WGC_SET, packed, size, true)) {
		rc = -errno;
		goto out;
	}
	rc = 0;
out:
	/* TODO: does nvl_array or peer or anything else leak? does this function leak? */
	free(packed);
	nvlist_destroy(nvl);
	if (peer_count)
		free(nvl_array);
	return rc;
}
