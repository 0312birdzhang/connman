/*
 *  ConnMan VPN daemon
 *
 *  Xray VPN plugin for ConnMan.
 *
 *  This plugin launches the official Xray-core binary with a config
 *  generated from the provider properties. Xray creates and owns a tun
 *  interface (configured via the tun inbound "name" field); the plugin
 *  waits for that interface to come up, hands it to the connman-vpnd
 *  bridge, and lets the bridge install the rtnl watch / bring it ready
 *  exactly like the WireGuard plugin does.
 *
 *  License: GPL-2.0
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include "../vpn-provider.h"
#include "../vpn.h"

#include "vpn.h"

#define XRAY_IFNAME_DEFAULT "utun50"
#define XRAY_STARTUP_TIMEOUT_MS 5000
#define XRAY_POLL_INTERVAL_US 50000
#define XRAY_ROUTE_SETUP_TIMEOUT 200
#define XRAY_DIED_DELAY_MS 50
#define XRAY_SIGTERM_GRACE_MS 100

#ifndef XRAY
#define XRAY "/usr/bin/xray"
#endif

struct xray_info {
	struct vpn_provider *provider;
	GPid pid;
	char *config_path;
	char *ifname;
	char *gateway;
	guint route_setup_id;
	guint dying_id;
	guint child_watch_id;
	bool dying;
	bool ipv4;
	bool ipv6;
};

struct xray_exit_data {
	struct vpn_provider *provider;
	int err;
};

struct {
	const char *opt;
	bool save;
} xray_options[] = {
	{"Xray.Address",          true},
	{"Xray.TunName",          true},
	{"Xray.DNS",              true},
	{"Xray.Routes",           true},
	{"Xray.OutboundProtocol", true},
	{"Xray.Port",             true},
	{"Xray.UUID",             true},
	{"Xray.Password",         true},
	{"Xray.Encryption",       true},
	{"Xray.Flow",             true},
	{"Xray.Network",          true},
	{"Xray.Security",         true},
	{"Xray.SNI",              true},
	{"Xray.ALPN",             true},
	{"Xray.Fingerprint",      true},
	{"Xray.PublicKey",        true},
	{"Xray.ShortID",          true},
	{"Xray.WSPath",           true},
	{"Xray.WSHost",           true},
	{"Xray.GRPCServiceName",  true},
	{"Xray.AssetDir",         true},
	{"Xray.LogLevel",         true},
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static void free_private_data(struct xray_info *info)
{
	if (!info)
		return;

	if (info->provider && vpn_provider_get_plugin_data(info->provider) == info)
		vpn_provider_set_plugin_data(info->provider, NULL);

	if (info->provider)
		vpn_provider_unref(info->provider);

	g_free(info->config_path);
	g_free(info->ifname);
	g_free(info->gateway);
	g_free(info);
}

static struct xray_info *create_private_data(struct vpn_provider *provider)
{
	struct xray_info *info;

	info = g_malloc0(sizeof(struct xray_info));
	info->provider = vpn_provider_ref(provider);
	info->pid = 0;

	return info;
}

/* ---- JSON helpers ----------------------------------------------------- */

static char *json_escape(const char *s)
{
	GString *g;
	const unsigned char *p;

	g = g_string_new("\"");
	for (p = (const unsigned char *)s; p && *p; p++) {
		switch (*p) {
		case '"':
		case '\\':
			g_string_append_printf(g, "\\%c", *p);
			break;
		case '\n':
			g_string_append(g, "\\n");
			break;
		case '\r':
			g_string_append(g, "\\r");
			break;
		case '\t':
			g_string_append(g, "\\t");
			break;
		default:
			if (*p < 0x20)
				g_string_append_printf(g, "\\u%04x", *p);
			else
				g_string_append_c(g, *p);
		}
	}
	g_string_append_c(g, '"');
	return g_string_free(g, FALSE);
}

static void append_kv_string(GString *g, const char *key, const char *val)
{
	char *esc = json_escape(val ? val : "");
	g_string_append_printf(g, "\"%s\": %s", key, esc);
	g_free(esc);
}

static void append_kv_uint(GString *g, const char *key, unsigned int val)
{
	g_string_append_printf(g, "\"%s\": %u", key, val);
}

static void append_json_string_item(GString *g, const char *val, bool first)
{
	char *esc = json_escape(val ? val : "");
	if (!first)
		g_string_append_c(g, ',');
	g_string_append(g, esc);
	g_free(esc);
}

/* Split "addr/prefix" into address and (for v4) dotted netmask. */
static int split_cidr(const char *cidr, char *ip, int ip_len,
			char *netmask, int nm_len, int *family)
{
	char buf[INET6_ADDRSTRLEN];
	char **tok;
	unsigned char prefix;
	char *end;
	int fam = AF_UNSPEC;

	tok = g_strsplit(cidr, "/", 2);
	if (g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return -EINVAL;
	}

	if (inet_pton(AF_INET, tok[0], buf) == 1) {
		fam = AF_INET;
	} else if (inet_pton(AF_INET6, tok[0], buf) == 1) {
		fam = AF_INET6;
	} else {
		g_strfreev(tok);
		return -EINVAL;
	}

	prefix = (unsigned char)g_ascii_strtoull(tok[1], &end, 10);
	g_strfreev(tok);

	g_strlcpy(ip, cidr, ip_len);
	char *slash = strchr(ip, '/');
	if (slash)
		*slash = '\0';

	if (netmask && nm_len > 0) {
		if (fam == AF_INET) {
			unsigned int m = prefix >= 32 ? 0xffffffffu :
						(0xffffffffu << (32 - prefix));
			snprintf(netmask, nm_len, "%u.%u.%u.%u",
				(m >> 24) & 0xff, (m >> 16) & 0xff,
				(m >> 8) & 0xff, m & 0xff);
		} else {
			snprintf(netmask, nm_len, "%u", prefix);
		}
	}

	if (family)
		*family = fam;

	return 0;
}

static int resolve_host(const char *host, char *out, int out_len)
{
	struct addrinfo hints, *res, *rp;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	err = getaddrinfo(host, NULL, &hints, &res);
	if (err)
		return -EHOSTUNREACH;

	for (rp = res; rp; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET) {
			inet_ntop(AF_INET,
				&((struct sockaddr_in *)rp->ai_addr)->sin_addr,
				out, out_len);
			break;
		} else if (rp->ai_family == AF_INET6) {
			inet_ntop(AF_INET6,
				&((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr,
				out, out_len);
			break;
		}
	}

	freeaddrinfo(res);
	return rp ? 0 : -EHOSTUNREACH;
}

/* ---- config.json generation ------------------------------------------ */

static void append_stream_settings(GString *g, struct vpn_provider *provider)
{
	const char *network = vpn_provider_get_string(provider, "Xray.Network");
	const char *security = vpn_provider_get_string(provider, "Xray.Security");
	const char *sni = vpn_provider_get_string(provider, "Xray.SNI");
	const char *alpn = vpn_provider_get_string(provider, "Xray.ALPN");
	const char *fpr = vpn_provider_get_string(provider, "Xray.Fingerprint");
	const char *wspath = vpn_provider_get_string(provider, "Xray.WSPath");
	const char *wshost = vpn_provider_get_string(provider, "Xray.WSHost");
	const char *grpc = vpn_provider_get_string(provider,
							"Xray.GRPCServiceName");
	const char *pubkey = vpn_provider_get_string(provider, "Xray.PublicKey");
	const char *sid = vpn_provider_get_string(provider, "Xray.ShortID");

	if (!network)
		network = "tcp";
	if (!security)
		security = "tls";

	g_string_append(g, "      \"streamSettings\": {\n");
	append_kv_string(g, "        \"network\"", network);
	g_string_append_c(g, ',');
	g_string_append_c(g, '\n');
	append_kv_string(g, "        \"security\"", security);
	g_string_append_c(g, '\n');

	if (g_str_equal(security, "tls")) {
		g_string_append(g, "        ,\"tlsSettings\": {\n");
		if (sni) {
			append_kv_string(g, "          \"serverName\"", sni);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		if (alpn) {
			g_string_append(g, "          \"alpn\": [");
			char **items = g_strsplit_set(alpn, ", ", -1);
			bool first = true;
			for (unsigned int i = 0; items[i]; i++) {
				if (!*items[i])
					continue;
				append_json_string_item(g, items[i], first);
				first = false;
			}
			g_strfreev(items);
			g_string_append(g, "],\n");
		}
		if (fpr) {
			append_kv_string(g, "          \"fingerprint\"", fpr);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		g_string_append(g, "          \"allowInsecure\": false\n");
		g_string_append(g, "        }\n");
	} else if (g_str_equal(security, "reality")) {
		g_string_append(g, "        ,\"realitySettings\": {\n");
		if (sni) {
			append_kv_string(g, "          \"serverName\"", sni);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		if (pubkey) {
			append_kv_string(g, "          \"publicKey\"", pubkey);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		if (sid) {
			append_kv_string(g, "          \"shortId\"", sid);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		if (fpr) {
			append_kv_string(g, "          \"fingerprint\"", fpr);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		g_string_append(g, "          \"show\": false\n");
		g_string_append(g, "        }\n");
	} else {
		/* security = "none": no security-specific block. */
	}

	if (g_str_equal(network, "tcp")) {
		g_string_append(g, "        ,\"tcpSettings\": { \"header\": { \"type\": \"none\" } }\n");
	} else if (g_str_equal(network, "ws")) {
		g_string_append(g, "        ,\"wsSettings\": {\n");
		if (wspath) {
			append_kv_string(g, "          \"path\"", wspath);
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
		}
		g_string_append(g, "          \"headers\": {");
		if (wshost) {
			g_string_append(g, "\n            ");
			append_kv_string(g, "Host", wshost);
			g_string_append_c(g, '\n');
			g_string_append(g, "          }\n");
		} else {
			g_string_append(g, "}\n");
		}
		g_string_append(g, "        }\n");
	} else if (g_str_equal(network, "grpc")) {
		g_string_append(g, "        ,\"grpcSettings\": {\n");
		if (grpc) {
			append_kv_string(g, "          \"serviceName\"", grpc);
			g_string_append_c(g, '\n');
		} else {
			g_string_append(g, "          \"serviceName\": \"\"\n");
		}
		g_string_append(g, "        }\n");
	}

	g_string_append(g, "      }\n");
}

static gchar *build_config_json(struct xray_info *info,
				struct vpn_provider *provider)
{
	const char *addr = vpn_provider_get_string(provider, "Xray.Address");
	const char *tunname = vpn_provider_get_string(provider, "Xray.TunName");
	const char *dns = vpn_provider_get_string(provider, "Xray.DNS");
	const char *proto = vpn_provider_get_string(provider,
							"Xray.OutboundProtocol");
	const char *host = vpn_provider_get_string(provider, "Host");
	const char *ports = vpn_provider_get_string(provider, "Xray.Port");
	const char *uuid = vpn_provider_get_string(provider, "Xray.UUID");
	const char *password = vpn_provider_get_string(provider, "Xray.Password");
	const char *enc = vpn_provider_get_string(provider, "Xray.Encryption");
	const char *flow = vpn_provider_get_string(provider, "Xray.Flow");
	const char *loglevel = vpn_provider_get_string(provider, "Xray.LogLevel");
	GString *g;
	unsigned int port;

	if (!addr || !proto || !host || !ports) {
		connman_error("xray: missing required property");
		return NULL;
	}

	port = (unsigned int)g_ascii_strtoull(ports, NULL, 10);

	g = g_string_new(NULL);
	g_string_append(g, "{\n");

	g_string_append(g, "  \"log\": {");
	append_kv_string(g, "\"loglevel\"", loglevel ? loglevel : "warning");
	g_string_append(g, "},\n");

	/* ---- tun inbound ---- */
	g_string_append(g, "  \"inbounds\": [\n    {\n");
	g_string_append(g, "      \"tag\": \"tun-in\",\n");
	g_string_append(g, "      \"protocol\": \"tun\",\n");
	g_string_append(g, "      \"settings\": {\n");
	append_kv_string(g, "        \"name\"",
			tunname ? tunname : XRAY_IFNAME_DEFAULT);
	g_string_append_c(g, ',');
	g_string_append_c(g, '\n');
	g_string_append(g, "        \"gateway\": [");
	append_json_string_item(g, addr, true);
	g_string_append(g, "],\n");
	append_kv_uint(g, "        \"mtu\"", 1500);
	if (dns) {
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		g_string_append(g, "        \"dns\": [");
		char **items = g_strsplit_set(dns, ", ", -1);
		bool first = true;
		for (unsigned int i = 0; items[i]; i++) {
			if (!*items[i])
				continue;
			append_json_string_item(g, items[i], first);
			first = false;
		}
		g_strfreev(items);
		g_string_append(g, "]\n");
	} else {
		g_string_append_c(g, '\n');
	}
	g_string_append(g, "      }\n");
	g_string_append(g, "    }\n  ],\n");

	/* ---- outbound ---- */
	g_string_append(g, "  \"outbounds\": [\n    {\n");
	g_string_append(g, "      \"tag\": \"proxy\",\n");

	if (g_str_equal(proto, "vless")) {
		g_string_append(g, "      \"protocol\": \"vless\",\n");
		g_string_append(g, "      \"settings\": {\n");
		g_string_append(g, "        \"vnext\": [\n          {\n");
		append_kv_string(g, "            \"address\"", host);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_uint(g, "            \"port\"", port);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		g_string_append(g, "            \"users\": [\n              {\n");
		append_kv_string(g, "                \"id\"", uuid ? uuid : "");
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_string(g, "                \"encryption\"",
					enc ? enc : "none");
		if (flow && *flow) {
			g_string_append_c(g, ',');
			g_string_append_c(g, '\n');
			append_kv_string(g, "                \"flow\"", flow);
		}
		g_string_append(g, "\n              }\n");
		g_string_append(g, "            ]\n          }\n        ]\n      }\n");
	} else if (g_str_equal(proto, "vmess")) {
		g_string_append(g, "      \"protocol\": \"vmess\",\n");
		g_string_append(g, "      \"settings\": {\n");
		g_string_append(g, "        \"vnext\": [\n          {\n");
		append_kv_string(g, "            \"address\"", host);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_uint(g, "            \"port\"", port);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		g_string_append(g, "            \"users\": [\n              {\n");
		append_kv_string(g, "                \"id\"", uuid ? uuid : "");
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_uint(g, "                \"alterId\"", 0);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_string(g, "                \"security\"",
					enc ? enc : "auto");
		g_string_append(g, "\n              }\n");
		g_string_append(g, "            ]\n          }\n        ]\n      }\n");
	} else if (g_str_equal(proto, "trojan")) {
		g_string_append(g, "      \"protocol\": \"trojan\",\n");
		g_string_append(g, "      \"settings\": {\n");
		g_string_append(g, "        \"servers\": [\n          {\n");
		append_kv_string(g, "            \"address\"", host);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_uint(g, "            \"port\"", port);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_string(g, "            \"password\"",
					password ? password : "");
		g_string_append(g, "\n          }\n        ]\n      }\n");
	} else if (g_str_equal(proto, "shadowsocks")) {
		g_string_append(g, "      \"protocol\": \"shadowsocks\",\n");
		g_string_append(g, "      \"settings\": {\n");
		g_string_append(g, "        \"servers\": [\n          {\n");
		append_kv_string(g, "            \"address\"", host);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_uint(g, "            \"port\"", port);
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_string(g, "            \"method\"",
					enc ? enc : "aes-256-gcm");
		g_string_append_c(g, ',');
		g_string_append_c(g, '\n');
		append_kv_string(g, "            \"password\"",
					password ? password : "");
		g_string_append(g, "\n          }\n        ]\n      }\n");
	} else {
		connman_error("xray: unsupported outbound protocol %s", proto);
		g_string_free(g, TRUE);
		return NULL;
	}

	append_stream_settings(g, provider);

	g_string_append(g, "    }\n  ],\n");

	/* ---- routing ---- */
	g_string_append(g, "  \"routing\": {\n");
	g_string_append(g, "    \"rules\": [\n");
	g_string_append(g, "      { \"type\": \"field\", \"inboundTag\": [\"tun-in\"], \"outboundTag\": \"proxy\" }\n");
	g_string_append(g, "    ]\n");
	g_string_append(g, "  }\n");

	g_string_append(g, "}\n");

	return g_string_free(g, FALSE);
}

/* ---- config file I/O -------------------------------------------------- */

static int write_config_file(struct xray_info *info, const char *json)
{
	const char *ident;
	char *path;
	int fd;

	ident = vpn_provider_get_ident(info->provider);
	if (!ident)
		ident = "default";

	path = g_strconcat(VPN_STATEDIR, "/connman-xray-", ident, ".json", NULL);

	fd = open(path, O_RDWR | O_NOFOLLOW | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR);
	if (fd < 0) {
		connman_error("xray: cannot create config %s: %s", path,
				strerror(errno));
		g_free(path);
		return -EIO;
	}

	if (write(fd, json, strlen(json)) < 0) {
		connman_error("xray: cannot write config: %s", strerror(errno));
		close(fd);
		g_free(path);
		return -EIO;
	}

	close(fd);
	info->config_path = path;
	return 0;
}

static void unlink_config(struct xray_info *info)
{
	if (info->config_path) {
		unlink(info->config_path);
		g_free(info->config_path);
		info->config_path = NULL;
	}
}

/* ---- process spawn / lifecycle ---------------------------------------- */

static gboolean xray_died(gpointer user_data);

static gchar **build_envp(struct vpn_provider *provider)
{
	const char *asset = vpn_provider_get_string(provider, "Xray.AssetDir");
	gchar **envp;

	envp = g_get_environ();
	if (asset && *asset)
		envp = g_environ_setenv(envp, "XRAY_LOCATION_ASSET", asset, TRUE);

	return envp;
}

static void xray_child_died(GPid pid, gint status, gpointer user_data)
{
	struct xray_info *info = user_data;
	struct xray_exit_data *data;
	int exit_code = 0;

	DBG("xray pid %d status %d", (int)pid, status);

	info->pid = 0;
	info->child_watch_id = 0;
	g_spawn_close_pid(pid);

	/* Clean disconnect path, or already dying - let it own vpn_died(). */
	if (info->dying || info->dying_id)
		return;

	if (info->route_setup_id) {
		g_source_remove(info->route_setup_id);
		info->route_setup_id = 0;
	}

	if (WIFEXITED(status))
		exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		exit_code = -WTERMSIG(status);

	/*
	 * Defer vpn_died() so that the bridge's update_provider_state()
	 * (scheduled ~1ms after xray_connect returned 0) has a chance to run
	 * first. Otherwise vpn_died() would free the bridge's private
	 * vpn_data and update_provider_state() would crash dereferencing it.
	 * The same deferred-died path is used by the clean disconnect below.
	 */
	info->dying = true;
	data = g_malloc0(sizeof(struct xray_exit_data));
	data->provider = info->provider;
	data->err = exit_code;
	info->dying_id = g_timeout_add(XRAY_DIED_DELAY_MS, xray_died, data);
}

static int spawn_xray(struct xray_info *info, struct vpn_provider *provider)
{
	gchar **argv;
	gchar **envp;
	GPid pid;
	GError *err = NULL;

	argv = g_new0(gchar *, 5);
	argv[0] = g_strdup(XRAY);
	argv[1] = g_strdup("run");
	argv[2] = g_strdup("-c");
	argv[3] = g_strdup(info->config_path);
	argv[4] = NULL;

	envp = build_envp(provider);

	g_spawn_async(NULL, argv, envp,
			G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
			NULL, NULL, &pid, &err);

	g_strfreev(argv);
	g_strfreev(envp);

	if (err) {
		connman_error("xray: failed to spawn %s: %s", XRAY,
				err->message);
		g_error_free(err);
		return -EIO;
	}

	info->pid = pid;
	DBG("xray started pid %d config %s", (int)pid, info->config_path);
	return 0;
}

static void kill_xray(struct xray_info *info)
{
	if (info->pid <= 0)
		return;

	kill(info->pid, SIGTERM);
	usleep(XRAY_SIGTERM_GRACE_MS * 1000);
	kill(info->pid, SIGKILL);

	/* Reap synchronously; we own the child (G_SPAWN_DO_NOT_REAP_CHILD). */
	waitpid(info->pid, NULL, 0);
	g_spawn_close_pid(info->pid);
	info->pid = 0;
}

/*
 * Wait (blocking) for the tun interface xray creates to appear and come up.
 * Returns the interface index, or a negative errno on failure.
 */
static int wait_for_tun_up(struct xray_info *info)
{
	int i;
	int index;
	GPid pid = info->pid;

	for (i = 0; i < XRAY_STARTUP_TIMEOUT_MS / (XRAY_POLL_INTERVAL_US / 1000);
			i++) {
		pid_t r;
		int status;

		/* Detect an early xray death (reap if already a zombie). */
		r = waitpid(pid, &status, WNOHANG);
		if (r == (pid_t)pid) {
			int code = WIFEXITED(status) ? WEXITSTATUS(status) :
					(WIFSIGNALED(status) ?
						-WTERMSIG(status) : 0);
			connman_error("xray: exited during startup code %d",
					code);
			info->pid = 0;
			g_spawn_close_pid(pid);
			return -ECHILD;
		}

		index = connman_inet_ifindex(info->ifname);
		if (index >= 0 && connman_inet_is_ifup(index))
			return index;

		usleep(XRAY_POLL_INTERVAL_US);
	}

	return -ETIMEDOUT;
}

/* ---- routes ------------------------------------------------------------ */

static gboolean xray_route_setup_cb(gpointer user_data)
{
	struct xray_info *info = user_data;
	const char *routes;
	char **items;
	unsigned long idx = 0;

	info->route_setup_id = 0;

	routes = vpn_provider_get_string(info->provider, "Xray.Routes");
	if (!routes || !*routes)
		return G_SOURCE_REMOVE;

	items = g_strsplit_set(routes, ", ", -1);
	for (unsigned int i = 0; items[i]; i++) {
		char ip[INET6_ADDRSTRLEN];
		char nm[INET6_ADDRSTRLEN];
		int family;

		if (!*items[i])
			continue;

		if (split_cidr(items[i], ip, sizeof(ip), nm, sizeof(nm),
					&family) < 0) {
			DBG("xray: ignore invalid route %s", items[i]);
			continue;
		}

		vpn_provider_append_route_complete(info->provider, idx,
					family, ip, nm, info->gateway);
		idx++;
	}
	g_strfreev(items);

	return G_SOURCE_REMOVE;
}

static void run_route_setup(struct xray_info *info)
{
	if (info->route_setup_id)
		g_source_remove(info->route_setup_id);

	info->route_setup_id = g_timeout_add(XRAY_ROUTE_SETUP_TIMEOUT,
						xray_route_setup_cb, info);
}

/* ---- connect / disconnect --------------------------------------------- */

static int xray_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	struct xray_info *info;
	const char *addr;
	const char *tunname;
	const char *routes;
	const char *host;
	gchar *json;
	char ip[INET6_ADDRSTRLEN];
	char netmask[INET6_ADDRSTRLEN];
	char gwbuf[INET6_ADDRSTRLEN];
	int family;
	int index;
	int err;

	DBG("");

	info = create_private_data(provider);
	vpn_provider_set_plugin_data(provider, info);

	addr = vpn_provider_get_string(provider, "Xray.Address");
	tunname = vpn_provider_get_string(provider, "Xray.TunName");
	host = vpn_provider_get_string(provider, "Host");

	if (!addr || !host) {
		DBG("xray: Xray.Address or Host missing");
		err = -EINVAL;
		goto error_notify;
	}

	info->ifname = g_strdup(tunname ? tunname : XRAY_IFNAME_DEFAULT);

	if (split_cidr(addr, ip, sizeof(ip), netmask, sizeof(netmask),
				&family) < 0) {
		DBG("xray: invalid Xray.Address %s", addr);
		err = -EINVAL;
		goto error_notify;
	}
	info->ipv4 = (family == AF_INET);
	info->ipv6 = (family == AF_INET6);

	/* Resolve the server host to use as the connman route gateway. */
	err = resolve_host(host, gwbuf, sizeof(gwbuf));
	if (err < 0) {
		DBG("xray: cannot resolve host %s", host);
		/* Fall back to the literal host (may be an IP already). */
		g_strlcpy(gwbuf, host, sizeof(gwbuf));
	}
	info->gateway = g_strdup(gwbuf);

	/* Decide split vs. default routing. Empty routes => full tunnel. */
	routes = vpn_provider_get_string(provider, "Xray.Routes");
	vpn_provider_set_boolean(provider, "SplitRouting",
					routes && *routes, false);

	json = build_config_json(info, provider);
	if (!json) {
		err = -EINVAL;
		goto error_notify;
	}

	err = write_config_file(info, json);
	g_free(json);
	if (err < 0)
		goto error_notify;

	err = spawn_xray(info, provider);
	if (err < 0)
		goto error_unlink;

	/*
	 * Block until xray creates and brings up the tun interface. This
	 * mirrors the WireGuard plugin, which synchronously creates its
	 * interface before returning; here the interface is created by the
	 * xray child process instead. A bounded poll keeps the blocking time
	 * within XRAY_STARTUP_TIMEOUT_MS.
	 */
	index = wait_for_tun_up(info);
	if (index < 0) {
		connman_error("xray: interface %s did not come up (%d)",
				info->ifname, index);
		kill_xray(info);
		err = index;
		goto error_unlink;
	}

	/*
	 * From here on, hand future (unexpected) xray exits to the GLib child
	 * watch. The setup below is synchronous (no main loop iteration), so
	 * an xray exit in this window is still caught: g_child_watch_add()
	 * detects an already-exited child. The blocking poll above reaped
	 * manually, so there is no double-reap risk before this point.
	 */

	if (vpn_set_ifname(provider, info->ifname) < 0) {
		DBG("xray: cannot set ifname %s", info->ifname);
		kill_xray(info);
		err = -EIO;
		goto error_unlink;
	}

	/* Hand the IP address to connman. */
	{
		struct connman_ipaddress *ipaddress;

		ipaddress = connman_ipaddress_alloc(family);
		if (!ipaddress) {
			kill_xray(info);
			err = -ENOMEM;
			goto error_unlink;
		}

		if (family == AF_INET)
			connman_ipaddress_set_ipv4(ipaddress, ip, netmask,
							info->gateway);
		else
			connman_ipaddress_set_ipv6(ipaddress, ip,
					(unsigned char)atoi(netmask),
					info->gateway);

		connman_ipaddress_set_p2p(ipaddress, true);
		vpn_provider_set_ipaddress(provider, ipaddress);
		connman_ipaddress_free(ipaddress);
	}

	vpn_provider_set_supported_ip_networks(provider, info->ipv4,
						info->ipv6);

	info->child_watch_id = g_child_watch_add(info->pid, xray_child_died,
							info);

	/*
	 * Returning 0 (like WireGuard) makes the bridge schedule
	 * update_provider_state(), which installs the rtnl newlink watch.
	 * vpn_rtnl_add_newlink_watch() immediately invokes vpn_newlink()
	 * with the current flags; since the interface is already up,
	 * data->state becomes VPN_STATE_READY.
	 */
	if (cb)
		cb(provider, user_data, 0);

	/* Install routes shortly after, once the bridge has caught up. */
	run_route_setup(info);

	return 0;

error_unlink:
	unlink_config(info);

error_notify:
	if (err == -EHOSTUNREACH)
		vpn_provider_add_error(provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
	else
		vpn_provider_add_error(provider,
					VPN_PROVIDER_ERROR_LOGIN_FAILED);

	if (cb)
		cb(provider, user_data, err ? err : -EINVAL);

	free_private_data(info);
	return err ? err : -EINVAL;
}

static gboolean xray_died(gpointer user_data)
{
	struct xray_exit_data *data = user_data;
	struct xray_info *info;

	DBG("");

	info = vpn_provider_get_plugin_data(data->provider);
	if (info)
		info->dying_id = 0;

	/* No task for a no-daemon VPN - invoke vpn_died() with NULL task. */
	vpn_died(NULL, data->err, data->provider);

	if (info)
		free_private_data(info);

	g_free(data);
	return G_SOURCE_REMOVE;
}

static int disconnect(struct vpn_provider *provider, int err)
{
	struct xray_info *info;
	struct xray_exit_data *data;

	DBG("");

	info = vpn_provider_get_plugin_data(provider);
	if (!info)
		return -ENODATA;

	if (info->dying_id)
		return -EALREADY;

	info->dying = true;

	if (info->route_setup_id) {
		g_source_remove(info->route_setup_id);
		info->route_setup_id = 0;
	}

	/* Detach the child watch so the disconnect path owns vpn_died(). */
	if (info->child_watch_id) {
		g_source_remove(info->child_watch_id);
		info->child_watch_id = 0;
	}

	vpn_provider_set_state(provider, VPN_PROVIDER_STATE_DISCONNECT);

	kill_xray(info);
	unlink_config(info);

	/* Simulate a task-running VPN to issue vpn_died after exiting. */
	data = g_malloc0(sizeof(struct xray_exit_data));
	data->provider = provider;
	data->err = err;

	info->dying_id = g_timeout_add(XRAY_DIED_DELAY_MS, xray_died, data);

	return 0;
}

static void xray_disconnect(struct vpn_provider *provider)
{
	disconnect(provider, 0);
}

static int xray_error_code(struct vpn_provider *provider, int exit_code)
{
	DBG("exit_code %d", exit_code);
	return exit_code;
}

static int xray_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(xray_options); i++) {
		if (!xray_options[i].save)
			continue;

		option = vpn_provider_get_string(provider, xray_options[i].opt);
		if (!option)
			continue;

		g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					xray_options[i].opt, option);
	}

	return 0;
}

static bool xray_uses_vpn_agent(struct vpn_provider *provider)
{
	return false;
}

static struct vpn_driver vpn_driver = {
	.flags		= VPN_FLAG_NO_TUN | VPN_FLAG_NO_DAEMON,
	.connect	= xray_connect,
	.disconnect	= xray_disconnect,
	.save		= xray_save,
	.error_code	= xray_error_code,
	.uses_vpn_agent	= xray_uses_vpn_agent,
};

static int xray_init(void)
{
	return vpn_register("xray", &vpn_driver, XRAY);
}

static void xray_exit(void)
{
	vpn_unregister("xray");
}

CONNMAN_PLUGIN_DEFINE(xray, "Xray VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, xray_init, xray_exit)
