#define _GNU_SOURCE
#include <stdlib.h>
#include <aul.h>
#include "aul_util.h"
#include "aul_sock.h"
#include "aul_cmd.h"

API int aul_app_data_new(const char *key)
{
	int ret;

	if (key == NULL)
		return AUL_R_EINVAL;

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_DATA_NEW,
		(unsigned char *)key, strlen(key), AUL_SOCK_NONE);

	return ret;
}

API int aul_app_data_get_raw(const char *key, bundle **b)
{
	int ret;
	int fd;
	app_pkt_t *pkt = NULL;

	if (key == NULL)
		return AUL_R_EINVAL;

	fd = aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_DATA_GET_RAW,
		(unsigned char *)key, strlen(key), AUL_SOCK_ASYNC);

	*b = NULL;
	if (fd > 0) {
		ret = aul_sock_recv_reply_pkt(fd, &pkt);
		if (ret < 0 || pkt == NULL) {
			_E("failed to recv data raw of %s", key);
		} else {
			ret = pkt->cmd;
			if (pkt->len)
				*b = bundle_decode(pkt->data, pkt->len);
		}
	} else {
		ret = fd;
	}

	if (pkt)
		free(pkt);

	return ret;
}

API int aul_app_data_put(const char *key, const char *data_key, const char *data_val)
{
	int ret;
	bundle *kb;

	if (key == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APP_DATA_KEY, key);
	bundle_add_str(kb, data_key, data_val);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), APP_DATA_PUT,
		kb, AUL_SOCK_NONE);

	bundle_free(kb);
	return ret;
}

API int aul_app_data_get(const char *key, const char *data_key, char **data_val)
{
	int ret;
	int fd;
	bundle *kb;
	app_pkt_t *pkt = NULL;

	if (key == NULL || data_key == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APP_DATA_KEY, key);
	bundle_add_str(kb, data_key, "");

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), APP_DATA_GET,
		kb, AUL_SOCK_ASYNC);

	if (fd > 0) {
		ret =  aul_sock_recv_reply_pkt(fd, &pkt);
		if (ret < 0 || pkt == NULL) {
			_E("failed to get data of %s %s", key, data_key);
		} else {
			if (pkt->cmd == 0 && pkt->len)
				*data_val = strndup((char *)pkt->data, pkt->len);

			ret = pkt->cmd;
		}
	} else {
		ret = fd;
		*data_val = NULL;
	}

	if (pkt)
		free(pkt);

	bundle_free(kb);

	return ret;
}

API int aul_app_data_get_owner(const char *key, const char *data_key,
	int *owner_pid)
{
	int ret;
	int fd;
	app_pkt_t *pkt = NULL;
	bundle *kb;

	if (key == NULL || data_key == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APP_DATA_KEY, key);
	bundle_add_str(kb, data_key, "0");

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), APP_DATA_GET_OWNER,
		kb, AUL_SOCK_ASYNC);

	if (fd > 0) {
		ret = aul_sock_recv_reply_pkt(fd, &pkt);
		if (ret < 0 || pkt == NULL) {
			_E("failed to get owner of %s %s", key, data_key);
		} else {
			if (pkt->cmd == 0 && pkt->len == sizeof(int))
				owner_pid = memcpy(owner_pid, pkt->data, pkt->len);

			ret = pkt->cmd;
		}
	} else {
		ret = fd;
	}

	if (pkt)
		free(pkt);

	bundle_free(kb);

	return ret;
}

API int aul_app_data_del(const char *key, const char *data_key)
{
	int ret;
	bundle *kb;

	if (key == NULL || data_key == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APP_DATA_KEY, key);
	bundle_add_str(kb, data_key, "0");

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), APP_DATA_DEL,
		kb, AUL_SOCK_NONE);

	bundle_free(kb);

	return ret;
}
