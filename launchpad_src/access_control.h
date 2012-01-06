/*
 *  aul
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>, Jaeho Lee <jaeho81.lee@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#ifdef DAC_ACTIVATE

#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <privilege-control.h>

#define INHOUSE_UID     5000
#define LABEL_LEN		23

static inline void __dac_init()
{
}

static inline int __set_dac(const char *pkg_name)
{
	return set_privilege(pkg_name);
}

static inline int __set_smack(char* path)
{
/*
 * This is additional option.
 * Though such a application fails in this function, that error is ignored.
 */
	char label[LABEL_LEN + 1] = {0, };
	int fd = 0;
	int result = -1;

	result = getxattr(path, "security.SMACK64EXEC", label, LABEL_LEN);
	if(result < 0)	// fail to get extended attribute
		return 0;	// ignore error

	fd = open("/proc/self/attr/current", O_RDWR);
	if(fd < 0)		// fail to open file
		return 0;	// ignore error

	result = write(fd, label, strlen(label));
	if(result < 0) {	// fail to write label
		close(fd);
		return 0;	// ignore error
	}

	close(fd);
	return 0;
}

#else
static inline void __dac_init()
{
}

static inline int __set_dac(const char *pkg_name)
{
	return 0;
}

static inline int __set_smack(char* path)
{
	return 0;
}
#endif


