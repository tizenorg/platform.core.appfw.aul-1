#ifndef __AUL_AMD_APP_GROUP_H_
#define __AUL_AMD_APP_GROUP_H_

#include <glib.h>
#include <bundle.h>

void app_group_add(int leader_pid, int pid, int wid);
void app_group_remove(int pid);
int app_group_get_window(int pid);
void app_group_get_leader_pids(int *cnt, int **pids);
void app_group_get_group_pids(int leader_pid, int *cnt, int **pids);
gboolean app_group_is_leader_pid(int pid);
void app_group_resume(int pid);
gboolean app_group_is_group_app(bundle* kb);
gboolean app_group_is_sub_app(int pid);
void app_group_reroute(int pid);
int app_group_get_caller_pid();
void app_group_clear_top(int pid);
int app_group_get_leader_pid(int pid);
void app_group_set_dead_pid(int pid);
int app_group_get_status(int pid);
int app_group_set_status(int pid, int status);
#endif

