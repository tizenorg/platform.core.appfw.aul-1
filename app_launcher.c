/*
 *  app_launcher
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Contact: Baptiste DURAND <baptiste.durand@open.eurogiciel.org>
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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <glib.h>
#include <ail.h>
#include "aul.h"


static char **gargv;
static int gargc;
bundle *kb = NULL;

static GMainLoop *mainloop = NULL;


struct launch_arg {
    char applicationId[256];
    int flag_debug;
} launch_arg;

static bundle *create_internal_bundle()
{
    bundle *kb;
    int i;
    char arg[1024] = {0, };
    char* val_array[128];

    kb = bundle_create();
    bundle_add(kb, AUL_K_DEBUG, "1");
    return kb;
}

int launch(char* appid,int debug_option)
{
    int pid = -1;


    if(!debug_option)
        pid = aul_open_app(appid);
    else {
        kb = create_internal_bundle();
        if (NULL == kb) {
            printf("bundle creation fail\n");
            return -1;
        }
        pid = aul_launch_app(appid, kb);
    }
    return pid;
}



static int __launch_app_dead_handler(int pid, void *data)
{
    int listen_pid = (int) data;

    if(listen_pid == pid)
        g_main_loop_quit(mainloop);

    return 0;
}

static gboolean run_func(void *data)
{
    int pid = -1;
    char *str = NULL;
    struct launch_arg* launch_arg_data = NULL;
    launch_arg_data = (struct launch_arg*)data;
    if ((pid = launch((char*)launch_arg_data->applicationId,launch_arg_data->flag_debug)) > 0) {
        printf("... successfully launched\n");
    } else {
        printf("... launch failed\n");
    }
    g_main_loop_quit(mainloop);
    if (kb) {
        bundle_free(kb);
        kb = NULL;
    }

    return TRUE;
}


void print_usage(char *program)
{
    printf("Usage : %s [ ... ]\n", program);
    printf(
        "   -h                        --help              Display this usage information.\n"
        "   -l                        --list              Display installed apps list\n"
        "   -S                        --status            Display running apps list\n"
        "   -s [tizen application ID] --start             Launch widget with tizen application ID\n"
        "   -k [tizen application ID] --kill              Kill widget with tizen application ID\n"
        "   -r [tizen application ID] --is-running        Check whether application is running by tizen application ID,\n"
        "                                                 If widget is running, 0(zero) will be returned.\n"
        "   -d                        --debug             Activate debug mode\n"
        );
}


ail_cb_ret_e appinfo_list_appid_namefunc(const ail_appinfo_h appinfo,  void *user_data)
{
    char* package_str_name = NULL;
    char* package_str_appid = NULL;
    char* package_str_x_package_type = NULL;
    ail_appinfo_get_str(appinfo, AIL_PROP_X_SLP_APPID_STR, &package_str_appid);
    ail_appinfo_get_str(appinfo, AIL_PROP_NAME_STR, &package_str_name);
    ail_appinfo_get_str(appinfo, AIL_PROP_X_SLP_PACKAGETYPE_STR, &package_str_x_package_type);

    printf("\t'%s'\t '%s'\t %s\n",package_str_name, package_str_appid, package_str_x_package_type);
    return AIL_CB_RET_CONTINUE;
}


int listApp()
{
    int ret = 0;
    printf("\tApplication List for user %lu\n", (long)getuid());
    printf("\tUser's Application \n");
    printf("\t Name \t AppID  \t Type \n");
    printf("\t=================================================\n");
    if ( ail_filter_list_usr_appinfo_foreach(NULL, appinfo_list_appid_namefunc, NULL, getuid() ) != AIL_ERROR_OK )
        ret = -1;
    printf("\t=================================================\n");
    return ret;
}



int iterfunc_status(const aul_app_info *info, void *data)
{
    printf("\t  %s (%d)\n",info->appid, info->pid);
    return 0;
}



int iterfunc_kill(const aul_app_info *info, void *data)
{
    if(!data)
        return 0;
    if(strcmp(info->appid,data) == 0) {
        aul_kill_pid(info->pid);
    printf("\tKill appId: %s (%d)\n", info->appid,info->pid);
    }
    return 0;
}

int IsAppInstalled(char *appid)
{
    ail_filter_h f;
    int res = 0;
    if(!appid)
        return 0;
    if (ail_filter_new(&f) != AIL_ERROR_OK)
        return -1;
    if (ail_filter_add_str(f, AIL_PROP_X_SLP_APPID_STR, appid) != AIL_ERROR_OK) {
        ail_filter_destroy(f);
        return -1;
    }
    if (ail_filter_count_usr_appinfo(f, &res, getuid()) != AIL_ERROR_OK) {
        ail_filter_destroy(f);
        return -1;
    }
    return res;
}

int main(int argc, char **argv)
{
    bool isDebugMode = false;
    bool dispHelp = false;
    bool dispList = false;
    bool dispRunList = false;
    int next_opt, opt_idx = 0;
    char op = '\0';
    int ret = 0;
    struct launch_arg  args;
    static struct option long_options[] = {
            { "help", no_argument, 0, 'h' },
            { "list", no_argument, 0, 'l' },
            { "status", no_argument, 0, 'S' },
            { "start", required_argument, 0, 's' },
            { "kill", required_argument, 0, 'k' },
            { "is-running", required_argument, 0, 'r' },
            { "debug", no_argument, 0, 'd' },
            { 0, 0, 0, 0 }
    };

    do {
            next_opt = getopt_long(argc,
                                   argv,
                                   "hlSs:k:r:d",
                                   long_options,
                                   &opt_idx);

            switch (next_opt) {
            case 'h':
                if (!dispHelp) {
                    print_usage(argv[0]);
                    dispHelp = true;
                }
                break;

            case 'l':
                if (dispList) {
                    break;
                }
                if (listApp()) {
                    printf("Fail to display the list of installed applications");
                    return -1;
                }
                dispList = true;
                break;

            case 'S':
                if (dispRunList) {
                    break;
                }
                printf("\t appId (PID)\n");
                if (aul_app_get_running_app_info(iterfunc_status, NULL)) {
                    printf("Fail to display the list of Running applications");
                    return -1;
                }
                dispRunList = true;
                break;

            case 's':
            case 'k':
            case 'r':
                if(strlen(optarg) > 255) {
                    print_usage(argv[0]);
                    return -1;
                } else
                    strcpy(args.applicationId, optarg);
                op = next_opt;
                break;

            case 'd':
                args.flag_debug = 1;
                break;

            case -1:
                break;

            default:
               print_usage(argv[0]);
               break;
            }
        } while (next_opt != -1);

        if (argc == 1)
            print_usage(argv[0]);

        if (optind < argc) {
            printf("Wrong option: ");
            while (optind < argc)
               printf("%s ", argv[optind++]);
            printf("\n");
            print_usage(argv[0]);
        }
        if ((op == 's') || (op == 'k') || (op == 'r')) {
          if (IsAppInstalled(args.applicationId) <= 0) {
                printf("The app with ID: %s is not avaible for the user %d \n", args.applicationId, getuid());
                return -1;
          }
        }

        if (op == 's') {
            if (strlen(args.applicationId) <= 0) {
                printf("result: %s\n", "failed");
                return -1;
            }
            aul_launch_init(NULL, NULL);
            g_idle_add(run_func, args.applicationId);
            mainloop = g_main_loop_new(NULL, FALSE);
            if (!mainloop) {
                printf("failed to create glib main loop\n");
                exit(EXIT_FAILURE);
            }
            g_main_loop_run(mainloop);
            return 0;
        } else if (op == 'k') {
            bool isRunning = false;
            isRunning = aul_app_is_running(args.applicationId);
            if (true == isRunning) {
                aul_app_get_running_app_info(iterfunc_kill, args.applicationId);
            } else {
                printf("result: %s\n", "App isn't running");
                return 0;
            }
        } else if (op == 'r') {
            bool isRunning = aul_app_is_running(args.applicationId);
            if (true == isRunning) {
                printf("result: %s\n", "running");
                return 0;
            } else {
                printf("result: %s\n", "not running");
                return -1;
            }
        }
    return 0;
}

