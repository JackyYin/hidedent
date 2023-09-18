#ifndef _HIDEDENT_H
#define _HIDEDENT_H

static int patch_prog_idx = 1;
static int exit_prog_idx = 2;

#define MAX_PID_STR_LEN (16)

struct pid_str {
	int pid_string_len;
	char pid_string[MAX_PID_STR_LEN];
};

#endif

