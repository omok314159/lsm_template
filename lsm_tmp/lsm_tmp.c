/*
 *  Template for creating new LSM module.
 *
 *  I referenced SELinux and SMACK hook function for implementations.
 *  
 */ 

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>

#ifdef CONFIG_SECURITY_LSM_TMP
int lsm_tmp_enabled = CONFIG_SECURITY_LSM_TMP;


/* Hook functions begin here. */

static int lsm_tmp_binder_set_context_mgr(struct task_struct *mgr)
{
	return 0;
}

static int lsm_tmp_binder_transaction(struct task_struct *from,
                                      struct task_struct *to)
{
	return 0;
}

static int lsm_tmp_binder_transfer_binder(struct task_struct *from,
                                          struct task_struct *to)
{
	return 0;
}

static int lsm_tmp_binder_transfer_file(struct task_struct *from,
                                        struct task_struct *to,
                                        struct file *file)
{
	return 0;
}

static int lsm_tmp_ptrace_access_check(struct task_struct *child,
                                     unsigned int mode)
{
	return 0;
}

static int lsm_tmp_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int lsm_tmp_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int lsm_tmp_capset(struct cred *new, const struct cred *old,
                          const kernel_cap_t *effective,
                          const kernel_cap_t *inheritable,
                          const kernel_cap_t *permitted)
{
	return 0;
}

static int lsm_tmp_capable(const struct cred *cred, struct user_namespace *ns,
                           int cap, int audit)
{
	return 0;
}

static int lsm_tmp_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int lsm_tmp_quota_on(struct dentry *dentry)
{
	return 0;
}

static int lsm_tmp_syslog(int type)
{
	return 0;
}

static int lsm_tmp_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

static int lsm_tmp_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

static int lsm_tmp_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
}

/* Derived from fs/exec.c:flush_old_files. */
static inline void flush_unauthorized_files(const struct cred *cred,
                                            struct files_struct *files)
{
	return ;
}

static void lsm_tmp_bprm_committing_creds(struct linux_binprm *bprm)
{
	return ;
}

static void lsm_tmp_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int lsm_tmp_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void lsm_tmp_sb_free_security(struct super_block *sb)
{
	return;
}
	
static int lsm_tmp_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int lsm_tmp_sb_remount(struct super_block *sb, void *data)
{
	return 0;
}

static int lsm_tmp_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static int lsm_tmp_sb_statfs(struct dentry *dentry)
{
  	return 0;
}

static int lsm_tmp_mount(const char *dev_name,
                         struct path *path,
                         const char *type,
                         unsigned long flags,
                         void *data)
{
	return 0;
}

static int lsm_tmp_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static int lsm_tmp_inode_alloc_security(struct inode *inode)
{
        return 0;
}

static void lsm_tmp_inode_free_security(struct inode *inode)
{
}

static int lsm_tmp_dentry_init_security(struct dentry *dentry, int mode,
                                        struct qstr *name, void **ctx,
                                        u32 *ctxlen)
{
	printk("lsm_tmp: lsm_tmp_dentry_init_security called\n");
	return 0;
}

static int lsm_tmp_inode_init_security(struct inode *inode, struct inode *dir,
                                       const struct qstr *qstr,
                                       const char **name,
                                       void **value, size_t *len)
{
	return -EOPNOTSUPP;
}

static int lsm_tmp_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
        return 0;
}

static int lsm_tmp_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
        return 0;
}

static int lsm_tmp_inode_unlink(struct inode *dir, struct dentry *dentry)
{
        return 0;
}

static int lsm_tmp_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
        return 0;
}

static int lsm_tmp_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
        return 0;
}

static int lsm_tmp_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
        return 0;
}

static int lsm_tmp_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
        return 0;
}

static int lsm_tmp_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                                struct inode *new_inode, struct dentry *new_dentry)
{
	return 0;
}

static int lsm_tmp_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int lsm_tmp_inode_follow_link(struct dentry *dentry, struct inode *inode,
                                     bool rcu)
{
	return 0;
}

static int lsm_tmp_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static int lsm_tmp_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int lsm_tmp_inode_getattr(const struct path *path)
{
	return 0;
}

static int lsm_tmp_inode_setxattr(struct dentry *dentry, const char *name,
                                  const void *value, size_t size, int flags)
{
	return 0;
}

static void lsm_tmp_inode_post_setxattr(struct dentry *dentry, const char *name,
                                        const void *value, size_t size,
                                        int flags)
{
	return ;
}


static int lsm_tmp_inode_getxattr(struct dentry *dentry, const char *name)
{
        return 0;
}

static int lsm_tmp_inode_listxattr(struct dentry *dentry)
{
        return 0;
}

static int lsm_tmp_inode_removexattr(struct dentry *dentry, const char *name)
{
        return 0;
}

static int lsm_tmp_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static int lsm_tmp_inode_setsecurity(struct inode *inode, const char *name,
                                     const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static int lsm_tmp_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

static void lsm_tmp_inode_getsecid(struct inode *inode, u32 *secid)
{
	*secid = 0;
}



static int lsm_tmp_file_permission(struct file *file, int mask)
{
	return 0;

}

static int lsm_tmp_file_alloc_security(struct file *file)
{
	return 0;
}

static void lsm_tmp_file_free_security(struct file *file)
{
	return ;
}

static int lsm_tmp_file_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
	return 0;
}

static int lsm_tmp_mmap_addr(unsigned long addr)
{
	return 0;
}

static int lsm_tmp_mmap_file(struct file *file, unsigned long reqprot,
                             unsigned long prot, unsigned long flags)
{
	return 0;
}

static int lsm_tmp_file_mprotect(struct vm_area_struct *vma,
                                 unsigned long reqprot,
                                 unsigned long prot)
{
	return 0;
}

static int lsm_tmp_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int lsm_tmp_file_fcntl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
	return 0;
}

static void lsm_tmp_file_set_fowner(struct file *file)
{
}

static int lsm_tmp_file_send_sigiotask(struct task_struct *tsk,
                                       struct fown_struct *fown, int signum)
{
	return 0;
}

static int lsm_tmp_file_receive(struct file *file)
{
	return 0;
}

static int lsm_tmp_file_open(struct file *file, const struct cred *cred)
{
	return 0;
}

static int lsm_tmp_task_create(unsigned long clone_flags)
{
        return 0;
}

static int lsm_tmp_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
        return 0;
}

static void lsm_tmp_cred_free(struct cred *cred)
{
}

static int lsm_tmp_cred_prepare(struct cred *new, const struct cred *old,
                                gfp_t gfp)
{
        return 0;
}

static void lsm_tmp_cred_transfer(struct cred *new, const struct cred *old)
{
}

static int lsm_tmp_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int lsm_tmp_kernel_create_files_as(struct cred *new, struct inode *inode)
{
        return 0;
}

static int lsm_tmp_kernel_module_request(char *kmod_name)
{
        return 0;
}

static int lsm_tmp_task_setpgid(struct task_struct *p, pid_t pgid)
{
        return 0;
}

static int lsm_tmp_task_getpgid(struct task_struct *p)
{
        return 0;
}

static int lsm_tmp_task_getsid(struct task_struct *p)
{
        return 0;
}

static void lsm_tmp_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int lsm_tmp_task_setnice(struct task_struct *p, int nice)
{
        return 0;
}

static int lsm_tmp_task_setioprio(struct task_struct *p, int ioprio)
{
        return 0;
}

static int lsm_tmp_task_getioprio(struct task_struct *p)
{
        return 0;
}

static int lsm_tmp_task_setrlimit(struct task_struct *p, unsigned int resource,
                struct rlimit *new_rlim)
{
        return 0;
}

static int lsm_tmp_task_setscheduler(struct task_struct *p)
{
        return 0;
}

static int lsm_tmp_task_getscheduler(struct task_struct *p)
{
        return 0;
}

static int lsm_tmp_task_movememory(struct task_struct *p)
{
        return 0;
}

static int lsm_tmp_task_kill(struct task_struct *p, struct siginfo *info,
                                int sig, u32 secid)
{
        return 0;
}

static int lsm_tmp_task_wait(struct task_struct *p)
{
        return 0;
}

static void lsm_tmp_task_to_inode(struct task_struct *p,
                                  struct inode *inode)
{
}

static int lsm_tmp_socket_create(int family, int type,
                                 int protocol, int kern)
{
	return 0;
}

static int lsm_tmp_socket_post_create(struct socket *sock, int family,
                                      int type, int protocol, int kern)
{
	return 0;
}

static int lsm_tmp_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return 0;
}

static int lsm_tmp_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return 0;
}

static int lsm_tmp_socket_listen(struct socket *sock, int backlog)
{
        return 0;
}

static int lsm_tmp_socket_accept(struct socket *sock, struct socket *newsock)
{
        return 0;
}

static int lsm_tmp_socket_sendmsg(struct socket *sock, struct msghdr *msg,
                                  int size)
{
	return 0;
}

static int lsm_tmp_socket_recvmsg(struct socket *sock, struct msghdr *msg,
                                  int size, int flags)
{
	return 0;
}

static int lsm_tmp_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int lsm_tmp_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int lsm_tmp_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int lsm_tmp_socket_getsockopt(struct socket *sock, int level,
                                     int optname)
{
	return 0;
}

static int lsm_tmp_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int lsm_tmp_socket_unix_stream_connect(struct sock *sock,
                                              struct sock *other,
                                              struct sock *newsk)
{
	return 0;
}

static int lsm_tmp_socket_unix_may_send(struct socket *sock,
                                        struct socket *other)
{
	return 0;
}

static int lsm_tmp_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int lsm_tmp_socket_getpeersec_stream(struct socket *sock, char __user *optval,
                                            int __user *optlen, unsigned len)
{
	return 0;
}

static int lsm_tmp_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int lsm_tmp_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void lsm_tmp_sk_free_security(struct sock *sk)
{
}

static void lsm_tmp_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void lsm_tmp_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void lsm_tmp_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int lsm_tmp_inet_conn_request(struct sock *sk, struct sk_buff *skb,
                                     struct request_sock *req)
{
	return 0;
}

static void lsm_tmp_inet_csk_clone(struct sock *newsk,
                                   const struct request_sock *req)
{
}

static void lsm_tmp_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

static int lsm_tmp_secmark_relabel_packet(u32 sid)
{
	return 0;
}

static void lsm_tmp_secmark_refcount_inc(void)
{
}

static void lsm_tmp_secmark_refcount_dec(void)
{
}

static void lsm_tmp_req_classify_flow(const struct request_sock *req,
                                      struct flowi *fl)
{
}

static int lsm_tmp_tun_dev_alloc_security(void **security)
{
        return 0;
}

static void lsm_tmp_tun_dev_free_security(void *security)
{
        kfree(security);
}

static int lsm_tmp_tun_dev_create(void)
{
	return 0;
}

static int lsm_tmp_tun_dev_attach_queue(void *security)
{
	return 0;
}

static int lsm_tmp_tun_dev_attach(struct sock *sk, void *security)
{
	return 0;
}

static int lsm_tmp_tun_dev_open(void *security)
{
	return 0;
}

static int lsm_tmp_netlink_send(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}

static int lsm_tmp_msg_msg_alloc_security(struct msg_msg *msg)
{
        return 0;
}

static void lsm_tmp_msg_msg_free_security(struct msg_msg *msg)
{
}

static int lsm_tmp_msg_queue_alloc_security(struct msg_queue *msq)
{
        return 0;
}

static void lsm_tmp_msg_queue_free_security(struct msg_queue *msq)
{
}

static int lsm_tmp_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
        return 0;
}

static int lsm_tmp_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
        return 0;
}

static int lsm_tmp_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
	return 0;
}

static int lsm_tmp_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
                                    struct task_struct *target,
                                    long type, int mode)
{
	return 0;
}

static int lsm_tmp_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void lsm_tmp_shm_free_security(struct shmid_kernel *shp)
{
}

static int lsm_tmp_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int lsm_tmp_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int lsm_tmp_shm_shmat(struct shmid_kernel *shp,
                             char __user *shmaddr, int shmflg)
{
	return 0;
}

static int lsm_tmp_sem_alloc_security(struct sem_array *sma)
{
	return 0;
}

static void lsm_tmp_sem_free_security(struct sem_array *sma)
{
}

static int lsm_tmp_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int lsm_tmp_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int lsm_tmp_sem_semop(struct sem_array *sma,
                             struct sembuf *sops, unsigned nsops, int alter)
{
        return 0;
}

static int lsm_tmp_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
        return 0;
}

static void lsm_tmp_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static void lsm_tmp_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	return;
}

static int lsm_tmp_getprocattr(struct task_struct *p,
                               char *name, char **value)
{
	return -EINVAL;
}

static int lsm_tmp_setprocattr(struct task_struct *p,
                               char *name, void *value, size_t size)
{
	return -EINVAL;
}


static int lsm_tmp_ismaclabel(const char *name)
{
	return 0;
}

static int lsm_tmp_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static int lsm_tmp_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return -EOPNOTSUPP;
}

static void lsm_tmp_release_secctx(char *secdata, u32 seclen)
{
}

static void lsm_tmp_inode_invalidate_secctx(struct inode *inode)
{
}

static int lsm_tmp_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

static int lsm_tmp_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

static int lsm_tmp_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}

#ifdef CONFIG_KEYS
static int lsm_tmp_key_alloc(struct key *k, const struct cred *cred,
                             unsigned long flags)
{
	return 0;
}

static void lsm_tmp_key_free(struct key *k)
{
}

static int lsm_tmp_key_permission(key_ref_t key_ref,
                                  const struct cred *cred,
                                  unsigned perm)
{
	return 0;
}

static int lsm_tmp_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

#endif /* CONFIG_KEYS */

static int lsm_tmp_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int lsm_tmp_set_mnt_opts(struct super_block *sb,
                                struct security_mnt_opts *opts,
                                unsigned long kern_flags,
                                unsigned long *set_kern_flags)
{
	return 0;
}


static int lsm_tmp_sb_clone_mnt_opts(const struct super_block *oldsb,
                                        struct super_block *newsb)
{
	return 0;
}

#ifdef CONFIG_AUDIT
static int lsm_tmp_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
	return 0;
}

static int lsm_tmp_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static int lsm_tmp_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

static void lsm_tmp_audit_rule_free(void *lsmrule)
{
}
#endif /* CONFIG_AUDIT */



static int lsm_tmp_parse_opts_str(char *options,
				  struct security_mnt_opts *opts)
{
	return 0;
} 




static struct security_hook_list lsm_tmp_hooks[] = {
        LSM_HOOK_INIT(binder_set_context_mgr, lsm_tmp_binder_set_context_mgr),
        LSM_HOOK_INIT(binder_transaction, lsm_tmp_binder_transaction),
        LSM_HOOK_INIT(binder_transfer_binder, lsm_tmp_binder_transfer_binder),
        LSM_HOOK_INIT(binder_transfer_file, lsm_tmp_binder_transfer_file),

        LSM_HOOK_INIT(ptrace_access_check, lsm_tmp_ptrace_access_check),
        LSM_HOOK_INIT(ptrace_traceme, lsm_tmp_ptrace_traceme),
        LSM_HOOK_INIT(capget, lsm_tmp_capget),
        LSM_HOOK_INIT(capset, lsm_tmp_capset),
        LSM_HOOK_INIT(capable, lsm_tmp_capable),
        LSM_HOOK_INIT(quotactl, lsm_tmp_quotactl),
        LSM_HOOK_INIT(quota_on, lsm_tmp_quota_on),
        LSM_HOOK_INIT(syslog, lsm_tmp_syslog),
        LSM_HOOK_INIT(vm_enough_memory, lsm_tmp_vm_enough_memory),

        LSM_HOOK_INIT(netlink_send, lsm_tmp_netlink_send),

        LSM_HOOK_INIT(bprm_set_creds, lsm_tmp_bprm_set_creds),
        LSM_HOOK_INIT(bprm_committing_creds, lsm_tmp_bprm_committing_creds),
        LSM_HOOK_INIT(bprm_committed_creds, lsm_tmp_bprm_committed_creds),
        LSM_HOOK_INIT(bprm_secureexec, lsm_tmp_bprm_secureexec),
        LSM_HOOK_INIT(sb_alloc_security, lsm_tmp_sb_alloc_security),
        LSM_HOOK_INIT(sb_free_security, lsm_tmp_sb_free_security),
        LSM_HOOK_INIT(sb_copy_data, lsm_tmp_sb_copy_data),
        LSM_HOOK_INIT(sb_remount, lsm_tmp_sb_remount),
        LSM_HOOK_INIT(sb_kern_mount, lsm_tmp_sb_kern_mount),
        LSM_HOOK_INIT(sb_show_options, lsm_tmp_sb_show_options),
        LSM_HOOK_INIT(sb_statfs, lsm_tmp_sb_statfs),
        LSM_HOOK_INIT(sb_mount, lsm_tmp_mount),
        LSM_HOOK_INIT(sb_umount, lsm_tmp_umount),
        LSM_HOOK_INIT(sb_set_mnt_opts, lsm_tmp_set_mnt_opts),
        LSM_HOOK_INIT(sb_clone_mnt_opts, lsm_tmp_sb_clone_mnt_opts),
        LSM_HOOK_INIT(sb_parse_opts_str, lsm_tmp_parse_opts_str),

        LSM_HOOK_INIT(dentry_init_security, lsm_tmp_dentry_init_security),

        LSM_HOOK_INIT(inode_alloc_security, lsm_tmp_inode_alloc_security),
        LSM_HOOK_INIT(inode_free_security, lsm_tmp_inode_free_security),
        LSM_HOOK_INIT(inode_init_security, lsm_tmp_inode_init_security),
        LSM_HOOK_INIT(inode_create, lsm_tmp_inode_create),
        LSM_HOOK_INIT(inode_link, lsm_tmp_inode_link),
        LSM_HOOK_INIT(inode_unlink, lsm_tmp_inode_unlink),
        LSM_HOOK_INIT(inode_symlink, lsm_tmp_inode_symlink),
        LSM_HOOK_INIT(inode_mkdir, lsm_tmp_inode_mkdir),
        LSM_HOOK_INIT(inode_rmdir, lsm_tmp_inode_rmdir),
        LSM_HOOK_INIT(inode_mknod, lsm_tmp_inode_mknod),
        LSM_HOOK_INIT(inode_rename, lsm_tmp_inode_rename),
        LSM_HOOK_INIT(inode_readlink, lsm_tmp_inode_readlink),
        LSM_HOOK_INIT(inode_follow_link, lsm_tmp_inode_follow_link),
        LSM_HOOK_INIT(inode_permission, lsm_tmp_inode_permission),
        LSM_HOOK_INIT(inode_setattr, lsm_tmp_inode_setattr),
        LSM_HOOK_INIT(inode_getattr, lsm_tmp_inode_getattr),
        LSM_HOOK_INIT(inode_setxattr, lsm_tmp_inode_setxattr),
        LSM_HOOK_INIT(inode_post_setxattr, lsm_tmp_inode_post_setxattr),
        LSM_HOOK_INIT(inode_getxattr, lsm_tmp_inode_getxattr),
        LSM_HOOK_INIT(inode_listxattr, lsm_tmp_inode_listxattr),
        LSM_HOOK_INIT(inode_removexattr, lsm_tmp_inode_removexattr),
        LSM_HOOK_INIT(inode_getsecurity, lsm_tmp_inode_getsecurity),
        LSM_HOOK_INIT(inode_setsecurity, lsm_tmp_inode_setsecurity),
        LSM_HOOK_INIT(inode_listsecurity, lsm_tmp_inode_listsecurity),
        LSM_HOOK_INIT(inode_getsecid, lsm_tmp_inode_getsecid),

        LSM_HOOK_INIT(file_permission, lsm_tmp_file_permission),
        LSM_HOOK_INIT(file_alloc_security, lsm_tmp_file_alloc_security),
        LSM_HOOK_INIT(file_free_security, lsm_tmp_file_free_security),
        LSM_HOOK_INIT(file_ioctl, lsm_tmp_file_ioctl),
        LSM_HOOK_INIT(mmap_file, lsm_tmp_mmap_file),
        LSM_HOOK_INIT(mmap_addr, lsm_tmp_mmap_addr),
        LSM_HOOK_INIT(file_mprotect, lsm_tmp_file_mprotect),
        LSM_HOOK_INIT(file_lock, lsm_tmp_file_lock),
        LSM_HOOK_INIT(file_fcntl, lsm_tmp_file_fcntl),
        LSM_HOOK_INIT(file_set_fowner, lsm_tmp_file_set_fowner),
        LSM_HOOK_INIT(file_send_sigiotask, lsm_tmp_file_send_sigiotask),
        LSM_HOOK_INIT(file_receive, lsm_tmp_file_receive),

        LSM_HOOK_INIT(file_open, lsm_tmp_file_open),

        LSM_HOOK_INIT(task_create, lsm_tmp_task_create),
        LSM_HOOK_INIT(cred_alloc_blank, lsm_tmp_cred_alloc_blank),
        LSM_HOOK_INIT(cred_free, lsm_tmp_cred_free),
        LSM_HOOK_INIT(cred_prepare, lsm_tmp_cred_prepare),
        LSM_HOOK_INIT(cred_transfer, lsm_tmp_cred_transfer),
        LSM_HOOK_INIT(kernel_act_as, lsm_tmp_kernel_act_as),
        LSM_HOOK_INIT(kernel_create_files_as, lsm_tmp_kernel_create_files_as),
        LSM_HOOK_INIT(kernel_module_request, lsm_tmp_kernel_module_request),
        LSM_HOOK_INIT(task_setpgid, lsm_tmp_task_setpgid),
        LSM_HOOK_INIT(task_getpgid, lsm_tmp_task_getpgid),
        LSM_HOOK_INIT(task_getsid, lsm_tmp_task_getsid),
        LSM_HOOK_INIT(task_getsecid, lsm_tmp_task_getsecid),
        LSM_HOOK_INIT(task_setnice, lsm_tmp_task_setnice),
        LSM_HOOK_INIT(task_setioprio, lsm_tmp_task_setioprio),
        LSM_HOOK_INIT(task_getioprio, lsm_tmp_task_getioprio),
        LSM_HOOK_INIT(task_setrlimit, lsm_tmp_task_setrlimit),
        LSM_HOOK_INIT(task_setscheduler, lsm_tmp_task_setscheduler),
        LSM_HOOK_INIT(task_getscheduler, lsm_tmp_task_getscheduler),
        LSM_HOOK_INIT(task_movememory, lsm_tmp_task_movememory),
        LSM_HOOK_INIT(task_kill, lsm_tmp_task_kill),
        LSM_HOOK_INIT(task_wait, lsm_tmp_task_wait),
        LSM_HOOK_INIT(task_to_inode, lsm_tmp_task_to_inode),

        LSM_HOOK_INIT(ipc_permission, lsm_tmp_ipc_permission),
        LSM_HOOK_INIT(ipc_getsecid, lsm_tmp_ipc_getsecid),

        LSM_HOOK_INIT(msg_msg_alloc_security, lsm_tmp_msg_msg_alloc_security),
        LSM_HOOK_INIT(msg_msg_free_security, lsm_tmp_msg_msg_free_security),

        LSM_HOOK_INIT(msg_queue_alloc_security,
                        lsm_tmp_msg_queue_alloc_security),
        LSM_HOOK_INIT(msg_queue_free_security, lsm_tmp_msg_queue_free_security),
        LSM_HOOK_INIT(msg_queue_associate, lsm_tmp_msg_queue_associate),
        LSM_HOOK_INIT(msg_queue_msgctl, lsm_tmp_msg_queue_msgctl),
        LSM_HOOK_INIT(msg_queue_msgsnd, lsm_tmp_msg_queue_msgsnd),
        LSM_HOOK_INIT(msg_queue_msgrcv, lsm_tmp_msg_queue_msgrcv),

        LSM_HOOK_INIT(shm_alloc_security, lsm_tmp_shm_alloc_security),
        LSM_HOOK_INIT(shm_free_security, lsm_tmp_shm_free_security),
        LSM_HOOK_INIT(shm_associate, lsm_tmp_shm_associate),
        LSM_HOOK_INIT(shm_shmctl, lsm_tmp_shm_shmctl),
        LSM_HOOK_INIT(shm_shmat, lsm_tmp_shm_shmat),

        LSM_HOOK_INIT(sem_alloc_security, lsm_tmp_sem_alloc_security),
        LSM_HOOK_INIT(sem_free_security, lsm_tmp_sem_free_security),
        LSM_HOOK_INIT(sem_associate, lsm_tmp_sem_associate),
        LSM_HOOK_INIT(sem_semctl, lsm_tmp_sem_semctl),
        LSM_HOOK_INIT(sem_semop, lsm_tmp_sem_semop),

        LSM_HOOK_INIT(d_instantiate, lsm_tmp_d_instantiate),

        LSM_HOOK_INIT(getprocattr, lsm_tmp_getprocattr),
        LSM_HOOK_INIT(setprocattr, lsm_tmp_setprocattr),

        LSM_HOOK_INIT(ismaclabel, lsm_tmp_ismaclabel),
        LSM_HOOK_INIT(secid_to_secctx, lsm_tmp_secid_to_secctx),
        LSM_HOOK_INIT(secctx_to_secid, lsm_tmp_secctx_to_secid),
        LSM_HOOK_INIT(release_secctx, lsm_tmp_release_secctx),
        LSM_HOOK_INIT(inode_invalidate_secctx, lsm_tmp_inode_invalidate_secctx),        LSM_HOOK_INIT(inode_notifysecctx, lsm_tmp_inode_notifysecctx),
        LSM_HOOK_INIT(inode_setsecctx, lsm_tmp_inode_setsecctx),
        LSM_HOOK_INIT(inode_getsecctx, lsm_tmp_inode_getsecctx),

        LSM_HOOK_INIT(unix_stream_connect, lsm_tmp_socket_unix_stream_connect),
        LSM_HOOK_INIT(unix_may_send, lsm_tmp_socket_unix_may_send),

        LSM_HOOK_INIT(socket_create, lsm_tmp_socket_create),
        LSM_HOOK_INIT(socket_post_create, lsm_tmp_socket_post_create),
        LSM_HOOK_INIT(socket_bind, lsm_tmp_socket_bind),
        LSM_HOOK_INIT(socket_connect, lsm_tmp_socket_connect),
        LSM_HOOK_INIT(socket_listen, lsm_tmp_socket_listen),
        LSM_HOOK_INIT(socket_accept, lsm_tmp_socket_accept),
        LSM_HOOK_INIT(socket_sendmsg, lsm_tmp_socket_sendmsg),
        LSM_HOOK_INIT(socket_recvmsg, lsm_tmp_socket_recvmsg),
        LSM_HOOK_INIT(socket_getsockname, lsm_tmp_socket_getsockname),
        LSM_HOOK_INIT(socket_getpeername, lsm_tmp_socket_getpeername),
        LSM_HOOK_INIT(socket_getsockopt, lsm_tmp_socket_getsockopt),
        LSM_HOOK_INIT(socket_setsockopt, lsm_tmp_socket_setsockopt),
        LSM_HOOK_INIT(socket_shutdown, lsm_tmp_socket_shutdown),
        LSM_HOOK_INIT(socket_sock_rcv_skb, lsm_tmp_socket_sock_rcv_skb),
        LSM_HOOK_INIT(socket_getpeersec_stream,
                        lsm_tmp_socket_getpeersec_stream),
        LSM_HOOK_INIT(socket_getpeersec_dgram, lsm_tmp_socket_getpeersec_dgram),
        LSM_HOOK_INIT(sk_alloc_security, lsm_tmp_sk_alloc_security),
        LSM_HOOK_INIT(sk_free_security, lsm_tmp_sk_free_security),
        LSM_HOOK_INIT(sk_clone_security, lsm_tmp_sk_clone_security),
        LSM_HOOK_INIT(sk_getsecid, lsm_tmp_sk_getsecid),
        LSM_HOOK_INIT(sock_graft, lsm_tmp_sock_graft),
        LSM_HOOK_INIT(inet_conn_request, lsm_tmp_inet_conn_request),
        LSM_HOOK_INIT(inet_csk_clone, lsm_tmp_inet_csk_clone),
        LSM_HOOK_INIT(inet_conn_established, lsm_tmp_inet_conn_established),
        LSM_HOOK_INIT(secmark_relabel_packet, lsm_tmp_secmark_relabel_packet),
        LSM_HOOK_INIT(secmark_refcount_inc, lsm_tmp_secmark_refcount_inc),
        LSM_HOOK_INIT(secmark_refcount_dec, lsm_tmp_secmark_refcount_dec),
        LSM_HOOK_INIT(req_classify_flow, lsm_tmp_req_classify_flow),
        LSM_HOOK_INIT(tun_dev_alloc_security, lsm_tmp_tun_dev_alloc_security),
        LSM_HOOK_INIT(tun_dev_free_security, lsm_tmp_tun_dev_free_security),
        LSM_HOOK_INIT(tun_dev_create, lsm_tmp_tun_dev_create),
        LSM_HOOK_INIT(tun_dev_attach_queue, lsm_tmp_tun_dev_attach_queue),
        LSM_HOOK_INIT(tun_dev_attach, lsm_tmp_tun_dev_attach),
        LSM_HOOK_INIT(tun_dev_open, lsm_tmp_tun_dev_open),

#ifdef CONFIG_KEYS
        LSM_HOOK_INIT(key_alloc, lsm_tmp_key_alloc),
        LSM_HOOK_INIT(key_free, lsm_tmp_key_free),
        LSM_HOOK_INIT(key_permission, lsm_tmp_key_permission),
        LSM_HOOK_INIT(key_getsecurity, lsm_tmp_key_getsecurity),
#endif

#ifdef CONFIG_AUDIT
        LSM_HOOK_INIT(audit_rule_init, lsm_tmp_audit_rule_init),
        LSM_HOOK_INIT(audit_rule_known, lsm_tmp_audit_rule_known),
        LSM_HOOK_INIT(audit_rule_match, lsm_tmp_audit_rule_match),
        LSM_HOOK_INIT(audit_rule_free, lsm_tmp_audit_rule_free),
#endif
};


static __init int lsm_tmp_init(void)
	{
	/* register the hooks */	
	
	if (!security_module_enable("lsm_tmp")) {
		lsm_tmp_enabled = 0;
        printk(KERN_INFO " LSM_TMP:  lsm_tmp_enabled = 0.\n");
		return 0;
	}
        printk(KERN_INFO " LSM_TMP:  lsm_tmp enabled. \n");

        if (!lsm_tmp_enabled) {
                printk(KERN_INFO "LSM_TMP:  Disabled at boot.\n");
                return 0;
        }

        /*
         * Register with LSM
         */

        security_add_hooks(lsm_tmp_hooks, ARRAY_SIZE(lsm_tmp_hooks));

        printk(KERN_INFO "LSM_TMP:  Initializing.\n");


	return 0;
}

/*
static void __exit lsm_tmp_exit (void)
{	
	return;
}

*/

security_initcall(lsm_tmp_init);

#endif /* CONFIG_SECURITY_lsm_tmp */

