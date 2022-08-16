#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/in.h>
#include <linux/module.h>

#define TRACK_FLAGS_TRACK 1

/* This is a BPF macro for that creates a BPF data-structure that we can communicate with in user-mode */
BPF_PERF_OUTPUT(events);

BPF_HASH(hash_tracking, struct file*, int, 10240);
BPF_HASH(hash_fntrack, u64, int, 10240);
BPF_HASH(hash_bound_fds, u64, int, 10240);

static u64 get_module_name(struct file* fp, char* pmodule_name)
{
    struct file_operations* fops = 0;
    struct module* owner = 0;

    if (0 != bpf_probe_read(
                &fops,
                sizeof(void*),
                (char*)fp + offsetof(struct file, f_op)))
        return -1;

    if (0 != bpf_probe_read(
                &owner,
                sizeof(void*),
                (char*)fops + offsetof(struct file_operations, owner)))
        return fops;

    if (0 != bpf_probe_read(
                pmodule_name,
                64 - sizeof(unsigned long) - 1,
                (char*)owner + offsetof(struct module, name)))
        return -3;

    pmodule_name[64 - sizeof(unsigned long)] = 0;

    return 0;
}

// The following is the data-structure we'll pass to our user-land program
typedef struct _DATA
{
    char process_name[TASK_COMM_LEN];    // Process name
    char event_type[TASK_COMM_LEN];      // event_type
    u32 pid;                             // Process ID
    u64 socket_fd;                       // Bound Socket FD
    u64 length;                          // length
    u64 timestamp;                       // nanoseconds since boot
} data_t;

/* This is our BPF routine, it contains two arguments:
- A pt_regs* struct, which contains the BPF VM registers
- A socket fd - this will actually be transformed by bcc to a local variable that is set by the registers, see note below
*/

//static struct file*
static void* get_file_from_fd_internal(int fd, int* handlecount)
{
    struct task_struct*     pcurrent        = (struct task_struct*)bpf_get_current_task();
    struct files_struct*    ptask_files     = 0;
    struct fdtable*         pfdt            = 0;
    struct fdtable          fdt             = {0};
    struct file*            pfile           = 0;
    long                    fcount          = 0;

    /*
     * Kernel code is:
     * struct files_struct ptask_files = current->files
     * struct fdtable* fdt = files->fdt
     * struct file* pfile = fdt->fd[file_handle]
     */

    if (!pcurrent)
        return pcurrent;

    if (0 != bpf_probe_read(
                &ptask_files, 
                sizeof(ptask_files), 
                (char*)pcurrent + offsetof(struct task_struct, files))
            || !ptask_files)
    {
        return 0;
    }

    if (0 != bpf_probe_read(
                &pfdt,
                sizeof(pfdt),
                (char*)ptask_files + offsetof(struct files_struct, fdt))
            || !pfdt)
    {
        return 0;
    }

    if (0 != bpf_probe_read(&fdt, sizeof(fdt), pfdt))
    {
        return 0;
    }

    if (fd >= fdt.max_fds)
        return 0;

    if (0 != bpf_probe_read(
                &pfile,
                sizeof(pfile),
                (char*)fdt.fd + (fd * sizeof(struct file*)))
            || !pfile)
    {
        return 0;
    }

    if (0 != bpf_probe_read(
                &fcount,
                sizeof(fcount),
                (char*)pfile + offsetof(struct file, f_count)))
    {
        return 0;
    }

    if (handlecount)
        *handlecount = fcount;
    
    return (void*)(pfdt);
}

static void* get_file_from_fd(int fd, int* handlecount)
{
    void* retval = get_file_from_fd_internal(fd, handlecount);

    return retval;
}


static int is_interesting_port(int port)
{
    return 1;
}

#define TYPE_RECVFROM           1
#define TYPE_RECVMSG            2
#define TYPE_RECV               3
#define TYPE_SENDTO             4
#define TYPE_SENDMSG            5
#define TYPE_SEND               6

static int on_recv_common(
        struct pt_regs*     ctx, 
        int                 fd, 
        void*               buf, 
        size_t              len, 
        unsigned int        flags, 
        struct sockaddr*    sa, 
        int                 addrlen, 
        int                 type)
{
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    data_t          data            = {0};
    
    int temp = fd;


    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    hash_fntrack.update(&pid_tgid, &temp);

    return 0;
    
}

int kprobe_sys_recvfrom(struct pt_regs* ctx, int fd, void* buf, size_t len, unsigned int flags, struct sockaddr* sa, int addr_len)
{
    return on_recv_common(ctx, fd, buf, len, flags, sa, addr_len, TYPE_RECVFROM);
}

int kprobe_sys_recvmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msg, unsigned int flags)
{
    return on_recv_common(ctx, fd, 0, 0, 0, 0, 0, TYPE_RECVMSG);
}

static int on_recv_ret_common(struct pt_regs* ctx, int type, int in_fdhandle, size_t rc)
{
    data_t          data            = { 0 };
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    int             fdhandle        = in_fdhandle;
    struct file*    pfile           = 0;
    int*            pfd             = 0;
    int             tempfd;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    pfd = hash_fntrack.lookup(&pid_tgid);
    if (!pfd)
        return 0;


    data.event_type[0] = 'r';
    data.event_type[1] = 'e';
    data.event_type[2] = 'c';
    data.event_type[3] = 'v';
    data.event_type[4] = 0;
    if (TYPE_RECVFROM == type)
    {
        data.event_type[4] = 'F';
        data.event_type[5] = 'r';
        data.event_type[6] = 'o';
        data.event_type[7] = 'm';
        data.event_type[8] = 0;
    }
    


    tempfd = (u64)(*pfd);
    data.socket_fd = tempfd;
    pfile = get_file_from_fd((int)data.length, 0);

    if (!pfile || !hash_tracking.lookup(&pfile))
    {
        hash_fntrack.delete(&pid_tgid);
        return 0;
    }

    data.pid = pid_tgid & 0xffffffff;
    if (pfd)
        data.socket_fd= *pfd;
    else
        data.socket_fd= 0xdecaf;

    data.length = rc;

    data.timestamp = bpf_ktime_get_boot_ns();
    events.perf_submit(ctx, &data, sizeof(data));


    hash_fntrack.delete(&pid_tgid);
    return 0;
}

int kretprobesys_recvfrom(struct pt_regs* ctx)
{
    return on_recv_ret_common(ctx, TYPE_RECVFROM, PT_REGS_PARM1(ctx), PT_REGS_RC(ctx));
}

int kretprobesys_recvmsg(struct pt_regs* ctx)
{
    return on_recv_ret_common(ctx, TYPE_RECVMSG, PT_REGS_PARM1(ctx), PT_REGS_RC(ctx));
}

//----------------------------------------------

static int on_send_common(
        struct pt_regs*     ctx, 
        int                 fd, 
        void*               buf, 
        size_t              len, 
        unsigned int        flags, 
        struct sockaddr*    sa, 
        int                 addrlen, 
        int                 type)
{
    data_t          data            = { 0 };
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    int             fdhandle        = fd;
    struct file*    pfile           = 0;
    int             track_flags     = TRACK_FLAGS_TRACK;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;
    
    //pfile = get_file_from_fd(fd, 0);
    //if (!pfile || !hash_tracking.lookup(&pfile))
        return 0;


    pfile = get_file_from_fd(fd, 0);

    //if (!hash_tracking.lookup(&pfile))
     //   return 0;

    data.event_type[0] = 's';
    data.event_type[1] = 'e';
    data.event_type[2] = 'n';
    data.event_type[3] = 'd';
    data.event_type[3] = 't';
    data.event_type[4] = 'o';
    data.event_type[5] = 0;

    data.socket_fd = fd;
    data.length = (u64)pfile;
    data.pid = pid_tgid & 0xffffffff;

    if (!pfile || !hash_tracking.lookup(&pfile))
        data.event_type[0] = 'X';

    data.timestamp = bpf_ktime_get_boot_ns();
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

#if 0
static int on_send_ret_common(struct pt_regs* ctx, int type)
{
    data_t          data            = { 0 };
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    int             fdhandle        = PT_REGS_PARM1(ctx);
    struct file*    pfile           = 0;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;
    
    pfile = get_file_from_fd(fdhandle, 0);

    data.event_type[0] = 'S';
    data.event_type[1] = 'E';
    data.event_type[2] = 'N';
    data.event_type[3] = 'D';
    data.event_type[4] = 0;
    if (TYPE_SENDTO == type)
    {
        data.event_type[4] = 'T';
        data.event_type[5] = 'o';
        data.event_type[6] = 0;
    }

    if (!pfile || !hash_tracking.lookup(&pfile))
        data.event_type[0] = 'X';

    if (!hash_tracking.lookup(&pfile))
        data.event_type[0] = 'X';
        //hash_send_context.insert(&pid_tgid, &fdhandle);

    data.socket_fd = fdhandle;
    data.length = pfile;
    data.pid = pid_tgid & 0xffffffff;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int kretprobesys_sendto(struct pt_regs* ctx)
{
    return on_send_ret_common(ctx, TYPE_SENDTO);
}

int kretprobesys_sendmsg(struct pt_regs* ctx)
{
    return on_send_ret_common(ctx, TYPE_SENDMSG);
}
#endif

int kprobe_sys_sendto(struct pt_regs* ctx, int fd, void* buf, size_t len, unsigned int flags, struct sockaddr* sa, int addr_len)
{
    return on_send_common(ctx, fd, buf, len, flags, sa, addr_len, TYPE_SENDTO);
}

int kprobe_sys_sendmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msg, unsigned int flags)
{
    return on_send_common(ctx, fd, 0, 0, 0, 0, 0, TYPE_SENDMSG);
}

//----------------------------------------------

#define MIN(x,y) (x<y)?x:y
int kprobe_sys_bind(struct pt_regs* ctx, int fd, struct sockaddr_in* puser_addr, int addrlen)
{
    data_t                  data            = {};    
    struct sockaddr_in      addr            = {0};
    long                    retval;
    int                     port            = 0;
    struct file*            pfile;
    int                     track_flags     = TRACK_FLAGS_TRACK;

    data.socket_fd = fd;

    // A bpf helper that gets the process name that invoked the bind operation
    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    
    //{if_not_condition}
        //{return} 0;
    
    data.timestamp = bpf_ktime_get_boot_ns();

    data.pid = bpf_get_current_pid_tgid();

    // Gets the pid via the bpf helper (pid is the upper 32 bits)
    data.length = fd;


    data.event_type[0] = 'b';
    data.event_type[1] = 'i';
    data.event_type[2] = 'n';
    data.event_type[3] = 'd';
    data.event_type[5] = 0;


    pfile = get_file_from_fd(fd, 0);
    data.length = 0;
    

    if (! (0 != (retval = bpf_probe_read_user(
                    &addr,
                    MIN(addrlen, sizeof(struct sockaddr_in)),
                    puser_addr))))
    {
        port = bpf_ntohs(puser_addr->sin_port); // TODO: this is the port, filter on basis of this
        if (is_interesting_port(port) && !hash_tracking.lookup(&pfile))
        {
            int dummy = 1;
            hash_tracking.insert(&pfile, &track_flags);
            hash_bound_fds.update(&data.socket_fd, &dummy);
            // Copies the data to the BPF structure, it is now available to user-mode
	    data.timestamp = bpf_ktime_get_boot_ns();
            //{if_condition}
                    events.perf_submit(ctx, &data, sizeof(data));
                //if (is_interesting_port(port))
        }
    }


    return 0;
}

//----------------------------------------------

int kretprobesys_accept4(struct pt_regs* ctx)
{
    int                     fd              = PT_REGS_PARM1(ctx);
    u64                     temp            = fd;
    int                     accepted_socket = PT_REGS_RC(ctx);
    data_t                  data            = {};    
    int                     port            = 0;
    struct file*            pfile;
    int                     track_flags     = TRACK_FLAGS_TRACK;
    u64                     pid_tgid        = bpf_get_current_pid_tgid();
    int*                    pfd             = 0;
    int                     fd_file_found   = 0;
    int                     fd_sock_found   = 0;
    struct file*            pfile2;

    // A bpf helper that gets the process name that invoked the bind operation
    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    
    //{if_not_condition}
        //{return} 0;
        
    data.event_type[0] = 'A';
    if (!(pfd = hash_fntrack.lookup(&pid_tgid)))
    {
        data.event_type[0] = 'X';
        return 0;
    }
    else
    {
        fd = *pfd;
        temp = fd;
        hash_fntrack.delete(&pid_tgid);
    }
    
    pfile = get_file_from_fd(fd, 0);
    data.length = (u64)pfile;
    if (pfile && hash_tracking.lookup(&pfile))
        fd_file_found = 1;
    if (hash_bound_fds.lookup(&temp))
        fd_sock_found = 1;
    if (!fd_sock_found && !fd_file_found)
        return 0;
    //hash_tracking.update(&pfile, &track_flags);

    // Get the accepted socket file structure
    pfile2 = get_file_from_fd(accepted_socket, 0);
    hash_tracking.update(&pfile2, &track_flags);

    data.timestamp = bpf_ktime_get_boot_ns();

    data.pid = pid_tgid;


    //data.event_type[0] = 'A';
    data.event_type[1] = 'C';
    data.event_type[2] = 'C';
    data.event_type[3] = 'E';
    data.event_type[4] = 'P';
    data.event_type[5] = 'T';
    data.event_type[6] = 0;

    data.socket_fd = (u64)fd << 32 | (u64)0xf0000000 << 32 | (u64)accepted_socket | (u64)0xf0000000;
    data.length = 0;
    //data.length = (u64)fd_sock_found << 32 | (u64)0xf0000000 << 32 | (u64)fd_file_found| (u64)0xf0000000;
    //data.length = get_file_from_fd(fd, 0);


    // Copies the data to the BPF structure, it is now available to user-mode
    data.timestamp = bpf_ktime_get_boot_ns();
    //{if_condition}
            events.perf_submit(ctx, &data, sizeof(data));
        //if (is_interesting_port(port))

    return 0;
}

int kprobe_sys_accept4(struct pt_regs* ctx, int fd)
{
    u64             pid_tgid        = bpf_get_current_pid_tgid();

    hash_fntrack.update(&pid_tgid, &fd);
 
    return 0;
}


// ------------------------------------
//
int kprobe_do_writev(struct pt_regs* ctx, unsigned long fd, void* vec, unsigned long vlen)
{
    data_t          data            = { 0 };
    int             tempfd          = fd;
    u64             pid_tgid        = bpf_get_current_pid_tgid();

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    data.socket_fd = fd;
    if (!get_file_from_fd(fd, 0))
        return 0;

    hash_fntrack.update(&pid_tgid, &tempfd);


    return 0;
}

int kretprobedo_writev(struct pt_regs* ctx)
{
    int             fd;
    int*            pfd             = 0;
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    data_t          data            = { 0 };
    struct file*    pfile           = 0;
    u64 rc;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    if (!(pfd = hash_fntrack.lookup(&pid_tgid)))
        return 0;
    
    fd = *pfd;
    data.socket_fd = fd;
    pfile = get_file_from_fd(data.socket_fd, 0);
    if (!pfile || !hash_tracking.lookup(&pfile))
        return 0;


    data.event_type[0] = 'W';
    data.event_type[1] = 'r';
    data.event_type[2] = 'i';
    data.event_type[3] = 't';
    data.event_type[4] = 'e';
    data.event_type[5] = 'v';
    data.event_type[6] = 0;

    data.pid = pid_tgid;
    data.length = PT_REGS_RC(ctx);

    //get_module_name(pfile, &data.modulename);

    data.timestamp = bpf_ktime_get_boot_ns();
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

// -----------------------------------------------------
//
int kprobe_ksys_write(struct pt_regs* ctx, unsigned int tempfd, char* buf, size_t count)
{
    int             fd              = tempfd; //PT_REGS_PARM1(ctx);
    data_t          data            = { 0 };
    u64             pid_tgid        = bpf_get_current_pid_tgid();

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    hash_fntrack.update(&pid_tgid, &tempfd);

    return 0;
}

int kretprobedo_write(struct pt_regs* ctx)
{
    int             fd;
    int*            pfd             = 0;
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    data_t          data            = { 0 };
    struct file*    pfile           = 0;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    if (!(pfd = hash_fntrack.lookup(&pid_tgid)))
        return 0;
    
    fd = *pfd;
    hash_fntrack.delete(&pid_tgid);
    data.socket_fd = fd;
    pfile = get_file_from_fd(fd, 0);
    if (!pfile || !hash_tracking.lookup(&pfile))
        return 0;


    data.event_type[0] = 'w';
    data.event_type[1] = 'r';
    data.event_type[2] = 'i';
    data.event_type[3] = 't';
    data.event_type[4] = 'e';
    data.event_type[5] = ' ';
    data.event_type[6] = 0;

    data.pid = pid_tgid;
    data.length = PT_REGS_RC(ctx);

    //get_module_name(pfile, &data.modulename);


    data.timestamp = bpf_ktime_get_boot_ns();
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

// --------------------------------------------

int syscall__close(struct pt_regs* ctx, int tempfd)
{
    int             fd              = tempfd;
    data_t          data            = { 0 };
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    struct file*    pfile           = 0;
    int             handlecount     = 0;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;

    data.socket_fd = fd;
    if (!(pfile = get_file_from_fd(fd, &handlecount)))
        return 0;

    if (!hash_tracking.lookup(&pfile))
        return 0;

    if ( 0 == handlecount)
        if (hash_tracking.lookup(&pfile))
            hash_tracking.delete(&pfile);

    data.event_type[0] = 'c';
    data.event_type[1] = 'l';
    data.event_type[2] = 'o';
    data.event_type[3] = 's';
    data.event_type[4] = 'e';
    data.event_type[5] = 0;


    data.socket_fd = tempfd;
    data.pid = pid_tgid;
    data.length = 0;
    //data.length = pfile;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}


// --------------------------------
int kprobe_sock_close(struct pt_regs* ctx, void* x, void* s)
{
    data_t data = {0};
    struct file* f = s;

    if (hash_tracking.lookup(&f))
        hash_tracking.delete(&f);

    return 0;
}

// ------------------------------
#if 0
int kprobe_do_sendfile(struct pt_regs* ctx, int out_fd, int in_fd, unsigned long offset, size_t count)
{
    int             fd              = out_fd;
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    data_t          data            = { 0 };

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;
    
    hash_fntrack.update(&pid_tgid, &fd);

    return 0;
}
#endif

int kretprobe_do_sendfile(struct pt_regs* ctx)
{
    u64             rc              = PT_REGS_RC(ctx);
    data_t          data            = { 0 };
    u64             pid_tgid        = bpf_get_current_pid_tgid();
    struct file*    pfile           = 0;
    int             fd              = 0;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    //{if_not_condition}
        //{return} 0;
    
    data.event_type[0] = 's';
    data.event_type[1] = 'e';
    data.event_type[2] = 'n';
    data.event_type[3] = 'd';
    data.event_type[4] = 'f';
    data.event_type[5] = 'i';
    data.event_type[6] = 'l';
    data.event_type[7] = 'e';
    data.event_type[8] = 0;

    fd = PT_REGS_PARM1(ctx);

    pfile = get_file_from_fd((int)fd, 0);
    if (pfile && hash_tracking.lookup(&pfile))
    {
        data.socket_fd = fd;
        data.length = rc;
        data.pid = pid_tgid;
        data.timestamp = bpf_ktime_get_boot_ns();
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
