#!/usr/bin/python3

import sys
from threading import Thread
from socket import socket
import ctypes as ct
import time
from bcc import BPF

with open("bpf.c", "r") as f:
    prog = str(f.read())
    prog = prog.strip()

def get_if_clause(processname):
    out_str = ""
    for i, c in enumerate(list(processname)):
        if "" != out_str:
            out_str += "\t\t\t\t&& "
        clause = f"(data.process_name[{i}] == '{c.upper()}' || data.process_name[{i}] == '{c.lower()}')"
        out_str = out_str + clause + "\\\n"
    out_str = f"(\\\n\t\t\t\t{out_str}\t)"
    return out_str

def get_if_condition(processes:list)->str:
    if not processes or not isinstance(processes, list) or len(processes) == 0:
        return ""
    clauses = ""
    for process in processes:
        clause = get_if_clause(process)
        if "" != clauses:
            clauses = clauses + "\\\n\t\t\t\t||\n\t\t\t\t"
        clauses = clauses + clause
    return f"if (\\\n{clauses}\\\n)"

def get_if_not_condition(processes:list)->str:
    if not processes or not isinstance(processes, list) or len(processes) == 0:
        return ""
    clauses = ""
    for process in processes:
        clause = get_if_clause(process)
        if "" != clauses:
            clauses = clauses + "\\\n\t\t\t\t||\n\t\t\t\t"
        clauses = clauses + clause
    return f"if (\\\n!({clauses})\\\n)"

prog = prog.replace("//{if_condition}", get_if_condition(["/usr/sbin/nginx", "nginx",]))
prog = prog.replace("//{if_not_condition}", get_if_not_condition(["/usr/sbin/nginx", "nginx",]))
prog = prog.replace("//{return}", "return ")

with open("out_bpf.c", "w") as f2:
    f2.write(prog)

# Compiles the BPF program via LLVM
b = BPF(text=prog)

# Represents the native data-structure above
class Data(ct.Structure):
    _fields_ = [
        ('process_name', ct.c_char * 16), 
        ('event_type', ct.c_char * 16),
        ('pid', ct.c_uint32),
        ('socket_fd', ct.c_uint64),
        ('length', ct.c_uint64),
        ('timestamp', ct.c_int64),
    ]

f_out = open("out.txt", "w")
# A callback to be called for every record in the 'events' BPF data structure
def print_event(cpu, data, size):
    data = ct.cast(data, ct.POINTER(Data)).contents
    print('{evttype} procname={process_name} pid={pid} socketid={socket_fd} timestamp={timestamp} length={length} '.format(
        evttype=data.event_type, 
        process_name=data.process_name, 
        pid=data.pid, 
        socket_fd=hex(data.socket_fd), 
        timestamp=data.timestamp,
        length=hex(data.length)))
    f_out.write('{evttype} procname={process_name} pid={pid} socketid={socket_fd} timestamp={timestamp} length={length} \n'.format(
        evttype=data.event_type,
        process_name=data.process_name,
        pid=data.pid,
        socket_fd=hex(data.socket_fd),
        timestamp=data.timestamp,
        length=hex(data.length)))
    f_out.flush()

# This calls libbpf, which in turns calls the bpf(2) syscall, and does a few more tricks to attach the kernel probe
b.attach_kprobe(event='__sys_bind', fn_name='kprobe_sys_bind')

b.attach_kretprobe(event='__sys_accept4', fn_name='kretprobesys_accept4')
b.attach_kprobe(event='__sys_accept4', fn_name='kprobe_sys_accept4')

b.attach_kprobe(event='__sys_recvfrom', fn_name='kprobe_sys_recvfrom')
b.attach_kretprobe(event='__sys_recvfrom', fn_name='kretprobesys_recvfrom')
b.attach_kprobe(event='__sys_recvmsg', fn_name='kprobe_sys_recvmsg')
b.attach_kretprobe(event='__sys_recvmsg', fn_name='kretprobesys_recvmsg')

b.attach_kprobe(event='__sys_sendto', fn_name='kprobe_sys_sendto')
b.attach_kprobe(event='__sys_sendmsg', fn_name='kprobe_sys_sendto')

b.attach_kprobe(event='do_writev', fn_name='kprobe_do_writev');
b.attach_kretprobe(event='do_writev', fn_name='kretprobedo_writev');

b.attach_kprobe(b.get_syscall_fnname('close'), fn_name='syscall__close')
b.attach_kretprobe(event='do_sendfile', fn_name='kretprobe_do_sendfile')

b.attach_kretprobe(event='__sys_sendmsg', fn_name='kretprobe_sys_sendto')
b.attach_kretprobe(event='__sys_sendto', fn_name='kretprobe_sys_sendto')
#b.attach_kprobe(event='__sys_sendmsg', fn_name='kprobe_sys_sendmsg')
#b.attach_kprobe(b.get_syscall_fnname('sendto'), fn_name='kprobe_sys_sendto')
#b.attach_kprobe(b.get_syscall_fnname('sendmsg'), fn_name='kprobe_sys_sendto')

# An async function that binds to localhost:31337 (To get an output for the above)
"""
def call_bind_async():
    time.sleep(2)
    print('Calling bind...')
    s = socket()
    s.bind(('localhost', 31337))

t = Thread(target=call_bind_async)
t.start()
"""

print()
print()
print()
print()
print()
print('*' * 80)
print("All hooks attached. Starting to monitor now.")
print('*' * 80)
print()
print()
print()
print()
print("*** RESTART NGINX NOW ***")
print()
print("By default, the script monitors port 8080 and 8090")
print("If you need a different port to be monitored, do the following")
print("1. Find the function is_interesting_port() in bpf.c")
print("2. Modify the body of the function to filter the listening ports you want")
print("3. Restart ebpf.py and nginx")


# This will open the BPF data structure for polling
b['events'].open_perf_buffer(print_event)
while True:
    try:
        # Poll the data structure till Ctrl+C
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print('Bye !')
        break

#b.attach_kprobe(event='sock_close', fn_name='kprobe_sock_close');

#b.attach_kprobe(b.get_syscall_fnname('sendfile'), fn_name='syscall__sendfile')
#b.attach_kretprobe(b.get_syscall_fnname('sendfile'), fn_name='kprobe_ret_sys_sendfile')

#b.attach_kprobe(event='do_sendfile', fn_name='kprobe_do_sendfile')

#b.attach_kprobe(event='ksys_write', fn_name='kprobe_ksys_write');
#b.attach_kretprobe(event='ksys_write', fn_name='kretprobedo_write');
#b.attach_kretprobe(event='__sys_sendmsg', fn_name='kretprobesys_sendmsg')
#b.attach_kretprobe(event='__sys_sendto', fn_name='kretprobesys_sendto')

