/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab offline provisioning, static validation and Linux
 * supervision for the softKMS PKCS#11 module against a co-located
 * softKMS daemon. Native PKCS#11 calls, service responses and application
 * status are preserved.
 *
 * The daemon boots locked and holds persistent file state. Every operation
 * launches one keykeeper (which spawns its key-free REST frontend child)
 * on fixed loopback ports with per-launch control files; init provisions
 * the keystore with the caller passphrase as the admin secret plus one
 * pkcs11 identity whose server-generated token IS the PKCS#11 PIN, while
 * health/exec unlock the existing keystore with the persisted admin
 * secret. No baked credentials or initialized state ship; failed or
 * foreign state is refused, never silently reset or reprovisioned.
 *
 * The caller PIN provisions the admin secret only: PKCS#11 login accepts
 * only the provisioned identity token (persisted 0600 in owned state for
 * the state owner). There is no distinct security-officer role: native
 * C_Login(CKU_SO) succeeds with the identity token, exactly like CKU_USER.
 * The native token label is fixed to softKMS and P-256 signing always
 * applies SHA-256; see provider.json constraints and the recipe docs.
 */
#define _GNU_SOURCE
#include <p11-kit/pkcs11.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROOT "/var/lib/p11lab"
#define OWNED ROOT "/softkms"
#define CONTROL "/run/p11lab/softkms"
#define MODULE "/usr/local/lib/p11lab/libsoftkms.so"
#define BINDIR "/usr/local/bin"
#define DAEMON BINDIR "/softkms-daemon"
#define CLI BINDIR "/softkms"
#define GRPC_ADDR "127.0.0.1:50051"
#define REST_ADDR "127.0.0.1:8080"
#define GRPC_PORT 50051
#define REST_PORT 8080
#define LOG_LIMIT 65536
/* The daemon resolves its audit log path from XDG state/data dirs with no
 * CLI override (--audit-storage only logs); scope HOME/XDG to the
 * per-launch control dir so the daemon and CLI helpers never touch
 * read-only or foreign paths. Called in forked children only: the
 * supervisor and application environments stay pristine. */
static void scope_xdg(void) {
    setenv("HOME",CONTROL "/home",1);
    setenv("XDG_STATE_HOME",CONTROL "/home/.local/state",1);
    setenv("XDG_DATA_HOME",CONTROL "/home/.local/share",1);
}

static volatile sig_atomic_t stopping;
static const char *label;
struct child { pid_t pid; int pipe; int out; int log; size_t written; const char *name; };
static struct child services[1] = {{0,-1,-1,-1,0,"keykeeper"}};
static pid_t application;

static int fail(const char *text) { fprintf(stderr,"p11lab-softkms: %s\n",text); return 1; }
static void erase(void *p, size_t n) { volatile unsigned char *v=p; while(n--) *v++=0; }
static void signal_handler(int sig) { stopping=sig; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (double)t.tv_sec+(double)t.tv_nsec/1e9; }
static void pause_poll(void) { struct timespec t={0,50000000}; nanosleep(&t,NULL); }
static int protected_file(int fd) {
    struct stat s;
    return fd>=0 && !fstat(fd,&s) && S_ISREG(s.st_mode) && s.st_uid==getuid() && s.st_nlink==1 && (s.st_mode&0777)==0600;
}
static int read_file(const char *path,char *out,size_t cap) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); size_t used=0;
    if(!protected_file(fd)) { if(fd>=0) close(fd); return 1; }
    while(used<cap) {
        ssize_t n=read(fd,out+used,cap-used);
        if(n<0 && errno==EINTR) continue;
        if(n<0) { close(fd); return 1; }
        if(!n) break;
        used+=(size_t)n;
    }
    if(used==cap) { close(fd); return 1; }
    close(fd);
    if(memchr(out,0,used)) return 1;
    out[used]=0; return 0;
}
static int write_file(const char *path,const void *data,size_t length,int exclusive) {
    int fd=open(path,O_WRONLY|O_NOFOLLOW|O_CLOEXEC|O_CREAT|(exclusive?O_EXCL:O_TRUNC),0600);
    size_t used=0;
    if(!protected_file(fd)) { if(fd>=0) close(fd); return 1; }
    while(used<length) {
        ssize_t n=write(fd,(const char *)data+used,length-used);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) { close(fd); return 1; }
        used+=(size_t)n;
    }
    int bad=fsync(fd); if(close(fd)) bad=1; return bad!=0;
}
static int write_text(const char *path,const char *text,int exclusive) {
    return write_file(path,text,strlen(text),exclusive);
}
static int directory(const char *path,int create) {
    struct stat s;
    if(create && mkdir(path,0700) && errno!=EEXIST) return 1;
    return lstat(path,&s) || !S_ISDIR(s.st_mode) || s.st_uid!=getuid() || (s.st_mode&0777)!=0700;
}
static int allowed(const char *name,const char *const *names) {
    for(size_t i=0;names[i];i++) if(!strcmp(name,names[i])) return 1;
    return 0;
}
static int roster(const char *path,const char *const *names) {
    DIR *d=opendir(path); struct dirent *entry; int bad=0;
    if(!d) return 1;
    errno=0;
    while((entry=readdir(d))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if(!allowed(entry->d_name,names)) { bad=1; break; }
        errno=0;
    }
    if(errno) bad=1;
    closedir(d); return bad;
}
static int is_hex(const char *s,size_t n) {
    for(size_t i=0;i<n;i++) if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return 0;
    return 1;
}
static int marker(char *output,size_t cap) {
    FILE *f=fopen("/usr/share/p11lab/runtime-id","r"); char id[66]={0};
    if(!f || !fgets(id,sizeof(id),f)) { if(f) fclose(f); return 1; }
    int extra=fgetc(f); fclose(f);
    if(strlen(id)!=65 || id[64]!='\n' || extra!=EOF || !is_hex(id,64)) return 1;
    id[64]=0;
    snprintf(output,cap,"schema=1\nprovider=softkms\nartifact=%s\nlabel=softKMS\nslot=0\n",id);
    return 0;
}
static int validate_root(void) {
    static const char *const names[]={"softkms",NULL}; struct stat s;
    if(directory(ROOT,0)) return fail("state directory is unsafe (owner or permissions)");
    if(!lstat(ROOT "/.init-lock",&s) || errno!=ENOENT) return fail("state initialization is already in progress");
    if(roster(ROOT,names)) return fail("partial state: unknown root entries");
    return 0;
}
static int sealed_secret(const char *path) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    int ok=protected_file(fd);
    if(fd>=0) close(fd);
    return ok?0:fail("provisioned credential file is unsafe");
}
static int validate_static(void) {
    static const char *const owned[]={"complete","lease","admin-secret","identity-token","storage",NULL};
    char actual[4096],expected[4096];
    /* storage/ is daemon-managed payload: only its directory binding is
     * checked statically, while salt/identity/key validity is proven
     * natively (unlock plus token login) on every operation. */
    if(directory(OWNED,0) || roster(OWNED,owned)) return fail("partial or unsafe owned state");
    if(directory(OWNED "/storage",0)) return fail("daemon storage directory is unsafe");
    if(sealed_secret(OWNED "/admin-secret") || sealed_secret(OWNED "/identity-token")) return 1;
    if(marker(expected,sizeof(expected)) || read_file(OWNED "/complete",actual,sizeof(actual)-1) || strcmp(actual,expected))
        return fail("incompatible non-secret initialization configuration");
    erase(actual,sizeof(actual)); erase(expected,sizeof(expected));
    return 0;
}
static int lease(void) {
    int fd=open(OWNED "/lease",O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if(!protected_file(fd) || flock(fd,LOCK_EX|LOCK_NB)) { if(fd>=0) close(fd); fail("state is unsafe or already in use"); return -1; }
    return fd;
}
static int exited(pid_t pid,int *code) {
    siginfo_t info; memset(&info,0,sizeof(info));
    if(waitid(P_PID,(id_t)pid,&info,WEXITED|WNOHANG|WNOWAIT)) return -1;
    if(!info.si_pid) return 0;
    *code=info.si_code==CLD_EXITED?info.si_status:128+info.si_status;
    return 1;
}
static void drain_fd(struct child *child,int fd) {
    char data[4096]; ssize_t n;
    if(fd<0) return;
    for(size_t reads=0;reads<16 && (n=read(fd,data,sizeof(data)))>0;reads++) {
        size_t keep=(size_t)n;
        if(keep>LOG_LIMIT-child->written) keep=LOG_LIMIT-child->written;
        if(keep && child->log>=0) {
            ssize_t written=write(child->log,data,keep);
            if(written>0) child->written+=(size_t)written;
        }
    }
}
static void drain(void) {
    for(size_t i=0;i<1;i++) { drain_fd(&services[i],services[i].pipe); drain_fd(&services[i],services[i].out); }
}
static int alive(void) {
    drain();
    for(size_t i=0;i<1;i++) if(services[i].pid) {
        int code=0;
        if(exited(services[i].pid,&code)!=0) { fprintf(stderr,"p11lab-softkms: required %s exited (status %d)\n",services[i].name,code); return 0; }
    }
    return !stopping;
}
static void close_child_fds(void) { for(int fd=3;fd<4096;fd++) close(fd); }
/* The keykeeper forks its key-free REST frontend itself on the fixed
 * loopback addresses; both inherit these pipes into one bounded log.
 * Fixed ports fail closed when occupied: a second daemon in the same
 * network namespace cannot bind and the operation fails loudly. */
static int launch_keykeeper(void) {
    struct child *child=&services[0];
    int outfds[2],errfds[2]; char path[256],pidtext[40];
    snprintf(path,sizeof(path),CONTROL "/%s.log",child->name);
    child->log=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    if(!protected_file(child->log) || pipe2(outfds,O_CLOEXEC) || pipe2(errfds,O_CLOEXEC))
        return fail("cannot create private bounded service logs");
    child->pid=fork();
    if(child->pid==0) {
        if(setsid()<0) _exit(126);
        int null=open("/dev/null",O_RDONLY);
        if(null<0 || dup2(null,STDIN_FILENO)<0 || dup2(outfds[1],STDOUT_FILENO)<0 || dup2(errfds[1],STDERR_FILENO)<0) _exit(126);
        close_child_fds(); scope_xdg();
        execl(DAEMON,DAEMON,"--user","--foreground","--storage-path",OWNED "/storage",
              "--pid-file",CONTROL "/softkms.pid","--grpc-addr",GRPC_ADDR,"--rest-addr",REST_ADDR,(char *)NULL);
        _exit(errno==ENOENT?127:126);
    }
    close(outfds[1]); close(errfds[1]);
    child->pipe=errfds[0]; child->out=outfds[0];
    if(child->pid<0 || fcntl(outfds[0],F_SETFL,O_NONBLOCK) || fcntl(errfds[0],F_SETFL,O_NONBLOCK)) {
        child->pid=0; close(outfds[0]); close(errfds[0]);
        return fail("cannot launch service");
    }
    snprintf(path,sizeof(path),CONTROL "/%s.pid",child->name);
    snprintf(pidtext,sizeof(pidtext),"%ld\n",(long)child->pid);
    return write_text(path,pidtext,0)?fail("cannot record owned service PID"):0;
}
static int tcp_ready(int port) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    struct timeval timeout={0,200000}; fd_set set;
    int error=0; socklen_t len=sizeof(error);
    if(fd<0) return 0;
    addr.sin_family=AF_INET; addr.sin_port=htons((uint16_t)port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(fcntl(fd,F_SETFL,O_NONBLOCK) || (connect(fd,(struct sockaddr *)&addr,sizeof(addr)) && errno!=EINPROGRESS)) { close(fd); return 0; }
    FD_ZERO(&set); FD_SET(fd,&set);
    if(select(fd+1,NULL,&set,NULL,&timeout)!=1 || getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&len) || error) { close(fd); return 0; }
    close(fd); return 1;
}
static int tcp_wait(void) {
    double deadline=now()+30;
    while(now()<deadline && alive()) {
        if(tcp_ready(GRPC_PORT) && tcp_ready(REST_PORT)) return 0;
        pause_poll();
    }
    return fail("service ports are not accepting");
}
/* Run a short helper with a kill deadline. Output is bounded and never
 * logged; only the exit status (and optional stdout match) matters. */
static int helper(const char *const *argv,double seconds,char *out,size_t cap) {
    int pipefds[2]; pid_t pid; int code=1,status=0; size_t used=0;
    double deadline=now()+seconds;
    if(pipe2(pipefds,O_CLOEXEC)) return -1;
    pid=fork();
    if(pid==0) {
        if(setsid()<0) _exit(126);
        int null=open("/dev/null",O_RDONLY);
        if(null<0 || dup2(null,STDIN_FILENO)<0 || dup2(pipefds[1],STDOUT_FILENO)<0) _exit(126);
        int log=open("/dev/null",O_WRONLY);
        if(log<0 || dup2(log,STDERR_FILENO)<0) _exit(126);
        close_child_fds(); scope_xdg(); execv(argv[0],(char *const *)argv); _exit(127);
    }
    close(pipefds[1]);
    if(pid<0) { close(pipefds[0]); return -1; }
    if(out && cap) out[0]=0;
    if(fcntl(pipefds[0],F_SETFL,O_NONBLOCK)) { kill(pid,SIGKILL); }
    else for(;;) {
        char data[1024]; ssize_t n=read(pipefds[0],data,sizeof(data));
        if(n>0 && out && cap && used<cap-1) {
            size_t keep=(size_t)n; if(keep>cap-1-used) keep=cap-1-used;
            memcpy(out+used,data,keep); used+=keep; out[used]=0;
        }
        int done=exited(pid,&code);
        if(done<0) { code=1; break; }
        if(done>0) break;
        if(stopping || now()>=deadline) { kill(-pid,SIGKILL); kill(pid,SIGKILL); code=124; }
        if(!alive()) { kill(-pid,SIGKILL); kill(pid,SIGKILL); code=1; break; }
        pause_poll();
    }
    while(waitpid(pid,&status,0)<0 && errno==EINTR) {}
    close(pipefds[0]); return code;
}
/* The health subcommand exits 0 whenever the daemon is reachable and
 * healthy, so readiness parses the exact initialized/unlocked fields
 * instead of trusting the status alone. */
static int health_state(int *initialized,int *unlocked) {
    const char *argv[]={DAEMON,"--health-check","--grpc-addr",GRPC_ADDR,"--log-level","error",NULL};
    char out[256]; char healthy[16],init[16],unl[16],version[64]; int end=-1;
    if(helper(argv,10,out,sizeof(out))) return fail("daemon health check failed");
    if(sscanf(out,"healthy=%15s initialized=%15s unlocked=%15s version=%63s%n",healthy,init,unl,version,&end)!=4
       || end<0 || out[end]!='\n' || out[end+1]!=0)
        return fail("daemon health report is malformed");
    if(strcmp(healthy,"true")) return fail("daemon is not healthy");
    if(!strcmp(init,"true")) *initialized=1; else if(!strcmp(init,"false")) *initialized=0;
    else return fail("daemon health report is malformed");
    if(!strcmp(unl,"true")) *unlocked=1; else if(!strcmp(unl,"false")) *unlocked=0;
    else return fail("daemon health report is malformed");
    if(!version[0]) return fail("daemon health report is malformed");
    erase(out,sizeof(out));
    return 0;
}
static int passphrase_valid(const char *text) {
    size_t n=strlen(text);
    if(n<32 || n>200) return 0;
    for(size_t i=0;i<n;i++) if(text[i]<' ' || text[i]>'~') return 0;
    return 1;
}
/* The entrypoint pipes exactly one '<passphrase>\n' line. Anything else
 * (missing newline, extra bytes, out-of-shape secret) fails closed. */
static int read_passphrase(char *out,size_t cap) {
    size_t used=0;
    for(;;) {
        char c; ssize_t n=read(STDIN_FILENO,&c,1);
        if(n<0 && errno==EINTR) continue;
        if(n<0) return fail("cannot read provisioned credential");
        if(!n) break;
        if(used>=cap) return fail("provisioned credential exceeds bound");
        out[used++]=c;
    }
    if(!used || out[used-1]!='\n') return fail("provisioned credential is malformed");
    out[--used]=0;
    if(memchr(out,'\r',used) || memchr(out,'\n',used) || !passphrase_valid(out)) {
        erase(out,cap);
        return fail("provisioned credential is malformed");
    }
    return 0;
}
static int token_valid(const char *text) {
    size_t n=strlen(text);
    if(n<100 || n>300) return 0;
    for(size_t i=0;i<n;i++) {
        char c=text[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')) return 0;
    }
    return 1;
}
static int start_services(void) {
    return launch_keykeeper() || tcp_wait();
}
/* The exact advertised mechanism roster, in native order. */
static const CK_MECHANISM_TYPE expected_mechs[]={
    0x1001,0x1041,0x1042,0x1043,0x1044,0x1040,0x1050,0x1057,0x1080,0x1087};
static int native(int quiet) {
    CK_FUNCTION_LIST_PTR f=NULL; CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    CK_SLOT_ID slot=0; CK_ULONG count=1; CK_INFO cinfo; CK_SLOT_INFO sinfo; CK_TOKEN_INFO info;
    CK_BYTE padded32[32],padded64[64],padded16[16];
    CK_MECHANISM_TYPE mechs[16]; CK_ULONG nmechs=16;
    char token[1024]; CK_ULONG objects=0;
    void *h=dlopen(MODULE,RTLD_NOW|RTLD_LOCAL),*symbol; int initialized=0,status=1;
    CK_SESSION_HANDLE session=0; int have_session=0;
    CK_RV rv=CKR_GENERAL_ERROR;
    if(setenv("SOFTKMS_DAEMON_ADDR",REST_ADDR,1)) return fail("cannot select owned daemon address");
    if(!h) return fail("cannot load PKCS11 module");
    symbol=dlsym(h,"C_GetFunctionList");
    _Static_assert(sizeof(symbol)==sizeof(get),"function pointer ABI"); memcpy(&get,&symbol,sizeof(get));
    if(!get || (rv=get(&f)) || !f) goto out;
    if((rv=f->C_Initialize(NULL))) goto out;
    initialized=1;
    /* P11Lab-repaired info output: every byte is deterministic. */
    memset(&cinfo,0xA5,sizeof(cinfo));
    if((rv=f->C_GetInfo(&cinfo))) goto out;
    memset(padded32,' ',sizeof(padded32));memcpy(padded32,"softKMS",7);
    memset(padded64,' ',sizeof(padded64));memcpy(padded64,"softKMS PKCS#11 Provider",24);
    if(cinfo.cryptokiVersion.major!=2 || cinfo.cryptokiVersion.minor!=40
       || memcmp(cinfo.manufacturerID,padded32,sizeof(padded32)) || cinfo.flags!=0
       || memcmp(cinfo.libraryDescription,padded64,32) || cinfo.libraryVersion.major!=0 || cinfo.libraryVersion.minor!=1) {
        fail("native library info is not ready"); goto out;
    }
    if((rv=f->C_GetSlotList(CK_TRUE,NULL,&count)) || count!=1) goto out;
    if((rv=f->C_GetSlotList(CK_TRUE,&slot,&count)) || count!=1 || slot!=0) goto out;
    memset(&sinfo,0xA5,sizeof(sinfo));
    if((rv=f->C_GetSlotInfo(slot,&sinfo))) goto out;
    memset(padded64,' ',sizeof(padded64));memcpy(padded64,"softKMS",7);
    if(sinfo.flags!=0x1UL || memcmp(sinfo.slotDescription,padded64,sizeof(padded64))
       || memcmp(sinfo.manufacturerID,padded32,sizeof(padded32))
       || sinfo.hardwareVersion.major!=1 || sinfo.hardwareVersion.minor!=0
       || sinfo.firmwareVersion.major!=1 || sinfo.firmwareVersion.minor!=0) {
        fail("native slot info is not ready"); goto out;
    }
    memset(&info,0xA5,sizeof(info));
    if((rv=f->C_GetTokenInfo(slot,&info))) goto out;
    /* Native flags: TOKEN_INITIALIZED | LOGIN_REQUIRED (standard bits, via
     * the repaired flag constants). The label is fixed. */
    memset(padded16,' ',sizeof(padded16));memcpy(padded16,"softKMS",7);
    if(memcmp(info.label,padded32,sizeof(padded32)) || info.flags!=0x404UL
       || memcmp(info.manufacturerID,padded32,sizeof(padded32))
       || memcmp(info.model,padded16,sizeof(padded16))
       || memcmp(info.serialNumber,"0000000000000000",16)
       || info.ulMaxPinLen!=256 || info.ulMinPinLen!=4
       || info.hardwareVersion.major!=1 || info.hardwareVersion.minor!=0
       || info.firmwareVersion.major!=1 || info.firmwareVersion.minor!=0
       || memcmp(info.utcTime,"0000000000000000",16)) {
        fail("native token info is not ready"); goto out;
    }
    if((rv=f->C_GetMechanismList(slot,mechs,&nmechs))) goto out;
    if(nmechs!=10 || memcmp(mechs,expected_mechs,sizeof(expected_mechs))) {
        fail("native mechanism roster is not ready"); goto out;
    }
    if((rv=f->C_OpenSession(slot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&session))) goto out;
    have_session=1;
    /* Readiness logs in with the provisioned identity token: only a real
     * login proves the daemon is unlocked and the identity is valid. */
    if(read_file(OWNED "/identity-token",token,sizeof(token)-1) || !token_valid(token)) {
        erase(token,sizeof(token));
        fail("provisioned identity token is unsafe"); goto out;
    }
    rv=f->C_Login(session,CKU_USER,(CK_UTF8CHAR_PTR)token,(CK_ULONG)strlen(token));
    erase(token,sizeof(token));
    if(rv) goto out;
    if((rv=f->C_FindObjectsInit(session,NULL,0))) goto out;
    for(;;) {
        CK_OBJECT_HANDLE page[64]; CK_ULONG got=0;
        rv=f->C_FindObjects(session,page,64,&got);
        if(rv) break;
        if(!got) break;
        objects+=got;
        if(objects>4096) { fail("native object roster exceeds bound"); goto out; }
    }
    if(rv) goto out;
    if((rv=f->C_FindObjectsFinal(session))) goto out;
    if((rv=f->C_Logout(session))) goto out;
    if((rv=f->C_CloseSession(session))) goto out;
    have_session=0;
    /* The repaired finalization invalidates sessions: an open session must
     * be unknown after C_Finalize (unpatched code keeps it usable). */
    if((rv=f->C_OpenSession(slot,CKF_SERIAL_SESSION,NULL,NULL,&session))) goto out;
    have_session=1;
    if((rv=f->C_Finalize(NULL))) goto out;
    initialized=0;
    have_session=0;
    {
        CK_SESSION_INFO sessinfo;
        rv=f->C_GetSessionInfo(session,&sessinfo);
        if(rv!=CKR_SESSION_HANDLE_INVALID) {
            fail("native finalization did not invalidate sessions"); goto out;
        }
        rv=CKR_OK;
    }
    if((rv=f->C_Initialize(NULL))) goto out;
    initialized=1;
    if((rv=f->C_Finalize(NULL))) goto out;
    initialized=0;
    if(!quiet) printf("ready: native_slot=0 token_present_index=0 label=softKMS objects=%lu\n",objects);
    status=0;
out:
    if(have_session && f) f->C_CloseSession(session);
    if(status && rv) fprintf(stderr,"p11lab-softkms: native readiness CK_RV=0x%08lx\n",rv);
    if(initialized && (rv=f->C_Finalize(NULL))) { fprintf(stderr,"C_Finalize: CK_RV=0x%08lx\n",rv);status=1; }
    erase(token,sizeof(token));
    if(h) dlclose(h);
    return status;
}
/* First-time provisioning on fresh state: the caller passphrase becomes
 * the admin secret, then one pkcs11 identity is created. The daemon must
 * report uninitialized here; anything else fails instead of adopting or
 * resetting foreign state. */
static int provision_init(void) {
    int initialized=0,unlocked=0; char pass[512]; char token[1024];
    const char *init_argv[]={CLI,"--server","http://" GRPC_ADDR,"--passphrase-file",OWNED "/admin-secret",
                             "init","--confirm","false",NULL};
    const char *id_argv[]={CLI,"--server","http://" GRPC_ADDR,"--passphrase-file",OWNED "/admin-secret",
                           "identity","create","--type","pkcs11","--description","p11lab-softkms",
                           "--token-file",CONTROL "/token",NULL};
    if(health_state(&initialized,&unlocked)) return 1;
    if(initialized || unlocked) return fail("fresh state is already initialized");
    if(read_passphrase(pass,256)) return 1;
    if(write_text(OWNED "/admin-secret",pass,1)) { erase(pass,sizeof(pass)); return fail("cannot seal admin secret"); }
    erase(pass,sizeof(pass));
    if(helper(init_argv,60,NULL,0)) return fail("keystore initialization failed");
    if(health_state(&initialized,&unlocked)) return 1;
    if(!initialized || !unlocked) return fail("keystore did not unlock after initialization");
    if(helper(id_argv,30,NULL,0)) return fail("identity provisioning failed");
    if(read_file(CONTROL "/token",token,sizeof(token)-1) || !token_valid(token)) {
        erase(token,sizeof(token));
        return fail("provisioned identity token is malformed");
    }
    if(write_text(OWNED "/identity-token",token,1)) { erase(token,sizeof(token)); return fail("cannot seal identity token"); }
    erase(token,sizeof(token));
    unlink(CONTROL "/token");
    return native(1);
}
/* Existing state: unlock with the persisted admin secret when locked.
 * Uninitialized storage is refused; initialization never happens here. */
static int provision_operational(int quiet) {
    int initialized=0,unlocked=0;
    const char *unlock_argv[]={CLI,"--server","http://" GRPC_ADDR,"--passphrase-file",OWNED "/admin-secret",
                               "unlock",NULL};
    if(health_state(&initialized,&unlocked)) return 1;
    if(!initialized) return fail("daemon storage is not initialized");
    if(!unlocked) {
        if(helper(unlock_argv,60,NULL,0)) return fail("keystore unlock failed");
        if(health_state(&initialized,&unlocked)) return 1;
        if(!initialized || !unlocked) return fail("keystore did not unlock");
    }
    return native(quiet);
}
static void signal_groups(int sig) {
    if(application>0) kill(-application,sig);
    for(size_t i=0;i<1;i++) if(services[i].pid>0) kill(-services[i].pid,sig);
}
static void signal_adopted(int sig) {
    char path[128];snprintf(path,sizeof(path),"/proc/self/task/%ld/children",(long)getpid());
    FILE *f=fopen(path,"r"); long pid;
    if(!f) return;
    /* Only this supervisor reaps its children. Each listed PID stays owned,
     * including an unreaped zombie, until the following reap step. */
    while(fscanf(f,"%ld",&pid)==1) if(pid>1) kill((pid_t)pid,sig);
    fclose(f);
}
static void cleanup(void) {
    signal_groups(SIGTERM);
    double deadline=now()+5; int status;
    while(now()<deadline) {
        drain();signal_adopted(SIGTERM);
        pid_t pid;
        while((pid=waitpid(-1,&status,WNOHANG))>0) {
            if(pid==application) application=0;
            for(size_t i=0;i<1;i++) if(pid==services[i].pid) services[i].pid=0;
        }
        if(pid<0 && errno==ECHILD) break;
        pause_poll();
    }
    signal_groups(SIGKILL);signal_adopted(SIGKILL);
    while(waitpid(-1,&status,0)>0 || errno==EINTR) { drain();signal_adopted(SIGKILL); }
    drain();
    for(size_t i=0;i<1;i++) {
        char path[256];snprintf(path,sizeof(path),CONTROL "/%s.pid",services[i].name);unlink(path);
        if(services[i].pipe>=0) close(services[i].pipe);
        if(services[i].out>=0) close(services[i].out);
        if(services[i].log>=0) close(services[i].log);
    }
    unlink(CONTROL "/softkms.pid");
    unlink(CONTROL "/token");
}
static int initialize(void) {
    char text[4096];
    if(write_text(OWNED "/lease","",1)) return fail("cannot create private native state");
    if(directory(OWNED "/storage",1)) return fail("cannot create daemon storage directory");
    if(start_services() || provision_init()) return 1;
    int bad=0;
    if(marker(text,sizeof(text)) || write_text(OWNED "/.complete",text,1) || rename(OWNED "/.complete",OWNED "/complete")) bad=fail("cannot seal completion marker");
    erase(text,sizeof(text));
    return bad;
}
static int operational(int quiet) {
    return start_services() || provision_operational(quiet);
}
int main(int argc,char **argv) {
    int status=1,leasefd=-1,controlfd=-1,init_lock=0;
    struct stat s;
    umask(077);label=getenv("P11LAB_LABEL");
    if(argc<2 || !label || strcmp(label,"softKMS")) return 2;
    if(getenv("SOFTKMS_DAEMON_ADDR")) return fail("unsupported native override: SOFTKMS_DAEMON_ADDR");
    if(validate_root()) return 1;
    int absent=lstat(OWNED,&s)!=0 && errno==ENOENT;
    if(!strcmp(argv[1],"existing")) {
        if(absent) return 10;
        if(directory(OWNED,0)) return fail("unsafe owned state directory");
        leasefd=lease();if(leasefd<0) return 1;
        status=validate_static();close(leasefd);return status;
    }
    int init=!strcmp(argv[1],"init"),exec=!strcmp(argv[1],"exec");
    if((!init && !exec && strcmp(argv[1],"health")) || (exec && (argc<4 || strcmp(argv[2],"--")))) return 2;
    if(init) {
        if(!absent) return fail("refusing initialization: occupied state");
        if(mkdir(ROOT "/.init-lock",0700)) return fail("state initialization is already in progress");
        init_lock=1;
        if(mkdir(OWNED,0700)) goto out;
    } else {
        if(absent || directory(OWNED,0) || (leasefd=lease())<0 || validate_static()) goto out;
    }
    if(directory("/run/p11lab",0) || directory(CONTROL,1)) { fail("unsafe private control directory");goto out; }
    controlfd=open(CONTROL "/service-lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(!protected_file(controlfd) || flock(controlfd,LOCK_EX|LOCK_NB)) { fail("service control is already in use");goto out; }
    struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_handler=signal_handler;sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM,&sa,NULL);sigaction(SIGINT,&sa,NULL);sigaction(SIGHUP,&sa,NULL);
    if(prctl(PR_SET_CHILD_SUBREAPER,1)) goto out;
    if(init) status=initialize();
    else if(!operational(exec)) {
        if(!exec) status=0;
        else {
            if(setenv("SOFTKMS_DAEMON_ADDR",REST_ADDR,1)) status=fail("cannot select owned daemon address");
            else {
                application=fork();
                if(application==0) { if(setsid()<0) _exit(126);close_child_fds();execvp(argv[3],argv+3);_exit(errno==ENOENT?127:126); }
                if(application<0) { application=0;status=fail("cannot launch application"); }
                else {
                    while(alive()) {
                        int code=1;int result=exited(application,&code);
                        if(result>0) { status=code;break; }
                        if(result<0) { status=fail("cannot observe application status");break; }
                        pause_poll();
                    }
                }
            }
        }
    }
out:
    cleanup();
    if(init_lock && rmdir(ROOT "/.init-lock")) status=fail("cannot remove owned initialization lock");
    if(leasefd>=0) close(leasefd);
    if(controlfd>=0) close(controlfd);
    return stopping?128+stopping:status;
}
