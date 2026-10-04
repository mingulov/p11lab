/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab offline provisioning, static validation and Linux
 * supervision for the Google kmsp11 client against a co-located fakekms.
 * Native PKCS#11 calls, service responses and application status are
 * preserved. This qualifies the CLIENT against an in-memory mock; it never
 * qualifies Cloud KMS.
 *
 * fakekms is memory-only: every operation launches a fresh instance on an
 * OS-ephemeral loopback port (printed to stdout), provisions the keyring
 * plus one SOFTWARE key per algorithm class through the bounded Go helper,
 * then gates native readiness on the exact provisioned roster. Provisioning
 * recreates every key per launch, but upstream fakekms semantics are mixed:
 * RSA keys are fixed pregenerated test vectors (rsaKeyFactory loads
 * testdata/rsa_*_private.pem), while EC and HMAC keys draw fresh
 * crypto/rand material per launch. All fake behavior, never real-KMS claims.
 *
 * The module ignores any caller PIN natively (C_Login CKU_USER accepts any
 * value, even empty); the adapter still requires a well-formed credential
 * input by shared contract but no PIN ever reaches this supervisor. There
 * is no security-officer role: the token presents SO as PIN-locked and
 * C_Login(CKU_SO) is natively CKR_PIN_LOCKED, so no SO credential exists.
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
#define OWNED ROOT "/kmsp11-fakekms"
#define CONTROL "/run/p11lab/kmsp11"
#define MODULE "/usr/local/lib/p11lab/libkmsp11.so"
#define BINDIR "/usr/local/bin"
#define CONFIG CONTROL "/config.yaml"
#define KEYRING_ID "p11lab"
#define KEYRING "projects/p/locations/global/keyRings/" KEYRING_ID
#define LOG_LIMIT 65536
#define PORT_LINE_LIMIT 256

static volatile sig_atomic_t stopping;
static const char *label;
static char endpoint[32];
struct child { pid_t pid; int pipe; int out; int log; size_t written; const char *name; };
static struct child services[1] = {{0,-1,-1,-1,0,"fakekms"}};
static pid_t application;

static int fail(const char *text) { fprintf(stderr,"p11lab-kmsp11: %s\n",text); return 1; }
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
static int label_valid(const char *text) {
    size_t n=strlen(text);
    if(!n || n>32) return 0;
    for(size_t i=0;i<n;i++) {
        char c=text[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c==' '||c=='.'||c=='_'||c=='-')) return 0;
    }
    return 1;
}
static int marker(char *output,size_t cap) {
    FILE *f=fopen("/usr/share/p11lab/runtime-id","r"); char id[66]={0};
    if(!f || !fgets(id,sizeof(id),f)) { if(f) fclose(f); return 1; }
    int extra=fgetc(f); fclose(f);
    if(strlen(id)!=65 || id[64]!='\n' || extra!=EOF || !is_hex(id,64)) return 1;
    id[64]=0;
    snprintf(output,cap,"schema=1\nprovider=kmsp11-fakekms\nartifact=%s\nlabel=%s\nslot=0\nkeyring=" KEYRING "\n",id,label);
    return 0;
}
static int validate_root(void) {
    static const char *const names[]={"kmsp11-fakekms",NULL}; struct stat s;
    if(directory(ROOT,0)) return fail("state directory is unsafe (owner or permissions)");
    if(!lstat(ROOT "/.init-lock",&s) || errno!=ENOENT) return fail("state initialization is already in progress");
    if(roster(ROOT,names)) return fail("partial state: unknown root entries");
    return 0;
}
static int validate_static(void) {
    static const char *const owned[]={"complete","lease",NULL};
    char actual[4096],expected[4096];
    /* The libkmsp11 config carries the per-launch ephemeral endpoint, so it
     * lives under the private control directory and is regenerated every
     * launch; only the marker and lease persist. */
    if(directory(OWNED,0) || roster(OWNED,owned)) return fail("partial or unsafe owned state");
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
        if(exited(services[i].pid,&code)!=0) { fprintf(stderr,"p11lab-kmsp11: required %s exited (status %d)\n",services[i].name,code); return 0; }
    }
    return !stopping;
}
static void close_child_fds(void) { for(int fd=3;fd<4096;fd++) close(fd); }
/* fakekms takes no arguments and prints its ephemeral address to stdout.
 * stdout is parsed (strictly) while stderr joins the bounded service log;
 * a printed address alone never gates readiness. */
static int launch_fakekms(void) {
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
        if(setenv("GOMAXPROCS","2",1)) _exit(126);
        close_child_fds();
        execl(BINDIR "/fakekms",BINDIR "/fakekms",(char *)NULL);
        _exit(errno==ENOENT?127:126);
    }
    close(outfds[1]); close(errfds[1]);
    /* Keep stderr on the drain pipe; stdout is parsed below, then drained. */
    child->pipe=errfds[0];
    if(child->pid<0 || fcntl(outfds[0],F_SETFL,O_NONBLOCK) || fcntl(errfds[0],F_SETFL,O_NONBLOCK)) {
        child->pid=0; close(outfds[0]); close(errfds[0]);
        return fail("cannot launch service");
    }
    /* Strictly parse the first stdout line: 127.0.0.1:<port>. Anything else
     * (extra text, another interface, out-of-range port) fails loudly. */
    double deadline=now()+30; size_t used=0; int done=0;
    char line[PORT_LINE_LIMIT+1];
    while(now()<deadline && !stopping && !done) {
        char c; ssize_t n=read(outfds[0],&c,1);
        if(n>0) {
            if(c=='\n') done=1;
            else if(used<PORT_LINE_LIMIT) line[used++]=c;
            else { close(outfds[0]); return fail("fakekms printed an overlong address line"); }
        } else if(!n) {
            int code=0;
            if(exited(child->pid,&code)>0) { close(outfds[0]); fprintf(stderr,"p11lab-kmsp11: required fakekms exited (status %d)\n",code); return 1; }
            pause_poll();
        } else if(errno!=EAGAIN && errno!=EINTR) { close(outfds[0]); return fail("cannot read service address"); }
        else {
            int code=0;
            if(exited(child->pid,&code)>0) { close(outfds[0]); fprintf(stderr,"p11lab-kmsp11: required fakekms exited (status %d)\n",code); return 1; }
            pause_poll();
        }
        drain();
    }
    if(!done) { close(outfds[0]); return fail("fakekms address deadline or required service failure"); }
    line[used]=0;
    unsigned port=0;
    if(sscanf(line,"127.0.0.1:%u",&port)!=1 || !port || port>65535) { close(outfds[0]); return fail("fakekms printed a non-loopback or invalid address"); }
    char canonical[32];
    snprintf(canonical,sizeof(canonical),"127.0.0.1:%u",port);
    if(strcmp(line,canonical)) { close(outfds[0]); return fail("fakekms printed a non-canonical address"); }
    snprintf(endpoint,sizeof(endpoint),"%s",canonical);
    /* Remaining stdout (none expected) joins the drain; the read end stays
     * open for the service lifetime so the child never sees SIGPIPE. */
    child->out=outfds[0];
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
        if(setenv("GOMAXPROCS","2",1)) _exit(126);
        close_child_fds(); execv(argv[0],(char *const *)argv); _exit(127);
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
/* Readiness beyond "printed an address": the helper performs a real gRPC
 * ListKeyRings round-trip, then provisions the keyring and keys. */
static int bootstrap(void) {
    const char *argv[]={BINDIR "/p11lab-kmsp11-bootstrap",endpoint,KEYRING_ID,NULL};
    char out[512];
    int code=helper(argv,150,out,sizeof(out));
    if(code) { fprintf(stderr,"p11lab-kmsp11: key provisioning failed (status %d)\n",code); return 1; }
    if(strcmp(out,KEYRING "\n")) return fail("provisioning reported an unexpected keyring");
    return 0;
}
static int write_config(void) {
    char text[1024];
    int n=snprintf(text,sizeof(text),"tokens:\n  - key_ring: \"" KEYRING "\"\n    label: \"%s\"\nkms_endpoint: \"%s\"\nuse_insecure_grpc_channel_credentials: true\nallow_software_keys: true\n",
        label,endpoint);
    if(n<0 || (size_t)n>=sizeof(text)) return fail("cannot render module configuration");
    /* libkmsp11 rejects group/other-writable config (EnsureWriteProtected). */
    return write_text(CONFIG,text,0)?fail("cannot write private module configuration"):0;
}
static int start_services(void) {
    if(launch_fakekms()) return 1;
    unsigned port=0;
    if(sscanf(endpoint,"127.0.0.1:%u",&port)!=1 || !tcp_ready((int)port)) return fail("service port is not accepting");
    /* A printed address plus an accepted TCP handshake still never gates
     * readiness alone; bootstrap() proves a real gRPC round-trip. */
    return bootstrap() || write_config();
}
/* Expected provisioned roster: five asymmetric pairs plus one HMAC secret. */
static const char *const expected_labels[]={
    "rsa-sign-pkcs1-2048","rsa-sign-pss-2048","ec-sign-p256","ec-sign-p384",
    "rsa-decrypt-oaep-2048","hmac-sha256",NULL};
static int native(int quiet) {
    CK_FUNCTION_LIST_PTR f=NULL; CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    CK_SLOT_ID slot=0; CK_ULONG count=1; CK_TOKEN_INFO info; CK_BYTE padded[32];
    CK_MECHANISM_TYPE mechs[64]; CK_ULONG nmechs=64; int ecdsa=0;
    void *h=dlopen(MODULE,RTLD_NOW|RTLD_LOCAL),*symbol; int initialized=0,status=1;
    CK_SESSION_HANDLE session=0; int have_session=0;
    CK_RV rv=CKR_GENERAL_ERROR;
    if(setenv("KMS_PKCS11_CONFIG",CONFIG,1)) return fail("cannot select owned module configuration");
    if(!h) return fail("cannot load PKCS11 module");
    symbol=dlsym(h,"C_GetFunctionList");
    _Static_assert(sizeof(symbol)==sizeof(get),"function pointer ABI"); memcpy(&get,&symbol,sizeof(get));
    if(!get || (rv=get(&f)) || !f) goto out;
    if((rv=f->C_Initialize(NULL))) goto out;
    initialized=1;
    if((rv=f->C_GetSlotList(CK_TRUE,NULL,&count)) || count!=1) goto out;
    if((rv=f->C_GetSlotList(CK_TRUE,&slot,&count)) || count!=1 || slot!=0) goto out;
    if((rv=f->C_GetTokenInfo(slot,&info))) goto out;
    memset(padded,' ',sizeof(padded));memcpy(padded,label,strlen(label));
    /* Native flags: RNG | USER_PIN_INITIALIZED | TOKEN_INITIALIZED |
     * SO_PIN_LOCKED. LOGIN_REQUIRED is natively absent (login optional). */
    if(memcmp(info.label,padded,sizeof(padded)) || info.flags!=0x400409UL) {
        fail("native token flags or label are not ready"); goto out;
    }
    if((rv=f->C_GetMechanismList(slot,mechs,&nmechs))) goto out;
    /* The native roster is exactly 46 entries: 24 zero values (23 from an
     * upstream vector-size/push_back mistake plus the genuine
     * CKM_RSA_PKCS_KEY_PAIR_GEN 0x0) and 22 distinct nonzero mechanisms.
     * Preserved as observed; readiness gates the exact count plus ECDSA. */
    if(nmechs!=46) { fail("native mechanism roster is not ready"); goto out; }
    for(CK_ULONG i=0;i<nmechs;i++) if(mechs[i]==CKM_ECDSA) ecdsa=1;
    if(!ecdsa) { fail("native ECDSA signing mechanism is not ready"); goto out; }
    if((rv=f->C_OpenSession(slot,CKF_SERIAL_SESSION,NULL,NULL,&session))) goto out;
    have_session=1;
    CK_OBJECT_HANDLE objs[32]; CK_ULONG found=0;
    if((rv=f->C_FindObjectsInit(session,NULL,0))) goto out;
    rv=f->C_FindObjects(session,objs,32,&found);
    CK_RV final_rv=f->C_FindObjectsFinal(session);
    if(rv) goto out;
    if(final_rv) { rv=final_rv; goto out; }
    if(found!=11) { fail("native provisioned object roster is not ready"); goto out; }
    int seen[6]={0,0,0,0,0,0};
    for(CK_ULONG i=0;i<found;i++) {
        char name[128]; CK_ATTRIBUTE attr={CKA_LABEL,name,sizeof(name)-1};
        if((rv=f->C_GetAttributeValue(session,objs[i],&attr,1))) goto out;
        if(attr.ulValueLen>=(CK_ULONG)sizeof(name)) { fail("native object label is not ready"); goto out; }
        name[attr.ulValueLen]=0;
        int hit=-1;
        for(int k=0;expected_labels[k];k++) if(!strcmp(name,expected_labels[k])) hit=k;
        if(hit<0) { fail("native object roster carries an unexpected label"); goto out; }
        seen[hit]++;
    }
    /* Five asymmetric pairs expose two objects each; HMAC exposes one. */
    if(seen[0]!=2 || seen[1]!=2 || seen[2]!=2 || seen[3]!=2 || seen[4]!=2 || seen[5]!=1) {
        fail("native provisioned object roster is not ready"); goto out;
    }
    /* Readiness never logs in: unlocking is caller authentication and must
     * not happen behind health checks or other applications. */
    if(!quiet) printf("ready: native_slot=0 token_present_index=0 label=%s keys=6 objects=11\n",label);
    status=0;
out:
    if(have_session && f) f->C_CloseSession(session);
    if(status && rv) fprintf(stderr,"p11lab-kmsp11: native readiness CK_RV=0x%08lx\n",rv);
    if(initialized && (rv=f->C_Finalize(NULL))) { fprintf(stderr,"C_Finalize: CK_RV=0x%08lx\n",rv);status=1; }
    if(h) dlclose(h);
    return status;
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
    unlink(CONFIG);
}
static int initialize(void) {
    char text[4096];
    if(write_text(OWNED "/lease","",1)) return fail("cannot create private native state");
    if(start_services() || native(1)) return 1;
    int bad=0;
    if(marker(text,sizeof(text)) || write_text(OWNED "/.complete",text,1) || rename(OWNED "/.complete",OWNED "/complete")) bad=fail("cannot seal completion marker");
    erase(text,sizeof(text));
    return bad;
}
static int operational(int quiet) {
    return start_services() || native(quiet);
}
int main(int argc,char **argv) {
    int status=1,leasefd=-1,controlfd=-1,init_lock=0;
    struct stat s;
    umask(077);label=getenv("P11LAB_LABEL");
    if(argc<2 || !label || !label_valid(label)) return 2;
    if(getenv("KMS_PKCS11_CONFIG")) return fail("unsupported native override: KMS_PKCS11_CONFIG");
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
out:
    cleanup();
    if(init_lock && rmdir(ROOT "/.init-lock")) status=fail("cannot remove owned initialization lock");
    if(leasefd>=0) close(leasefd);
    if(controlfd>=0) close(controlfd);
    return stopping?128+stopping:status;
}
