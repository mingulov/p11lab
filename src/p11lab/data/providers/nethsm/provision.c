/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab HTTPS provisioning, static validation and Linux supervision.
 * Native PKCS#11 calls, server responses and application status are preserved.
 */
#define _GNU_SOURCE
#include <p11-kit/pkcs11.h>
#include <curl/curl.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROOT "/var/lib/p11lab"
#define OWNED ROOT "/nethsm"
#define CONTROL "/run/p11lab/nethsm"
#define MODULE "/usr/local/lib/p11lab/libnethsm_pkcs11.so"
#define API "https://127.0.0.1:8443/api/v1"
#define LOG_LIMIT 65536

static volatile sig_atomic_t stopping;
static const char *label;
static char admin[201], unlock[201];
struct child { pid_t pid; int pipe; int log; size_t written; const char *name; };
static struct child services[2] = {{0,-1,-1,0,"etcd"},{0,-1,-1,0,"keyfender"}};
static pid_t application;

static int fail(const char *text) { fprintf(stderr,"p11lab-nethsm: %s\n",text); return 1; }
static void erase(void *p, size_t n) { volatile unsigned char *v=p; while(n--) *v++=0; }
static void signal_handler(int sig) { stopping=sig; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (double)t.tv_sec+(double)t.tv_nsec/1e9; }
static void pause_poll(void) { struct timespec t={0,50000000}; nanosleep(&t,NULL); }
static int secret_valid(const char *text) {
    size_t n=strlen(text);
    if(n<10 || n>200) return 0;
    for(size_t i=0;i<n;i++) if((unsigned char)text[i]<32 || (unsigned char)text[i]>126) return 0;
    return 1;
}
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
static int write_file(const char *path,const char *text,int exclusive) {
    int fd=open(path,O_WRONLY|O_NOFOLLOW|O_CLOEXEC|O_CREAT|(exclusive?O_EXCL:O_TRUNC),0600);
    size_t length=strlen(text),used=0;
    if(!protected_file(fd)) { if(fd>=0) close(fd); return 1; }
    while(used<length) {
        ssize_t n=write(fd,text+used,length-used);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) { close(fd); return 1; }
        used+=(size_t)n;
    }
    int bad=fsync(fd); if(close(fd)) bad=1; return bad!=0;
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
static int data_files(const char *path,int wal) {
    DIR *d=opendir(path); struct dirent *e; int bad=0,found=0; char file[512];
    if(!d) return 1;
    errno=0;
    while((e=readdir(d))) {
        if(!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        size_t n=strlen(e->d_name);
        int expected=(n==(wal?37U:38U) && is_hex(e->d_name,16) && e->d_name[16]=='-' && is_hex(e->d_name+17,16) && !strcmp(e->d_name+33,wal?".wal":".snap"));
        if(!wal && !strcmp(e->d_name,"db")) expected=1;
        if(!expected) { bad=1; break; }
        snprintf(file,sizeof(file),"%s/%s",path,e->d_name);
        int fd=open(file,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat s;
        if(!protected_file(fd) || fstat(fd,&s) || s.st_size<4096) { if(fd>=0) close(fd); bad=1; break; }
        if(!wal && !strcmp(e->d_name,"db")) {
            unsigned char header[20];
            /* Observed native bbolt little-endian magic 0xed0cdaed. */
            if(pread(fd,header,sizeof(header),0)!=(ssize_t)sizeof(header) || memcmp(header+16,"\xed\xda\x0c\xed",4)) bad=1;
            found=1;
        } else if(wal) found=1;
        close(fd); if(bad) break;
        errno=0;
    }
    if(errno) bad=1;
    closedir(d); return bad || !found;
}
static void quote(const char *input,char *output,size_t cap) {
    size_t j=0; output[j++]='"';
    for(size_t i=0;input[i];i++) {
        if(j+3>=cap) abort();
        if(input[i]=='"' || input[i]=='\\') output[j++]='\\';
        output[j++]=input[i];
    }
    output[j++]='"'; output[j]=0;
}
static void config(char *output,size_t cap) {
    char quoted[403]; quote(admin,quoted,sizeof(quoted));
    snprintf(output,cap,"log_level: Error\nslots:\n  - label: \"%s\"\n    operator:\n      username: \"operator\"\n    administrator:\n      username: \"admin\"\n      password: %s\n    retries:\n      count: 0\n      delay_seconds: 0\n    timeout_seconds: 5\n    instances:\n      - url: \"" API "\"\n        danger_insecure_cert: true\n",label,quoted);
    erase(quoted,sizeof(quoted));
}
static int marker(char *output,size_t cap) {
    FILE *f=fopen("/usr/share/p11lab/runtime-id","r"); char id[66]={0};
    if(!f || !fgets(id,sizeof(id),f)) { if(f) fclose(f); return 1; }
    int extra=fgetc(f); fclose(f);
    if(strlen(id)!=65 || id[64]!='\n' || extra!=EOF || !is_hex(id,64)) return 1;
    id[64]=0;
    snprintf(output,cap,"schema=1\nprovider=nethsm\nartifact=%s\nlabel=%s\nslot=0\nserver=frozen-binary\n",id,label);
    return 0;
}
static int validate_root(void) {
    static const char *const names[]={"nethsm",NULL}; struct stat s;
    if(directory(ROOT,0)) return fail("state directory is unsafe (owner or permissions)");
    if(!lstat(ROOT "/.init-lock",&s) || errno!=ENOENT) return fail("state initialization is already in progress");
    if(roster(ROOT,names)) return fail("partial state: unknown root entries");
    return 0;
}
static int validate_static(void) {
    static const char *const owned[]={"complete","p11nethsm.conf","admin","unlock","lease","data",NULL};
    static const char *const data[]={"member",NULL};
    static const char *const member[]={"snap","wal",NULL};
    char actual[2048],expected[2048];
    if(directory(OWNED,0) || roster(OWNED,owned) || read_file(OWNED "/admin",admin,sizeof(admin)) ||
       read_file(OWNED "/unlock",unlock,sizeof(unlock)) || !secret_valid(admin) || !secret_valid(unlock))
        return fail("partial or unsafe credential/configuration state");
    if(marker(expected,sizeof(expected)) || read_file(OWNED "/complete",actual,sizeof(actual)-1) || strcmp(actual,expected))
        return fail("incompatible non-secret initialization configuration");
    config(expected,sizeof(expected));
    int bad=read_file(OWNED "/p11nethsm.conf",actual,sizeof(actual)-1) || strcmp(actual,expected);
    erase(actual,sizeof(actual)); erase(expected,sizeof(expected));
    if(bad) return fail("incompatible module configuration");
    if(directory(OWNED "/data",0) || roster(OWNED "/data",data) || directory(OWNED "/data/member",0) ||
       roster(OWNED "/data/member",member) || directory(OWNED "/data/member/snap",0) || directory(OWNED "/data/member/wal",0) ||
       data_files(OWNED "/data/member/snap",0) || data_files(OWNED "/data/member/wal",1))
        return fail("partial or unsafe native etcd data");
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
static void drain(void) {
    char data[4096];
    for(size_t i=0;i<2;i++) {
        if(services[i].pipe<0) continue;
        ssize_t n;
        for(size_t reads=0;reads<16 && (n=read(services[i].pipe,data,sizeof(data)))>0;reads++) {
            size_t keep=(size_t)n;
            if(keep>LOG_LIMIT-services[i].written) keep=LOG_LIMIT-services[i].written;
            if(keep && services[i].log>=0) {
                ssize_t written=write(services[i].log,data,keep);
                if(written>0) services[i].written+=(size_t)written;
            }
        }
    }
}
static int alive(void) {
    drain();
    for(size_t i=0;i<2;i++) if(services[i].pid) {
        int code=0;
        if(exited(services[i].pid,&code)!=0) { fprintf(stderr,"p11lab-nethsm: required %s exited (status %d)\n",services[i].name,code); return 0; }
    }
    return !stopping;
}
static void close_child_fds(void) { for(int fd=3;fd<4096;fd++) close(fd); }
static int launch(struct child *child,const char *const *argv) {
    int pipefds[2]; char path[256],pidtext[40];
    snprintf(path,sizeof(path),CONTROL "/%s.log",child->name);
    child->log=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    if(!protected_file(child->log) || pipe2(pipefds,O_CLOEXEC)) return fail("cannot create private bounded service logs");
    child->pid=fork();
    if(child->pid==0) {
        if(setsid()<0) _exit(126);
        int null=open("/dev/null",O_RDONLY);
        if(null<0 || dup2(null,STDIN_FILENO)<0 || dup2(pipefds[1],STDOUT_FILENO)<0 || dup2(pipefds[1],STDERR_FILENO)<0) _exit(126);
        close_child_fds(); execv(argv[0],(char *const *)argv); _exit(127);
    }
    close(pipefds[1]); child->pipe=pipefds[0];
    if(child->pid<0 || fcntl(child->pipe,F_SETFL,O_NONBLOCK)) { child->pid=0; return fail("cannot launch service"); }
    snprintf(path,sizeof(path),CONTROL "/%s.pid",child->name);
    snprintf(pidtext,sizeof(pidtext),"%ld\n",(long)child->pid);
    return write_file(path,pidtext,0)?fail("cannot record owned service PID"):0;
}
struct response { char text[8193]; size_t used; };
static size_t receive(char *data,size_t size,size_t count,void *context) {
    struct response *r=context;
    if(size && count>SIZE_MAX/size) return 0;
    size_t n=size*count;
    if(n>sizeof(r->text)-1-r->used) return 0;
    memcpy(r->text+r->used,data,n); r->used+=n; r->text[r->used]=0; return n;
}
static long request(const char *url,const char *method,const char *body,int authenticate,struct response *response) {
    CURL *curl=curl_easy_init(); long code=0; struct curl_slist *headers=NULL;
    memset(response,0,sizeof(*response));
    if(!curl) return 0;
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,method);
    curl_easy_setopt(curl,CURLOPT_PROXY,"");
    curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT_MS,300L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS,1500L);
    curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,receive);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,response);
    if(authenticate) { curl_easy_setopt(curl,CURLOPT_USERNAME,"admin"); curl_easy_setopt(curl,CURLOPT_PASSWORD,admin); }
    if(body) {
        headers=curl_slist_append(headers,"Content-Type: application/json");
        curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
        curl_easy_setopt(curl,CURLOPT_POSTFIELDS,body);
    }
    CURLcode result=curl_easy_perform(curl);
    if(result==CURLE_OK) curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code);
    curl_slist_free_all(headers); curl_easy_cleanup(curl); return code;
}
static int state(char *out,size_t cap) {
    struct response r;
    if(request(API "/health/state","GET",NULL,0,&r)!=200) return 1;
    static const char *const states[]={"Unprovisioned","Operational","Locked","Failed",NULL};
    for(size_t i=0;states[i];i++) {
        char expected[80]; snprintf(expected,sizeof(expected),"{\"state\":\"%s\"}",states[i]);
        if(!strcmp(r.text,expected)) { snprintf(out,cap,"%s",states[i]); return 0; }
    }
    return 1;
}
static int post(const char *endpoint,const char *method,const char *body,int auth) {
    struct response r; char url[256]; snprintf(url,sizeof(url),API "%s",endpoint);
    long code=request(url,method,body,auth,&r); erase(&r,sizeof(r));
    if(code!=200 && code!=201 && code!=204) { fprintf(stderr,"p11lab-nethsm: native %s HTTP %ld; partial state retained\n",endpoint,code); return 1; }
    return 0;
}
static int wait_state(char *out,int initial) {
    double deadline=now()+60;
    while(now()<deadline && alive()) {
        if(!state(out,32) && (!strcmp(out,"Operational") || (initial && (!strcmp(out,"Unprovisioned") || !strcmp(out,"Locked"))))) return 0;
        pause_poll();
    }
    return fail("API readiness deadline or required service failure");
}
static int start_services(void) {
    static const char *const etcd[]={"/usr/local/bin/etcd","--name","default","--listen-client-urls","http://127.0.0.1:2379",
        "--advertise-client-urls","http://127.0.0.1:2379","--listen-peer-urls","http://127.0.0.1:2380",
        "--initial-advertise-peer-urls","http://127.0.0.1:2380","--initial-cluster","default=http://127.0.0.1:2380",
        "--host-whitelist","127.0.0.1","--max-txn-ops","512","--log-level","error","--data-dir",OWNED "/data",NULL};
    static const char *const keyfender[]={"/usr/local/bin/keyfender","--internal-ipv4=127.0.0.1/32","--internal-ipv4-only=true",
        "--http=8080","--https=8443","--platform=127.0.0.1","--logs=*:error","--start",NULL};
    return launch(&services[0],etcd) || launch(&services[1],keyfender);
}
static int native(int quiet) {
    CK_FUNCTION_LIST_PTR f=NULL; CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    CK_SLOT_ID slot=0; CK_ULONG count=1; CK_TOKEN_INFO info; CK_BYTE padded[32];
    void *h=dlopen(MODULE,RTLD_NOW|RTLD_LOCAL),*symbol; int initialized=0,status=1;
    CK_RV rv=CKR_GENERAL_ERROR;
    if(!h) return fail("cannot load musl PKCS11 module");
    symbol=dlsym(h,"C_GetFunctionList");
    _Static_assert(sizeof(symbol)==sizeof(get),"function pointer ABI"); memcpy(&get,&symbol,sizeof(get));
    if(!get || (rv=get(&f)) || !f) goto out;
    if((rv=f->C_Initialize(NULL))) goto out;
    initialized=1;
    if((rv=f->C_GetSlotList(CK_TRUE,NULL,&count)) || count!=1) goto out;
    if((rv=f->C_GetSlotList(CK_TRUE,&slot,&count)) || count!=1 || slot!=0) goto out;
    if((rv=f->C_GetTokenInfo(slot,&info))) goto out;
    memset(padded,' ',sizeof(padded));memcpy(padded,label,strlen(label));
    if(memcmp(info.label,padded,sizeof(padded)) || (info.flags&(CKF_TOKEN_INITIALIZED|CKF_USER_PIN_INITIALIZED))!=(CKF_TOKEN_INITIALIZED|CKF_USER_PIN_INITIALIZED)) {
        fail("native token flags or label are not ready"); goto out;
    }
    if(!quiet) printf("ready: native_slot=0 token_present_index=0 label=%s server=Operational\n",label);
    status=0;
out:
    if(status && rv) fprintf(stderr,"p11lab-nethsm: native readiness CK_RV=0x%08lx\n",rv);
    if(initialized && (rv=f->C_Finalize(NULL))) { fprintf(stderr,"C_Finalize: CK_RV=0x%08lx\n",rv);status=1; }
    dlclose(h);return status;
}
static void signal_groups(int sig) {
    if(application>0) kill(-application,sig);
    for(size_t i=0;i<2;i++) if(services[i].pid>0) kill(-services[i].pid,sig);
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
            for(size_t i=0;i<2;i++) if(pid==services[i].pid) services[i].pid=0;
        }
        if(pid<0 && errno==ECHILD) break;
        pause_poll();
    }
    signal_groups(SIGKILL);signal_adopted(SIGKILL);
    while(waitpid(-1,&status,0)>0 || errno==EINTR) { drain();signal_adopted(SIGKILL); }
    drain();
    for(size_t i=0;i<2;i++) {
        char path[256];snprintf(path,sizeof(path),CONTROL "/%s.pid",services[i].name);unlink(path);
        if(services[i].pipe>=0) close(services[i].pipe);
        if(services[i].log>=0) close(services[i].log);
    }
    erase(admin,sizeof(admin));erase(unlock,sizeof(unlock));
}
static int input_secrets(char *pin) {
    char bytes[403]={0};size_t used=0;ssize_t n;
    while(used<sizeof(bytes) && (n=read(STDIN_FILENO,bytes+used,sizeof(bytes)-used))>0) used+=(size_t)n;
    close(STDIN_FILENO);
    char *separator=memchr(bytes,'\n',used);
    int bad=1;
    if(used<sizeof(bytes) && used && bytes[used-1]=='\n' && separator && !memchr(bytes,0,used)) {
        size_t first=(size_t)(separator-bytes),second=used-first-2;
        if(first<=200 && second<=200) {
            memcpy(pin,bytes,first);pin[first]=0;memcpy(admin,separator+1,second);admin[second]=0;
            if(secret_valid(pin) && secret_valid(admin)) bad=0;
        }
    }
    erase(bytes,sizeof(bytes));return bad;
}
static int initialize(const char *pin) {
    unsigned char random[32];size_t done=0;
    while(done<sizeof(random)) {
        ssize_t n=getrandom(random+done,sizeof(random)-done,0);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return fail("cannot generate independent runtime unlock passphrase");
        done+=(size_t)n;
    }
    for(size_t i=0;i<sizeof(random);i++) snprintf(unlock+2*i,3,"%02x",random[i]);
    erase(random,sizeof(random));
    char text[2048],qp[403],qa[403],qu[403],stamp[32],state_text[32];
    if(write_file(OWNED "/admin",admin,1) || write_file(OWNED "/unlock",unlock,1) || write_file(OWNED "/lease","",1) || directory(OWNED "/data",1)) return fail("cannot create private native state");
    config(text,sizeof(text));int bad=write_file(OWNED "/p11nethsm.conf",text,1);erase(text,sizeof(text));
    if(bad || start_services() || wait_state(state_text,1)) return 1;
    if(strcmp(state_text,"Unprovisioned")) return fail("refusing to provision an already initialized server");
    time_t current=time(NULL);struct tm utc;if(!gmtime_r(&current,&utc) || !strftime(stamp,sizeof(stamp),"%Y-%m-%dT%H:%M:%SZ",&utc)) return 1;
    quote(pin,qp,sizeof(qp));quote(admin,qa,sizeof(qa));quote(unlock,qu,sizeof(qu));
    snprintf(text,sizeof(text),"{\"unlockPassphrase\":%s,\"adminPassphrase\":%s,\"systemTime\":\"%s\"}",qu,qa,stamp);
    bad=post("/provision","POST",text,0);erase(text,sizeof(text));erase(qa,sizeof(qa));erase(qu,sizeof(qu));
    if(!bad) bad=wait_state(state_text,0);
    if(!bad) {
        snprintf(text,sizeof(text),"{\"realName\":\"P11Lab operator\",\"role\":\"Operator\",\"passphrase\":%s}",qp);
        bad=post("/users/operator","PUT",text,1);erase(text,sizeof(text));
    }
    erase(qp,sizeof(qp));
    if(!bad) bad=native(1);
    if(!bad && (marker(text,sizeof(text)) || write_file(OWNED "/.complete",text,1) || rename(OWNED "/.complete",OWNED "/complete"))) bad=fail("cannot seal completion marker");
    return bad;
}
static int operational(void) {
    char state_text[32],body[500],q[403];
    if(start_services() || wait_state(state_text,1)) return 1;
    if(!strcmp(state_text,"Locked")) {
        quote(unlock,q,sizeof(q));snprintf(body,sizeof(body),"{\"passphrase\":%s}",q);
        int bad=post("/unlock","POST",body,0);erase(body,sizeof(body));erase(q,sizeof(q));
        if(bad || wait_state(state_text,0)) return 1;
    } else if(strcmp(state_text,"Operational")) return fail("completed state is natively unprovisioned; refusing reset");
    struct response r;
    if(request(API "/users/admin","GET",NULL,1,&r)!=200 || !strstr(r.text,"\"role\":\"Administrator\"")) return fail("native administrator authentication is not ready");
    if(request(API "/users/operator","GET",NULL,1,&r)!=200 || !strstr(r.text,"\"role\":\"Operator\"")) return fail("native operator is absent or changed");
    erase(&r,sizeof(r));return 0;
}
int main(int argc,char **argv) {
    char pin[201]={0};int status=1,leasefd=-1,controlfd=-1,init_lock=0;
    struct stat s;
    umask(077);label=getenv("P11LAB_LABEL");
    if(argc<2 || !label || !*label || strlen(label)>32) return 2;
    if(validate_root()) return 1;
    int absent=lstat(OWNED,&s)!=0 && errno==ENOENT;
    if(!strcmp(argv[1],"existing")) {
        if(absent) return 10;
        if(directory(OWNED,0)) return fail("unsafe owned state directory");
        leasefd=lease();if(leasefd<0) return 1;
        status=validate_static();close(leasefd);erase(admin,sizeof(admin));erase(unlock,sizeof(unlock));return status;
    }
    int init=!strcmp(argv[1],"init"),exec=!strcmp(argv[1],"exec");
    if((!init && !exec && strcmp(argv[1],"health")) || (exec && (argc<4 || strcmp(argv[2],"--")))) return 2;
    if(init) {
        if(!absent || input_secrets(pin)) return fail("refusing initialization: occupied state or invalid passphrases");
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
    if(prctl(PR_SET_CHILD_SUBREAPER,1) || curl_global_init(CURL_GLOBAL_DEFAULT)) goto out;
    if(init) status=initialize(pin);
    else if(!operational() && !native(exec)) {
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
    erase(pin,sizeof(pin));cleanup();curl_global_cleanup();
    if(init_lock && rmdir(ROOT "/.init-lock")) status=fail("cannot remove owned initialization lock");
    if(leasefd>=0) close(leasefd);
    if(controlfd>=0) close(controlfd);
    return stopping?128+stopping:status;
}
