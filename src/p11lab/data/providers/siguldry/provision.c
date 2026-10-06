/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab mTLS bootstrap, offline provisioning, static validation and
 * Linux supervision for the Siguldry signing stack. Native PKCS#11 calls,
 * service responses and application status are preserved.
 *
 * The module authenticates with a caller key-access password (the PKCS#11
 * PIN). There is no native security-officer role: C_Login(CKU_SO) returns
 * CKR_USER_TYPE_INVALID natively, so no SO credential is accepted.
 */
#define _GNU_SOURCE
#include <p11-kit/pkcs11.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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
#define OWNED ROOT "/siguldry"
#define CREDS OWNED "/creds"
#define STATEDIR OWNED "/state"
#define CONTROL "/run/p11lab/siguldry"
#define MODULE "/usr/local/lib/p11lab/libsiguldry_pkcs11.so"
#define BINDIR "/usr/local/bin"
#define USER "siguldry-client"
#define SERVER_CN "siguldry-server"
#define BRIDGE_CN "localhost"
#define SERVER_PORT 44333
#define CLIENT_PORT 44334
#define LOG_LIMIT 65536
#define PIN_MIN 32
#define PIN_MAX 200
#define PW_FILE CONTROL "/pw"
#define SIGNER_SOCKET CONTROL "/signer.socket"
#define PROXY_SOCKET CONTROL "/client-proxy.socket"

static volatile sig_atomic_t stopping;
static const char *label;
static char pin[201];
struct child { pid_t pid; int pipe; int log; size_t written; const char *name; };
static struct child services[4] = {{0,-1,-1,0,"siguldry-bridge"},{0,-1,-1,0,"siguldry-signer"},{0,-1,-1,0,"siguldry-server"},{0,-1,-1,0,"siguldry-client"}};
static pid_t application;

static int fail(const char *text) { fprintf(stderr,"p11lab-siguldry: %s\n",text); return 1; }
static void erase(void *p, size_t n) { volatile unsigned char *v=p; while(n--) *v++=0; }
static void signal_handler(int sig) { stopping=sig; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (double)t.tv_sec+(double)t.tv_nsec/1e9; }
static void pause_poll(void) { struct timespec t={0,50000000}; nanosleep(&t,NULL); }
static int secret_valid(const char *text) {
    size_t n=strlen(text);
    if(n<PIN_MIN || n>PIN_MAX) return 0;
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
/* P11Lab-owned mTLS bootstrap. Semantics mirror the vetted upstream devel
 * helper (RSA-2048, SHA-256, 3650-day validity, SAN+EKU leaf extensions,
 * v3_ca self-signed CA) without shipping or running that script and without
 * an openssl CLI in the runtime. The CA private key is never written. */
static EVP_PKEY *bootstrap_key(void) { return EVP_RSA_gen(2048); }
static int bootstrap_serial(X509 *cert) {
    BIGNUM *b=BN_new(); ASN1_INTEGER *a=ASN1_INTEGER_new();
    int ok=b && a && BN_rand(b,160,BN_RAND_TOP_ONE,BN_RAND_TOP_ANY)
        && BN_to_ASN1_INTEGER(b,a) && X509_set_serialNumber(cert,a);
    BN_free(b); ASN1_INTEGER_free(a); return ok;
}
static int bootstrap_name(X509 *cert,const char *cn) {
    X509_NAME *n=X509_NAME_new();
    int ok=n && X509_NAME_add_entry_by_txt(n,"CN",MBSTRING_ASC,(const unsigned char *)cn,-1,-1,0)
        && X509_set_subject_name(cert,n);
    X509_NAME_free(n); return ok;
}
static int bootstrap_ext(X509 *issuer,X509 *subject,int nid,const char *value) {
    X509V3_CTX ctx; X509V3_set_ctx(&ctx,issuer,subject,NULL,NULL,0);
    X509_EXTENSION *e=X509V3_EXT_conf_nid(NULL,&ctx,nid,value);
    int ok=e && X509_add_ext(subject,e,-1);
    X509_EXTENSION_free(e); return ok;
}
static int bootstrap_pem(const char *path,int key,void *object) {
    int fd=open(path,O_WRONLY|O_NOFOLLOW|O_CLOEXEC|O_CREAT|O_EXCL,0600);
    FILE *f=NULL; int ok=0;
    if(!protected_file(fd)) { if(fd>=0) close(fd); return 0; }
    f=fdopen(fd,"w");
    if(f) ok=key?PEM_write_PrivateKey(f,object,NULL,NULL,0,NULL,NULL):PEM_write_X509(f,object);
    if(f) { if(fclose(f)) ok=0; } else close(fd);
    return ok;
}
static int bootstrap_creds(void) {
    EVP_PKEY *cak=bootstrap_key(); X509 *ca=X509_new();
    char path[512],san[256];
    struct { const char *cn; const char *eku; int wanteku_san; const char *file; } leaves[3] = {
        {SERVER_CN,"clientAuth,serverAuth",1,"server"},
        {BRIDGE_CN,"serverAuth",1,"bridge"},
        {USER,"clientAuth",0,USER},
    };
    if(!cak || !ca) goto bad;
    if(directory(CREDS,1)) goto bad;
    X509_set_version(ca,2);
    if(!bootstrap_serial(ca) || !bootstrap_name(ca,"Siguldry CA") || !X509_set_pubkey(ca,cak)
        || !X509_set_issuer_name(ca,X509_get_subject_name(ca))
        || !X509_gmtime_adj(X509_getm_notBefore(ca),0)
        || !X509_gmtime_adj(X509_getm_notAfter(ca),3650L*86400L)
        || !bootstrap_ext(ca,ca,NID_subject_key_identifier,"hash")
        || !bootstrap_ext(ca,ca,NID_authority_key_identifier,"keyid:always,issuer")
        || !bootstrap_ext(ca,ca,NID_basic_constraints,"critical,CA:TRUE")
        || !X509_sign(ca,cak,EVP_sha256())) goto bad;
    snprintf(path,sizeof(path),CREDS "/siguldry.ca_certificate.pem");
    if(!bootstrap_pem(path,0,ca)) goto bad;
    for(size_t i=0;i<3;i++) {
        EVP_PKEY *k=bootstrap_key(); X509 *c=X509_new();
        if(!k || !c) { EVP_PKEY_free(k); X509_free(c); goto bad; }
        snprintf(san,sizeof(san),"DNS:%s",leaves[i].cn);
        X509_set_version(c,2);
        int ok=bootstrap_serial(c) && bootstrap_name(c,leaves[i].cn) && X509_set_pubkey(c,k)
            && X509_set_issuer_name(c,X509_get_subject_name(ca))
            && X509_gmtime_adj(X509_getm_notBefore(c),0)
            && X509_gmtime_adj(X509_getm_notAfter(c),3650L*86400L)
            && (!leaves[i].wanteku_san || bootstrap_ext(ca,c,NID_subject_alt_name,san))
            && bootstrap_ext(ca,c,NID_ext_key_usage,leaves[i].eku)
            && X509_sign(c,cak,EVP_sha256());
        snprintf(path,sizeof(path),CREDS "/siguldry.%s.private_key.pem",leaves[i].file);
        ok=ok && bootstrap_pem(path,1,k);
        snprintf(path,sizeof(path),CREDS "/siguldry.%s.certificate.pem",leaves[i].file);
        ok=ok && bootstrap_pem(path,0,c);
        EVP_PKEY_free(k); X509_free(c);
        if(!ok) goto bad;
    }
    EVP_PKEY_free(cak); X509_free(ca); return 0;
bad:
    EVP_PKEY_free(cak); X509_free(ca);
    ERR_clear_error();
    return fail("cannot bootstrap private mTLS credentials");
}
static void config_bridge(char *out,size_t cap) {
    snprintf(out,cap,"server_listening_address = \"127.0.0.1:44333\"\n"
        "client_listening_address = \"127.0.0.1:44334\"\n"
        "\n[credentials]\n"
        "private_key = \"" CREDS "/siguldry.bridge.private_key.pem\"\n"
        "certificate = \"" CREDS "/siguldry.bridge.certificate.pem\"\n"
        "ca_certificate = \"" CREDS "/siguldry.ca_certificate.pem\"\n");
}
static void config_server(char *out,size_t cap) {
    snprintf(out,cap,"state_directory = \"" STATEDIR "\"\n"
        "bridge_hostname = \"localhost\"\n"
        "bridge_port = 44333\n"
        "connection_pool_size = 1\n"
        "idle_client_timeout = 3600\n"
        "connection_watchdog_timeout = 10800\n"
        "user_password_length = 32\n"
        "signer_socket_path = \"" SIGNER_SOCKET "\"\n"
        "pkcs11_bindings = []\n"
        "\n[credentials]\n"
        "private_key = \"" CREDS "/siguldry.server.private_key.pem\"\n"
        "certificate = \"" CREDS "/siguldry.server.certificate.pem\"\n"
        "ca_certificate = \"" CREDS "/siguldry.ca_certificate.pem\"\n"
        "\n[certificate_subject]\n"
        "country = \"US\"\n"
        "state_or_province = \"Massachusetts\"\n"
        "locality = \"Cambridge\"\n"
        "organization = \"An Example Organization\"\n"
        "organizational_unit = \"Example Department of the Organization\"\n");
}
static void config_client(char *out,size_t cap) {
    snprintf(out,cap,"server_hostname = \"" SERVER_CN "\"\n"
        "bridge_hostname = \"localhost\"\n"
        "bridge_port = 44334\n"
        "keys = []\n"
        "\n[credentials]\n"
        "private_key = \"" CREDS "/siguldry." USER ".private_key.pem\"\n"
        "certificate = \"" CREDS "/siguldry." USER ".certificate.pem\"\n"
        "ca_certificate = \"" CREDS "/siguldry.ca_certificate.pem\"\n");
}
static int marker(char *output,size_t cap) {
    FILE *f=fopen("/usr/share/p11lab/runtime-id","r"); char id[66]={0};
    if(!f || !fgets(id,sizeof(id),f)) { if(f) fclose(f); return 1; }
    int extra=fgetc(f); fclose(f);
    if(strlen(id)!=65 || id[64]!='\n' || extra!=EOF || !is_hex(id,64)) return 1;
    id[64]=0;
    snprintf(output,cap,"schema=1\nprovider=siguldry\nartifact=%s\nlabel=%s\nslot=0\nkey=p256\nuser_password_length=32\n",id,label);
    return 0;
}
static int validate_root(void) {
    static const char *const names[]={"siguldry",NULL}; struct stat s;
    if(directory(ROOT,0)) return fail("state directory is unsafe (owner or permissions)");
    if(!lstat(ROOT "/.init-lock",&s) || errno!=ENOENT) return fail("state initialization is already in progress");
    if(roster(ROOT,names)) return fail("partial state: unknown root entries");
    return 0;
}
static int protected_any(const char *path,size_t minlen,size_t maxlen) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat s;
    if(!protected_file(fd) || fstat(fd,&s) || s.st_size<(off_t)minlen || s.st_size>(off_t)maxlen) { if(fd>=0) close(fd); return 1; }
    close(fd); return 0;
}
static int validate_static(void) {
    static const char *const owned[]={"complete","lease","bridge.toml","server.toml","client.toml","creds","state",NULL};
    static const char *const creds[]={"siguldry.ca_certificate.pem","siguldry.server.private_key.pem",
        "siguldry.server.certificate.pem","siguldry.bridge.private_key.pem","siguldry.bridge.certificate.pem",
        "siguldry." USER ".private_key.pem","siguldry." USER ".certificate.pem",NULL};
    static const char *const statedb[]={"siguldry.sqlite","siguldry.sqlite-wal","siguldry.sqlite-shm","siguldry.sqlite-journal",NULL};
    char actual[4096],expected[4096];
    if(directory(OWNED,0) || roster(OWNED,owned)) return fail("partial or unsafe owned state");
    if(directory(CREDS,0) || roster(CREDS,creds)) return fail("partial or unsafe credential state");
    for(size_t i=0;creds[i];i++) {
        char path[512]; snprintf(path,sizeof(path),CREDS "/%s",creds[i]);
        if(protected_any(path,64,16384)) return fail("partial or unsafe credential file");
    }
    if(directory(STATEDIR,0) || roster(STATEDIR,statedb)) return fail("partial or unsafe native database state");
    int db=open(STATEDIR "/siguldry.sqlite",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    char magic[16]; static const char sqlite[16]="SQLite format 3"; struct stat ds;
    /* The native stack creates the database mode 0640 (sqlx); the 0700
     * state directory remains the access boundary. Either native mode is
     * accepted with the exact magic; nothing else is widened. */
    if(db<0 || fstat(db,&ds) || !S_ISREG(ds.st_mode) || ds.st_uid!=getuid() || ds.st_nlink!=1
        || ((ds.st_mode&0777)!=0600 && (ds.st_mode&0777)!=0640)) { if(db>=0) close(db); return fail("partial or unsafe native database"); }
    if(pread(db,magic,sizeof(magic),0)!=(ssize_t)sizeof(magic) || memcmp(magic,sqlite,15) || magic[15]) { close(db); return fail("partial state: invalid SQLite server database"); }
    close(db);
    if(marker(expected,sizeof(expected)) || read_file(OWNED "/complete",actual,sizeof(actual)-1) || strcmp(actual,expected))
        return fail("incompatible non-secret initialization configuration");
    config_bridge(expected,sizeof(expected));
    if(read_file(OWNED "/bridge.toml",actual,sizeof(actual)-1) || strcmp(actual,expected))
        return fail("incompatible bridge configuration");
    config_server(expected,sizeof(expected));
    if(read_file(OWNED "/server.toml",actual,sizeof(actual)-1) || strcmp(actual,expected))
        return fail("incompatible server configuration");
    config_client(expected,sizeof(expected));
    if(read_file(OWNED "/client.toml",actual,sizeof(actual)-1) || strcmp(actual,expected))
        return fail("incompatible client configuration");
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
static void drain(void) {
    char data[4096];
    for(size_t i=0;i<4;i++) {
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
    for(size_t i=0;i<4;i++) if(services[i].pid) {
        int code=0;
        if(exited(services[i].pid,&code)!=0) { fprintf(stderr,"p11lab-siguldry: required %s exited (status %d)\n",services[i].name,code); return 0; }
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
static int unix_ready(const char *path) {
    struct stat s;
    return !lstat(path,&s) && S_ISSOCK(s.st_mode) && s.st_uid==getuid();
}
/* Run a short native helper with a kill deadline. Output is bounded and
 * never logged; only the exit status (and optional stdout match) matters. */
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
        pause_poll();
    }
    while(waitpid(pid,&status,0)<0 && errno==EINTR) {}
    close(pipefds[0]); return code;
}
static int whoami_ready(void) {
    static const char *const argv[]={BINDIR "/siguldry-client","--config",OWNED "/client.toml",
        "--credentials-directory",CREDS,"whoami",NULL};
    /* whoami retries refused connections indefinitely, so every attempt is
     * bounded; the readiness loop repeats until the startup deadline. */
    return helper(argv,5,NULL,0)==0;
}
static int run_manage(const char *tag,const char *const *argv) {
    char path[256]; snprintf(path,sizeof(path),CONTROL "/manage-%s.log",tag);
    int log=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    pid_t pid; int code=1,status=0; double deadline=now()+120;
    size_t written=0; char data[4096]; int pipefds[2];
    if(!protected_file(log) || pipe2(pipefds,O_CLOEXEC)) { if(log>=0) close(log); return fail("cannot run native management command"); }
    pid=fork();
    if(pid==0) {
        if(setsid()<0) _exit(126);
        int null=open("/dev/null",O_RDONLY);
        if(null<0 || dup2(null,STDIN_FILENO)<0 || dup2(pipefds[1],STDOUT_FILENO)<0 || dup2(pipefds[1],STDERR_FILENO)<0) _exit(126);
        close_child_fds(); execv(argv[0],(char *const *)argv); _exit(127);
    }
    close(pipefds[1]);
    if(pid<0) { close(pipefds[0]); close(log); return fail("cannot run native management command"); }
    if(fcntl(pipefds[0],F_SETFL,O_NONBLOCK)) kill(pid,SIGKILL);
    else for(;;) {
        ssize_t n;
        for(size_t reads=0;reads<16 && (n=read(pipefds[0],data,sizeof(data)))>0;reads++) {
            size_t keep=(size_t)n;
            if(keep>LOG_LIMIT-written) keep=LOG_LIMIT-written;
            if(keep) { ssize_t w=write(log,data,keep); if(w>0) written+=(size_t)w; }
        }
        int done=exited(pid,&code);
        if(done<0) { code=1; break; }
        if(done>0) break;
        if(stopping || now()>=deadline) { kill(-pid,SIGKILL); kill(pid,SIGKILL); code=124; }
        pause_poll();
    }
    while(waitpid(pid,&status,0)<0 && errno==EINTR) {}
    close(pipefds[0]); close(log);
    if(code) { fprintf(stderr,"p11lab-siguldry: native manage %s failed (status %d); partial state retained\n",tag,code); return 1; }
    return 0;
}
static int start_services(void) {
    static const char *const bridge[]={BINDIR "/siguldry-bridge","--config",OWNED "/bridge.toml",
        "listen","--credentials-directory",CREDS,NULL};
    static const char *const signer[]={BINDIR "/siguldry-signer","--socket",SIGNER_SOCKET,NULL};
    static const char *const server[]={BINDIR "/siguldry-server","--config",OWNED "/server.toml",
        "listen","--credentials-directory",CREDS,NULL};
    static const char *const proxy[]={BINDIR "/siguldry-client","--config",OWNED "/client.toml",
        "--credentials-directory",CREDS,"proxy","--mode","bind","--socket",PROXY_SOCKET,NULL};
    /* Stale socket paths fail native binds; the control directory is private
     * to this operation, so only our own names are unlinked. */
    unlink(SIGNER_SOCKET); unlink(PROXY_SOCKET);
    return launch(&services[0],bridge) || launch(&services[1],signer)
        || launch(&services[2],server) || launch(&services[3],proxy);
}
static int wait_ready(void) {
    double deadline=now()+60;
    while(now()<deadline && alive()) {
        if(unix_ready(SIGNER_SOCKET) && unix_ready(PROXY_SOCKET)
            && tcp_ready(SERVER_PORT) && tcp_ready(CLIENT_PORT) && whoami_ready()) return 0;
        pause_poll();
    }
    return fail("service readiness deadline or required service failure");
}
static int native(int quiet) {
    CK_FUNCTION_LIST_PTR f=NULL; CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    CK_SLOT_ID slot=0; CK_ULONG count=1; CK_TOKEN_INFO info; CK_BYTE padded[32];
    CK_MECHANISM_TYPE mechs[16]; CK_ULONG nmechs=16; int ecdsa=0;
    void *h=dlopen(MODULE,RTLD_NOW|RTLD_LOCAL),*symbol; int initialized=0,status=1;
    CK_RV rv=CKR_GENERAL_ERROR;
    if(setenv("LIBSIGULDRY_PKCS11_PROXY_PATH",PROXY_SOCKET,1)) return fail("cannot select owned proxy socket");
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
    if(memcmp(info.label,padded,sizeof(padded)) || (info.flags&(CKF_TOKEN_INITIALIZED|CKF_LOGIN_REQUIRED|CKF_USER_PIN_INITIALIZED))!=(CKF_TOKEN_INITIALIZED|CKF_LOGIN_REQUIRED|CKF_USER_PIN_INITIALIZED)) {
        fail("native token flags or label are not ready"); goto out;
    }
    if((rv=f->C_GetMechanismList(slot,mechs,&nmechs))) goto out;
    for(CK_ULONG i=0;i<nmechs;i++) if(mechs[i]==CKM_ECDSA) ecdsa=1;
    if(!ecdsa) { fail("native ECDSA signing mechanism is not ready"); goto out; }
    /* Readiness never logs in: unlocking is caller authentication and must
     * not happen behind health checks or other applications. */
    if(!quiet) printf("ready: native_slot=0 token_present_index=0 label=%s key=p256 mech=ECDSA\n",label);
    status=0;
out:
    if(status && rv) fprintf(stderr,"p11lab-siguldry: native readiness CK_RV=0x%08lx\n",rv);
    if(initialized && (rv=f->C_Finalize(NULL))) { fprintf(stderr,"C_Finalize: CK_RV=0x%08lx\n",rv);status=1; }
    if(h) dlclose(h);
    return status;
}
static void signal_groups(int sig) {
    if(application>0) kill(-application,sig);
    for(size_t i=0;i<4;i++) if(services[i].pid>0) kill(-services[i].pid,sig);
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
            for(size_t i=0;i<4;i++) if(pid==services[i].pid) services[i].pid=0;
        }
        if(pid<0 && errno==ECHILD) break;
        pause_poll();
    }
    signal_groups(SIGKILL);signal_adopted(SIGKILL);
    while(waitpid(-1,&status,0)>0 || errno==EINTR) { drain();signal_adopted(SIGKILL); }
    drain();
    for(size_t i=0;i<4;i++) {
        char path[256];snprintf(path,sizeof(path),CONTROL "/%s.pid",services[i].name);unlink(path);
        if(services[i].pipe>=0) close(services[i].pipe);
        if(services[i].log>=0) close(services[i].log);
    }
    unlink(PW_FILE);
    erase(pin,sizeof(pin));
}
static int input_secrets(void) {
    char bytes[202]={0};size_t used=0;ssize_t n;
    while(used<sizeof(bytes) && (n=read(STDIN_FILENO,bytes+used,sizeof(bytes)-used))>0) used+=(size_t)n;
    close(STDIN_FILENO);
    int bad=1;
    if(used<sizeof(bytes) && used>1 && bytes[used-1]=='\n' && !memchr(bytes,0,used) && !memchr(bytes,'\n',used-1)) {
        memcpy(pin,bytes,used-1);pin[used-1]=0;
        if(secret_valid(pin)) bad=0;
    }
    erase(bytes,sizeof(bytes));return bad;
}
static int initialize(void) {
    char text[4096];
    static const char *const migrate[]={BINDIR "/siguldry-server","--config",OWNED "/server.toml","manage","migrate",NULL};
    static const char *const users[]={BINDIR "/siguldry-server","--config",OWNED "/server.toml","manage","users","create",USER,NULL};
    const char *key_argv[]={BINDIR "/siguldry-server","--config",OWNED "/server.toml","manage","key","create",
        "--algorithm=p256","--password-file",PW_FILE,USER,label,NULL};
    if(write_text(OWNED "/lease","",1) || directory(STATEDIR,1)) return fail("cannot create private native state");
    config_bridge(text,sizeof(text));
    if(write_text(OWNED "/bridge.toml",text,1)) return fail("cannot write bridge configuration");
    config_server(text,sizeof(text));
    if(write_text(OWNED "/server.toml",text,1)) return fail("cannot write server configuration");
    config_client(text,sizeof(text));
    if(write_text(OWNED "/client.toml",text,1)) return fail("cannot write client configuration");
    erase(text,sizeof(text));
    if(bootstrap_creds()) return 1;
    if(run_manage("migrate",migrate) || run_manage("users",users)) return 1;
    /* The native key password is the caller PIN. It travels in a private
     * control file that is unlinked immediately after provisioning. */
    if(write_text(PW_FILE,pin,1)) return fail("cannot stage private key password");
    int bad=run_manage("key",key_argv);
    erase(pin,sizeof(pin)); unlink(PW_FILE);
    if(bad) return 1;
    if(start_services() || wait_ready() || native(1)) return 1;
    if(marker(text,sizeof(text)) || write_text(OWNED "/.complete",text,1) || rename(OWNED "/.complete",OWNED "/complete")) bad=fail("cannot seal completion marker");
    erase(text,sizeof(text));
    return bad;
}
static int operational(int quiet) {
    return start_services() || wait_ready() || native(quiet);
}
int main(int argc,char **argv) {
    int status=1,leasefd=-1,controlfd=-1,init_lock=0;
    struct stat s;
    umask(077);label=getenv("P11LAB_LABEL");
    if(argc<2 || !label || !*label || strlen(label)>32) return 2;
    if(getenv("LIBSIGULDRY_PKCS11_KEYS")) return fail("unsupported native override: LIBSIGULDRY_PKCS11_KEYS");
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
        if(!absent || input_secrets()) return fail("refusing initialization: occupied state or invalid passphrase");
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
    erase(pin,sizeof(pin));cleanup();
    if(init_lock && rmdir(ROOT "/.init-lock")) status=fail("cannot remove owned initialization lock");
    if(leasefd>=0) close(leasefd);
    if(controlfd>=0) close(controlfd);
    return stopping?128+stopping:status;
}
