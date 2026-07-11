#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>

extern unsigned long hues_wad_len(void);
extern unsigned long hues_wad_read(unsigned long, void*, unsigned long);
extern void hues_debug(const char*, unsigned long);
extern void hues_exit(int) __attribute__((noreturn));

int errno;
static unsigned char heap[20 * 1024 * 1024] __attribute__((aligned(16)));
static size_t heap_pos;
typedef struct { size_t size; } Header;

void *malloc(size_t n){
    n=(n+15)&~(size_t)15;
    if(heap_pos+sizeof(Header)+n>sizeof(heap)) return 0;
    Header *h=(Header*)(heap+heap_pos); h->size=n; heap_pos+=sizeof(Header)+n;
    return h+1;
}
void free(void *p){(void)p;}
void *calloc(size_t n,size_t s){ if(s && n>(size_t)-1/s)return 0; size_t z=n*s; void*p=malloc(z); if(p)memset(p,0,z); return p; }
void *realloc(void *p,size_t n){ if(!p)return malloc(n); Header*h=((Header*)p)-1; void*q=malloc(n); if(q)memcpy(q,p,h->size<n?h->size:n); return q; }

void *memcpy(void*d,const void*s,size_t n){unsigned char*a=d;const unsigned char*b=s;while(n--)*a++=*b++;return d;}
void *memmove(void*d,const void*s,size_t n){unsigned char*a=d;const unsigned char*b=s;if(a<b)memcpy(d,s,n);else while(n--)a[n]=b[n];return d;}
void *memset(void*d,int c,size_t n){unsigned char*a=d;while(n--)*a++=(unsigned char)c;return d;}
int memcmp(const void*a,const void*b,size_t n){const unsigned char*x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
size_t strlen(const char*s){size_t n=0;while(s[n])n++;return n;}
int strcmp(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return(unsigned char)*a-(unsigned char)*b;}
int strncmp(const char*a,const char*b,size_t n){while(n&&*a&&*a==*b){a++;b++;n--;}return n?(unsigned char)*a-(unsigned char)*b:0;}
char *strcpy(char*d,const char*s){char*r=d;while((*d++=*s++));return r;}
char *strncpy(char*d,const char*s,size_t n){char*r=d;while(n&&*s){*d++=*s++;n--;}while(n--)*d++=0;return r;}
char *strcat(char*d,const char*s){strcpy(d+strlen(d),s);return d;}
char *strchr(const char*s,int c){for(;;s++){if(*s==c)return(char*)s;if(!*s)return 0;}}
char *strrchr(const char*s,int c){const char*r=0;do{if(*s==c)r=s;}while(*s++);return(char*)r;}
char *strstr(const char*h,const char*n){size_t z=strlen(n);if(!z)return(char*)h;for(;*h;h++)if(!strncmp(h,n,z))return(char*)h;return 0;}
char *strdup(const char*s){size_t n=strlen(s)+1;char*d=malloc(n);if(d)memcpy(d,s,n);return d;}
size_t strlcpy(char*d,const char*s,size_t n){size_t z=strlen(s);if(n){size_t c=z<n-1?z:n-1;memcpy(d,s,c);d[c]=0;}return z;}
size_t strlcat(char*d,const char*s,size_t n){size_t z=strlen(d);return z+strlcpy(z<n?d+z:d,s,z<n?n-z:0);}
int strcasecmp(const char*a,const char*b){while(*a&&tolower(*a)==tolower(*b)){a++;b++;}return tolower(*a)-tolower(*b);}
int strncasecmp(const char*a,const char*b,size_t n){while(n&&*a&&tolower(*a)==tolower(*b)){a++;b++;n--;}return n?tolower(*a)-tolower(*b):0;}
char *strerror(int e){(void)e;return "HuesOS error";}
int abs(int v){return v<0?-v:v;}
int atoi(const char*s){return(int)strtol(s,0,10);}
double atof(const char*s){int neg=0;double v=0,scale=1;while(isspace(*s))s++;if(*s=='-'){neg=1;s++;}while(isdigit(*s))v=v*10+(*s++-'0');if(*s++=='.')while(isdigit(*s)){scale*=10;v+=(*s++-'0')/scale;}return neg?-v:v;}
long strtol(const char*s,char**e,int base){int neg=0;long v=0;while(isspace(*s))s++;if(*s=='-'){neg=1;s++;}else if(*s=='+')s++;while(isalnum(*s)){int d=isdigit(*s)?*s-'0':tolower(*s)-'a'+10;if(d>=base)break;v=v*base+d;s++;}if(e)*e=(char*)s;return neg?-v:v;}
unsigned long strtoul(const char*s,char**e,int b){return(unsigned long)strtol(s,e,b);}
char *getenv(const char*n){(void)n;return 0;}
int system(const char*cmd){(void)cmd;return -1;}
int access(const char*p,int m){(void)m;return strstr(p,".wad")?0:-1;}
int mkdir(const char*p,...){(void)p;return 0;}
int remove(const char*p){(void)p;return 0;}
int rename(const char*a,const char*b){(void)a;(void)b;return 0;}

double fabs(double x){return x<0?-x:x;}
double atan(double x){int neg=x<0;if(neg)x=-x;double r;if(x>1.0)r=M_PI/2.0-x/(x*x+0.28);else r=x/(1.0+0.28*x*x);return neg?-r:r;}

static FILE wad_file={0,1}, sink_file={0,2}, std_file={0,2};
FILE *stdin=&std_file,*stdout=&std_file,*stderr=&std_file;
FILE *fopen(const char*p,const char*m){if(strstr(p,".wad")){wad_file.pos=0;return&wad_file;}if(strchr(m,'w')||strchr(m,'a')){sink_file.pos=0;return&sink_file;}errno=ENOENT;return 0;}
int fclose(FILE*f){(void)f;return 0;}
size_t fread(void*out,size_t s,size_t n,FILE*f){size_t bytes=s*n;if(f&&f->kind==1){size_t got=hues_wad_read(f->pos,out,bytes);f->pos+=got;return s?got/s:0;}return 0;}
size_t fwrite(const void*in,size_t s,size_t n,FILE*f){if(f==stdout||f==stderr)hues_debug(in,s*n);if(f)f->pos+=s*n;return n;}
int fseek(FILE*f,long off,int whence){if(!f)return-1;unsigned long base=whence==SEEK_SET?0:whence==SEEK_CUR?f->pos:hues_wad_len();f->pos=base+off;return 0;}
long ftell(FILE*f){return f?(long)f->pos:-1;}
int fflush(FILE*f){(void)f;return 0;} int feof(FILE*f){return f&&f->kind==1&&f->pos>=hues_wad_len();} int ferror(FILE*f){(void)f;return 0;}

static void outch(char **p,size_t *left,int c,int *total){if(*left>1){**p=(char)c;(*p)++;(*left)--;}(*total)++;}
static void outstr(char **p,size_t*l,const char*s,int*t){if(!s)s="(null)";while(*s)outch(p,l,*s++,t);}
static void outnum(char **p,size_t*l,unsigned long v,unsigned base,int neg,int min_digits,int*t){char b[32];int n=0;if(neg)outch(p,l,'-',t);do{int d=v%base;b[n++]=d<10?'0'+d:'a'+d-10;v/=base;}while(v);while(n<min_digits)b[n++]='0';while(n)outch(p,l,b[--n],t);}
int vsnprintf(char*out,size_t cap,const char*fmt,va_list ap){
 char*p=out;size_t l=cap;int t=0;
 while(*fmt){
  if(*fmt!='%'){outch(&p,&l,*fmt++,&t);continue;}
  fmt++; int zero=0,width=0,precision=0;
  while(*fmt=='-'||*fmt=='+'||*fmt==' '||*fmt=='#'||*fmt=='0'){if(*fmt=='0')zero=1;fmt++;}
  while(*fmt>='0'&&*fmt<='9')width=width*10+(*fmt++-'0');
  if(*fmt=='.'){fmt++;while(*fmt>='0'&&*fmt<='9')precision=precision*10+(*fmt++-'0');}
  int is_long=0;if(*fmt=='l'){is_long=1;fmt++;}
  int digits=precision?precision:(zero?width:0);
  switch(*fmt++){
   case '%':outch(&p,&l,'%',&t);break;
   case 's':outstr(&p,&l,va_arg(ap,char*),&t);break;
   case 'c':outch(&p,&l,va_arg(ap,int),&t);break;
   case 'd':case 'i':{long v=is_long?va_arg(ap,long):va_arg(ap,int);outnum(&p,&l,v<0?-v:v,10,v<0,digits,&t);break;}
   case 'u':{unsigned long v=is_long?va_arg(ap,unsigned long):va_arg(ap,unsigned);outnum(&p,&l,v,10,0,digits,&t);break;}
   case 'x':case 'X':{unsigned long v=is_long?va_arg(ap,unsigned long):va_arg(ap,unsigned);outnum(&p,&l,v,16,0,digits,&t);break;}
   case 'p':outstr(&p,&l,"0x",&t);outnum(&p,&l,(unsigned long)va_arg(ap,void*),16,0,0,&t);break;
   case 'f':{double v=va_arg(ap,double);long whole=(long)v;outnum(&p,&l,whole<0?-whole:whole,10,whole<0,0,&t);outch(&p,&l,'.',&t);outnum(&p,&l,0,10,0,precision?precision:2,&t);break;}
   default:break;
  }
 }
 if(cap)*p=0;return t;
}
int snprintf(char*o,size_t n,const char*f,...){va_list a;va_start(a,f);int r=vsnprintf(o,n,f,a);va_end(a);return r;}
int sprintf(char*o,const char*f,...){va_list a;va_start(a,f);int r=vsnprintf(o,(size_t)-1,f,a);va_end(a);return r;}
int printf(const char*f,...){char b[512];va_list a;va_start(a,f);int r=vsnprintf(b,sizeof(b),f,a);va_end(a);hues_debug(b,strlen(b));return r;}
int vfprintf(FILE*fp,const char*f,va_list a){char b[512];int r=vsnprintf(b,sizeof(b),f,a);fwrite(b,1,strlen(b),fp);return r;}
int fprintf(FILE*fp,const char*f,...){va_list a;va_start(a,f);int r=vfprintf(fp,f,a);va_end(a);return r;}
int sscanf(const char*s,const char*f,...){(void)s;(void)f;return 0;}
int putchar(int c){char x=c;hues_debug(&x,1);return c;} int puts(const char*s){hues_debug(s,strlen(s));hues_debug("\n",1);return 0;}
void exit(int c){hues_exit(c);} void abort(void){hues_exit(-1);} void hues_assert_fail(const char*a,const char*f,int l){(void)a;(void)f;(void)l;hues_exit(-2);}
