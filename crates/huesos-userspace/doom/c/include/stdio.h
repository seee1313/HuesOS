#ifndef HUES_STDIO_H
#define HUES_STDIO_H
#include <stddef.h>
#include <stdarg.h>
typedef struct HuesFile { unsigned long pos; int kind; } FILE;
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
extern FILE *stdin, *stdout, *stderr;
FILE *fopen(const char *, const char *);
int fclose(FILE *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int fseek(FILE *, long, int);
long ftell(FILE *);
int fflush(FILE *);
int feof(FILE *);
int ferror(FILE *);
int remove(const char *);
int rename(const char *, const char *);
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int vfprintf(FILE *, const char *, va_list);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int vsnprintf(char *, size_t, const char *, va_list);
int sscanf(const char *, const char *, ...);
int putchar(int);
int puts(const char *);
#endif
