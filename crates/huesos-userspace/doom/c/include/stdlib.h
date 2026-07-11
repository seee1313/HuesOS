#ifndef HUES_STDLIB_H
#define HUES_STDLIB_H
#include <stddef.h>
void *malloc(size_t);
void *calloc(size_t,size_t);
void *realloc(void *,size_t);
void free(void *);
int abs(int);
int atoi(const char *);
double atof(const char *);
long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
char *getenv(const char *);
int system(const char *);
void exit(int) __attribute__((noreturn));
void abort(void) __attribute__((noreturn));
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#endif
