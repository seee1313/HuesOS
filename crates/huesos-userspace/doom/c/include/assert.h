#ifndef HUES_ASSERT_H
#define HUES_ASSERT_H
void hues_assert_fail(const char*,const char*,int) __attribute__((noreturn));
#define assert(x) ((x)?(void)0:hues_assert_fail(#x,__FILE__,__LINE__))
#endif
