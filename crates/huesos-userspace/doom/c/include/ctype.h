#ifndef HUES_CTYPE_H
#define HUES_CTYPE_H
static inline int tolower(int c){return c>='A'&&c<='Z'?c+32:c;}
static inline int toupper(int c){return c>='a'&&c<='z'?c-32:c;}
static inline int isspace(int c){return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\f'||c=='\v';}
static inline int isdigit(int c){return c>='0'&&c<='9';}
static inline int isxdigit(int c){return isdigit(c)||(tolower(c)>='a'&&tolower(c)<='f');}
static inline int isalpha(int c){c=tolower(c);return c>='a'&&c<='z';}
static inline int isalnum(int c){return isalpha(c)||isdigit(c);}
static inline int isprint(int c){return c>=32&&c<127;}
#endif
