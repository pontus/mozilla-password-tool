#include <string.h>
#include <stdlib.h>



static char* password = 0;
static int pwdcallcount = 0;

void PK11_SetPasswordFunc(void* func);
extern void SEC_Init(void);
extern int NSS_Init(const char *configdir);
extern int NSS_Shutdown(void);

struct SECItemStr {
  int		type;
  unsigned char*	data;
  unsigned int	len;
};

typedef struct SECItemStr SECItem;


int PK11SDR_Encrypt(SECItem *keyid, SECItem *data, SECItem *result, void *cx);
int PK11SDR_Decrypt(SECItem *data, SECItem *result, void *cx);


void set_password(char* pwd)
{
  password = pwd;
  pwdcallcount = 0;
}


char* passwordfunc(char* pwd)
{
  char* tmp = 0;

  pwdcallcount++;

  if( password)
    tmp = strdup(password);
  password = 0;
  return tmp;
}

void fixup_password(void)
{
  PK11_SetPasswordFunc(passwordfunc);
}


