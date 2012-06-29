#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "bcrypt.h"
#include "SCEPPluginDemoAPI.h"

#define MAXBUF 1024

struct passentry
{
  char* password;
  char* uid;
};

int verifypass(struct passentry* inpass,FILE* passdata);
int storepass(struct passentry* inpass,FILE* passdata);
