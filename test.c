#include "./include/test.h"

int main(int argc, char* argv[])
{
  struct passentry* entry;
  char fname[]="passdata";
  char* sw;
  FILE* fh;
  char* uid;
  char* pass;
  fh = fopen(fname,"a+");
  if(fh == NULL)
  {
    error(0,errno,"Error occured");
  }
  entry = (struct passentry*)malloc(sizeof(struct passentry));
  if(argc > 1)
  {
    sw = argv[1];
  }
  else
  {
    printf("No option supplied!\n");
    free(entry);
    return 1;
  }
  switch(sw[1])
  {
    case 's':
      uid = argv[2];
      pass = argv[3]; 
      entry->password = pass;
      entry->uid = uid;
      storepass(entry,fh);
      break;
    case 'v':
      uid = argv[2];
      pass = argv[3]; 
      entry->password = pass;
      entry->uid = uid;
      verifypass(entry,fh);
      break;
  }
  fclose(fh);
  free(entry);
  return 0;
}

int verifypass(struct passentry* inpass,FILE* passdata)
{
  char outhash[BCRYPT_HASHSIZE];
  char* currline;
  currline = (char*)malloc(MAXBUF);
  int retval = 0;
  while(fgets(currline,MAXBUF,passdata) != NULL)
  {
    //strip off trailing \n
    currline[strnlen(currline,MAXBUF) - 1] = '\0';
    if(strncmp(inpass->uid,currline,MAXBUF) == 0)
    {
      printf("Found match! %s\n",currline);
      if(fgets(currline,MAXBUF,passdata) != NULL)
      {
        currline[strnlen(currline,MAXBUF) - 1] = '\0';
        retval = bcrypt_hashpw(inpass->password,currline,outhash); 
        if(retval == 0)
        {
          if(strncmp(currline,outhash,MAXBUF) == 0)
          {
            printf("Password for %s was correct!\n",inpass->uid);
          }
          else
          {
            printf("Password for %s was INCORRECT!!\n",inpass->uid);
          }
        }
      }
      break;
    }
  }
  free(currline);
  return 1;
}
int storepass(struct passentry* inpass,FILE* passdata)
{
  char salt[BCRYPT_HASHSIZE];
  char hash[BCRYPT_HASHSIZE];
  char passentry[MAXBUF];
  int wf=3;
  int retval=0;
  retval = bcrypt_gensalt(wf,salt);
  if(retval == 0)
  {
    retval = bcrypt_hashpw(inpass->password,salt,hash);
    if(retval == 0)
    {
      retval = snprintf(passentry,MAXBUF,"%s\n%s\n---\n",inpass->uid,hash);
      if(retval > 0)
      {
        retval = fputs(passentry,passdata);
      }
    }
  }
  return retval;
}
