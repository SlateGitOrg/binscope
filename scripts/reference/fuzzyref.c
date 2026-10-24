#include <fuzzy.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char**argv){
  if(argc==4 && !strcmp(argv[1],"cmp")){ printf("%d\n", fuzzy_compare(argv[2],argv[3])); return 0;}
  return 2;
}
