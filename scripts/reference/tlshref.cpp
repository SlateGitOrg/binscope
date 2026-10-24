#include "tlsh.h"
#include <cstdio>
#include <cstring>
#include <vector>
// usage: tlshref hash FILE... | tlshref diff H1 H2
int main(int argc, char** argv){
  if(argc<3) return 2;
  if(!strcmp(argv[1],"hash")){
    for(int a=2;a<argc;a++){
      FILE* f=fopen(argv[a],"rb"); if(!f){printf("ERR\t%s\n",argv[a]);continue;}
      std::vector<unsigned char> buf; unsigned char tmp[65536]; size_t n;
      while((n=fread(tmp,1,sizeof tmp,f))>0) buf.insert(buf.end(),tmp,tmp+n); fclose(f);
      Tlsh t; t.final(buf.data(), buf.size());
      const char* h=t.getHash(1); printf("%s\t%s\n", (h&&*h)?h:"TNULL", argv[a]);
    }
    return 0;
  }
  if(!strcmp(argv[1],"diff")){
    Tlsh a,b; if(a.fromTlshStr(argv[2])||b.fromTlshStr(argv[3])) {printf("PARSEERR\n");return 1;}
    printf("%d\t%d\n", a.totalDiff(&b,true), a.totalDiff(&b,false)); return 0;
  }
  return 2;
}
