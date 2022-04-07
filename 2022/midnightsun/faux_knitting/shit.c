#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <stdio.h>
int main() {
    int v3 = time(0LL);
  int seed = (unsigned int)(v3 - v3 % 10);
  srand(v3 - v3 % 10);
  void* addr = mmap(0LL, 0x800000uLL, 2, 34, -1, 0LL);
  int  * v8 = (int *)addr;
  if ( addr == (void *)-1LL )
    exit(1);
  for (int i = 0; i <= 0x1FFFFF; ++i )
  {
    int * v4 = v8++;
    *v4 = rand();
  }

  const size_t size = 0x200000;

if(addr != NULL)
{
  FILE *out = fopen("memory.bin", "wb");
  if(out != NULL)
  {
    // size_t to_go = size;
    // while(to_go > 0)
    // {
      const size_t wrote = fwrite(addr, 0x8000,0x100, out);
    //   if(wrote == 0)
    //     break;
    //   to_go -= wrote;
    // }
    fclose(out);
  }

}
}