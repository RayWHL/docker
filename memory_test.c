#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
void print_time(struct timespec time1,struct timespec time2)
{
    
    printf("%ld\n",(time2.tv_nsec-time1.tv_nsec)+1000000000*(time2.tv_sec-time1.tv_sec));
}

int main()
{
    struct timespec time1,time2;
    //int size=100*1024*1024;
    unsigned int size;
    char *addr;
    
    printf("pid=%d\n",getpid());
    printf("input size (kb):");
    scanf("%u",&size);
    size=size*1024;
    printf("to malloc");
    getchar();
    addr=(char *)malloc(size);

    if(addr==NULL)
    {
        printf("error\n");
        return 0;
    }

    for(int i=0;i<size;++i)
        addr[i]='a';

    printf("to free");
    getchar();
    clock_gettime(CLOCK_REALTIME,&time1);
    free(addr);
    clock_gettime(CLOCK_REALTIME,&time2);
    print_time(time1,time2);
    return 0;
}