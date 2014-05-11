#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

pid_t getpid(void) {
        pid_t fakepid;
	char *pidenv;
	
	pidenv =  getenv("FAKEPID");
	if (pidenv)
	        fakepid = atoi(pidenv);
	else
		fakepid = 1;
        return fakepid;
}
