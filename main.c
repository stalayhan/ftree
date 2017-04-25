/*
 * ftree (Function tree) local function visualization
 * Joey Pabalinas <alyptik@protonmail.com>
 *
 * Based on ftrace by <Ryan.Oneill@LeviathanSecurity.com>
 */

#include "ftree.h"

int main(int argc, char **argv, char **envp) {
	int opt, i, pid, status, skip_getopt = 0;
	struct handle handle;
	char **p, *arch;

        struct sigaction act;
        __sigset_t set;
        act.sa_handler = sighandle;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        sigaction (SIGINT, &act, NULL);
        sigemptyset (&set);
        sigaddset (&set, SIGINT);

	if (argc < 2) {
		usage:
		printf("Usage: %s [-p <pid>] [-Sstve] <prog>\n", argv[0]);
		printf("[-p] Trace by PID\n");
		printf("[-t] Type detection of function args\n");
		printf("[-s] Print string values\n");
	//	printf("[-r] Show return values\n");
		printf("[-v] Verbose output\n");
		printf("[-e] Misc. ELF info. (Symbols,Dependencies)\n");
		printf("[-S] Show function calls with stripped symbols\n");
		printf("[-C] Complete control flow analysis\n");
		exit(0);
	}

	if (argc == 2 && argv[1][0] == '-')
		goto usage;

	memset(&opts, 0, sizeof(opts));

	opts.arch = 64; // default
	arch = getenv(FTRACE_ENV);
	if (arch != NULL) {
		switch(atoi(arch)) {
			case 32:
				opts.arch = 32;
				break;
			case 64:
				opts.arch = 64;
				break;
			default:
				fprintf(stderr, "Unknown architecture: %s\n", arch);
				break;
		}
	}

	if (argv[1][0] != '-') {

		handle.path = xstrdup(argv[1]);
		handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1);

		for (i = 0, p = &argv[1]; i != argc - 1; p++, i++) {
			*(handle.args + i) = xstrdup(*p);
		}
		*(handle.args + i) = NULL;
		skip_getopt = 1;

	} else {
		handle.path = xstrdup(argv[2]);
		handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1);

		for (i = 0, p = &argv[2]; i != argc - 2; p++, i++) {
			*(handle.args + i) = xstrdup(*p);
		}
		*(handle.args + i) = NULL;
	}


	if (skip_getopt)
		goto begin;

	while ((opt = getopt(argc, argv, "CSrhtvep:s")) != -1) {
		switch(opt) {
			case 'S':
				opts.stripped++;
				break;
			case 'r':
				opts.showret++;
				break;
			case 'v':
				opts.verbose++;
				break;
			case 'e':
				opts.elfinfo++;
				break;
			case 't':
				opts.typeinfo++;
				break;
			case 'p':
				opts.attach++;
				handle.pid = atoi(optarg);
				break;
			case 's':
				opts.getstr++;
				break;
			case 'C':
				opts.cflow++;
				break;
			case 'h':
				goto usage;
			default:
				printf("Unknown option\n");
				exit(0);
		}
	}

begin:
	if (opts.verbose) {
		switch(opts.arch) {
			case 32:
				printf("[+] 32bit ELF mode enabled!\n");
				break;
			case 64:
				printf("[+] 64bit ELF mode enabled!\n");
				break;
		}
		if (opts.typeinfo)
			printf("[+] Pointer type prediction enabled\n");
	}

	if (opts.arch == 32 && opts.typeinfo) {
		printf("[!] Option -t may not be used on 32bit executables\n");
		exit(0);
	}

	if (opts.arch == 32 && opts.getstr) {
		printf("[!] Option -s may not be used on 32bit executables\n");
		exit(0);
	}

	if (opts.getstr && opts.typeinfo) {
		printf("[!] Options -t and -s may not be used together\n");
		exit(0);
	}

	/*
	 * We are not attaching, but rather executing
	 * in this first instance
	 */
	if (!opts.attach) {

		if (!validate_em_type(handle.path)) {
			printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
			exit(-1);
		}

		if ((pid = fork()) < 0) {
			perror("fork");
			exit(-1);
		}

		if (pid == 0) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
              			perror("PTRACE_TRACEME");
              			exit(-1);
			}
			ptrace(PTRACE_SETOPTIONS, 0, 0, PTRACE_O_TRACEEXIT);
		  	execve(handle.path, handle.args, envp);
			exit(0);
		}
		waitpid(0, &status, WNOHANG);
		handle.pid = pid;
		global_pid = pid;
		examine_process(&handle);
		goto done;
	}

	/*
	 * In this second instance we trace an
	 * existing process id.
	 */
	if (ptrace(PTRACE_ATTACH, handle.pid, NULL, NULL) == -1) {
		perror("PTRACE_ATTACH");
		exit(-1);
	}
	handle.path = get_path(handle.pid);
        if (!validate_em_type(handle.path)) {
        	printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
        	exit(-1);
       	}

	waitpid(handle.pid, &status, WUNTRACED);
	global_pid = handle.pid;
	examine_process(&handle);


done:
	printf("%s\n", WHITE);
	ptrace(PTRACE_DETACH, handle.pid, NULL, NULL);
	exit(0);

}
