/*
 * ftree (Function tree) local function visualization
 * Joey Pabalinas <alyptik@protonmail.com>
 *
 * Based on ftrace by <Ryan.Oneill@LeviathanSecurity.com>
 */

#ifndef FTREE_H
#define FTREE_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <stdarg.h>

/*
 * For our color coding output
 */
#define WHITE "\x1B[37m"
#define RED  "\x1B[31m"
#define GREEN  "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define DEFAULT_COLOR  "\x1B[0m"

#define MAX_SYMS 8192 * 2

/*
 * On 32bit systems should be set:
 * export FTRACE_ARCH=32
 */
#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_ADDR_SPACE 256
#define MAXSTR 512

#define TEXT_SPACE  0
#define DATA_SPACE  1
#define STACK_SPACE 2
#define HEAP_SPACE  3

#define CALLSTACK_DEPTH 0xf4240

int global_pid;

struct branch_instr {
	char *mnemonic;
	uint8_t opcode;
};

struct elf_section_range {
	char *sh_name;
	unsigned long sh_addr;
	unsigned int sh_size;
};

struct {
	int stripped;
	int callsite;
	int showret;
	int attach;
	int verbose;
	int elfinfo;
	int typeinfo; //imm vs. ptr
	int getstr;
	int arch;
	int cflow;
} opts;

struct elf64 {
	Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        Elf64_Sym  *sym;
        Elf64_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;
};

struct elf32 {
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf32_Sym  *sym;
	Elf32_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;

};

struct address_space {
	unsigned long svaddr;
	unsigned long evaddr;
	unsigned int size;
	int count;
};

struct syms {
	char *name;
	unsigned long value;
};

typedef struct breakpoint {
	unsigned long vaddr;
	long orig_code;
} breakpoint_t;

typedef struct calldata {
		char *symname;
		char *string;
		unsigned long vaddr;
		unsigned long retaddr;
	//	unsigned int depth;
		breakpoint_t breakpoint;
} calldata_t;

typedef struct callstack {
	calldata_t *calldata;
	unsigned int depth;
} callstack_t;

struct call_list {
	char *callstring;
	struct call_list *next;
};

#define MAX_SHDRS 256

struct handle {
	char *path;
	char **args;
	uint8_t *map;
	struct elf32 *elf32;
	struct elf64 *elf64;
	struct elf_section_range sh_range[MAX_SHDRS];
	struct syms lsyms[MAX_SYMS]; //local syms
	struct syms dsyms[MAX_SYMS]; //dynamic syms
	char *libnames[256];
	int lsc; //lsyms count
	int dsc; // dsyms count
	int lnc; //libnames count
	int shdr_count;
	int pid;
};

void load_elf_section_range(struct handle *);
void get_address_space(struct address_space *, int, char *);
void MapElf32(struct handle *);
void MapElf64(struct handle *);
void *HeapAlloc(unsigned int);
char *xstrdup(const char *);
char *get_section_by_range(struct handle *, unsigned long);
void sighandle(int);
int validate_em_type(char *);
void examine_process(struct handle *);
char * get_path(int);

#endif
