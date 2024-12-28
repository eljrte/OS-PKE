#ifndef _ELF_H_
#define _ELF_H_

#include "util/types.h"
#include "process.h"

#define MAX_CMDLINE_ARGS 64



/* sh_type */   //来源于linux内核
#define SHT_NULL	0
#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_RELA	4
#define SHT_HASH	5
#define SHT_DYNAMIC	6
#define SHT_NOTE	7
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_SHLIB	10
#define SHT_DYNSYM	11
#define SHT_NUM		12
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

/* sh_flags */
#define SHF_WRITE		0x1
#define SHF_ALLOC		0x2
#define SHF_EXECINSTR		0x4
#define SHF_RELA_LIVEPATCH	0x00100000
#define SHF_RO_AFTER_INIT	0x00200000
#define SHF_MASKPROC		0xf0000000

/* special section indexes */
#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_LIVEPATCH	0xff20
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_HIRESERVE	0xffff


#define STT_FUNC       2 


// elf header structure
typedef struct elf_header_t {
  uint32 magic;
  uint8 elf[12];
  uint16 type;      /* Object file type */
  uint16 machine;   /* Architecture */
  uint32 version;   /* Object file version */
  uint64 entry;     /* Entry point virtual address */
  uint64 phoff;     /* Program header table file offset */
  uint64 shoff;     /* Section header table file offset */
  uint32 flags;     /* Processor-specific flags */
  uint16 ehsize;    /* ELF header size in bytes */
  uint16 phentsize; /* Program header table entry size */
  uint16 phnum;     /* Program header table entry count */
  uint16 shentsize; /* Section header table entry size */
  uint16 shnum;     /* Section header table entry count */
  uint16 shstrndx;  /* Section header string table index */
} elf_header;

// Program segment header.
typedef struct elf_prog_header_t {
  uint32 type;   /* Segment type */
  uint32 flags;  /* Segment flags */
  uint64 off;    /* Segment file offset */
  uint64 vaddr;  /* Segment virtual address */
  uint64 paddr;  /* Segment physical address */
  uint64 filesz; /* Segment size in file */
  uint64 memsz;  /* Segment size in memory */
  uint64 align;  /* Segment alignment */
} elf_prog_header;



//根据linux内核复制而来  /usr/include/linux/elf.h
typedef struct elf_sym {
  uint32 st_name;		/* Symbol name, index in string tbl */
  unsigned char	st_info;	/* Type and binding attributes */            // 高 4 位 和 低 4 位 分别表示符号的绑定和类型
  unsigned char	st_other;	/* No defined meaning, 0 */
  uint16 st_shndx;		/* Associated section index */
  uint64 st_value;		/* Value of the symbol */                        //当类型为func时 st_value指函数的入口地址 内存中起始位置 可以和ra关联
  uint64 st_size;		/* Associated symbol size */                       //函数的代码长度
} elf_symbol;

typedef struct ELF_shdr {
  uint32 sh_name;		/* Section name, index in shstring tbl */
  uint32 sh_type;		/* Type of section */
  uint64 sh_flags;		/* Miscellaneous section attributes */
  uint64 sh_addr;		/* Section virtual addr at execution */
  uint64 sh_offset;		/* Section file offset */
  uint64 sh_size;		/* Size of section in bytes */
  uint32 sh_link;		/* Index of another section */
  uint32 sh_info;		/* Additional section information */
  uint64 sh_addralign;	/* Section alignment */
  uint64 sh_entsize;	/* Entry size if section holds table */
} elf_shdr;

#define ELF_MAGIC 0x464C457FU  // "\x7FELF" in little endian
#define ELF_PROG_LOAD 1

typedef enum elf_status_t {
  EL_OK = 0,

  EL_EIO,
  EL_ENOMEM,
  EL_NOTELF,
  EL_ERR,

} elf_status;

typedef struct elf_ctx_t {
  void *info;
  elf_header ehdr;
} elf_ctx;

elf_status elf_init(elf_ctx *ctx, void *info);
elf_status elf_load(elf_ctx *ctx);

void load_bincode_from_host_elf(process *p);
void load_func_name(elf_ctx *ctx);

#endif
