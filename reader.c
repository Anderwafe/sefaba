#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define EI_NIDENT_SIZE 16
unsigned char ELFMAG[4] = {0x7F, 'E', 'L', 'F'};
typedef struct {
    unsigned char ELFMAG[4]; //ELFMAG constant, which defined upper;        1...4
    unsigned char EI_CLASS; // file class;                                  5
    unsigned char EI_DATA; // data encoding;                                6
    unsigned char EI_VERSION; // file version;                              7
    unsigned char EI_OSABI; // OS/ABI identification                        8
    unsigned char EI_ABIVERSION; // ABI version                             9
    unsigned char EI_PAD[EI_NIDENT_SIZE - 9 - 1]; // start of padding bytes 10..EI_NIDENT_SIZE
    unsigned char EI_NIDENT; // size of e_ident                             EI_NIDENT_SIZE
} e_ident_fields;

// ELF32

typedef uint32_t Elf32_Addr; // Unsigned program address
typedef uint16_t Elf32_Half; // Unsigned medium integer
typedef uint32_t Elf32_Off; // Unsigned file offset
typedef int32_t Elf32_Sword; // Signed large integer
typedef uint32_t Elf32_Word; // Unsigned large integer
//typedef uint8_t unsigned char; // unsigned small integer

struct elf32_word_descriptor {
    Elf32_Word key;
    char* value;
    char* description;
};

struct elf32_half_descriptor {
    Elf32_Half key;
    char* value;
    char* description;
};

struct elf_uchar_descriptor {
    unsigned char key;
    char* value;
    char* description;
};

// Elf32_Ehdr's e_type descriptors
struct elf32_half_descriptor e_type_descriptors[] = {
        {.key = 0, .value = "ET_NONE", .description = "No file type"},
        {.key = 1, .value = "ET_REL", .description = "Relocatable file"},
        {.key = 2, .value = "ET_EXEC", .description = "Executable file"},
        {.key = 3, .value = "ET_DYN", .description = "Shared object file"},
        {.key = 4, .value = "ET_Core", .description = "Core file"},
        {.key = 0xFE00, .value = "ET_LOOS", .description = "Operating system-specific"},
        {.key = 0xFEFF, .value = "ET_HIOS", .description = "Operating system-specific"},
        {.key = 0xFF00, .value = "ET_LOPROC", .description = "Processor-specific file"},
        {.key = 0xFFFF, .value = "ET_HIPROC", .description = "Processor-specific file"},
};

struct elf32_half_descriptor e_machine_des[] = {
	{.key = 0, .value = "EM_NONE", .description = "No machine"},
	{.key = 1, .value = "EM_M32", .description = "AT&T WE 32100"},
	{.key = 2, .value = "EM_SPARC", .description = "SPARC"},
	{.key = 3, .value = "EM_386", .description = "Intel 80386"},
	{.key = 4, .value = "EM_68K", .description = "Motorola 68000"},
	{.key = 5, .value = "EM_88K", .description = "Motorola 88000"},
	{.key = 6, .value = "reserved", .description = "Reserved for future use (was EM_486)"},
	{.key = 7, .value = "EM_860", .description = "Intel 80860"},
	{.key = 8, .value = "EM_MIPS", .description = "MIPS I Architecture"},
	{.key = 9, .value = "EM_S370", .description = "IBM System/370 Processor"},
	{.key = 10, .value = "EM_MIPS_RS3_LE", .description = "MIPS RS3000 Little-endian"},
	{.key = 11-14, .value = "reserved", .description = "Reserved for future use"},
	{.key = 15, .value = "EM_PARISC", .description = "Hewlett-Packard PA-RISC"},
	{.key = 16, .value = "reserved", .description = "Reserved for future use"},
	{.key = 17, .value = "EM_VPP500", .description = "Fujitsu VPP500"},
	{.key = 18, .value = "EM_SPARC32PLUS", .description = "Enhanced instruction set SPARC"},
	{.key = 19, .value = "EM_960", .description = "Intel 80960"},
	{.key = 20, .value = "EM_PPC", .description = "PowerPC"},
	{.key = 21, .value = "EM_PPC64", .description = "64-bit PowerPC"},
	{.key = 22, .value = "EM_S390", .description = "IBM System/390 Processor"},
	{.key = 23-35, .value = "reserved", .description = "Reserved for future use"},
	{.key = 36, .value = "EM_V800", .description = "NEC V800"},
	{.key = 37, .value = "EM_FR20", .description = "Fujitsu FR20"},
	{.key = 38, .value = "EM_RH32", .description = "TRW RH-32"},
	{.key = 39, .value = "EM_RCE", .description = "Motorola RCE"},
	{.key = 40, .value = "EM_ARM", .description = "Advanced RISC Machines ARM"},
	{.key = 41, .value = "EM_ALPHA", .description = "Digital Alpha"},
	{.key = 42, .value = "EM_SH", .description = "Hitachi SH"},
	{.key = 43, .value = "EM_SPARCV9", .description = "SPARC Version 9"},
	{.key = 44, .value = "EM_TRICORE", .description = "Siemens TriCore embedded processor"},
	{.key = 45, .value = "EM_ARC", .description = "Argonaut RISC Core, Argonaut Technologies Inc."},
	{.key = 46, .value = "EM_H8_300", .description = "Hitachi H8/300"},
	{.key = 47, .value = "EM_H8_300H", .description = "Hitachi H8/300H"},
	{.key = 48, .value = "EM_H8S", .description = "Hitachi H8S"},
	{.key = 49, .value = "EM_H8_500", .description = "Hitachi H8/500"},
	{.key = 50, .value = "EM_IA_64", .description = "Intel IA-64 processor architecture"},
	{.key = 51, .value = "EM_MIPS_X", .description = "Stanford MIPS-X"},
	{.key = 52, .value = "EM_COLDFIRE", .description = "Motorola ColdFire"},
	{.key = 53, .value = "EM_68HC12", .description = "Motorola M68HC12"},
	{.key = 54, .value = "EM_MMA", .description = "Fujitsu MMA Multimedia Accelerator"},
	{.key = 55, .value = "EM_PCP", .description = "Siemens PCP"},
	{.key = 56, .value = "EM_NCPU", .description = "Sony nCPU embedded RISC processor"},
	{.key = 57, .value = "EM_NDR1", .description = "Denso NDR1 microprocessor"},
	{.key = 58, .value = "EM_STARCORE", .description = "Motorola Star*Core processor"},
	{.key = 59, .value = "EM_ME16", .description = "Toyota ME16 processor"},
	{.key = 60, .value = "EM_ST100", .description = "STMicroelectronics ST100 processor"},
	{.key = 61, .value = "EM_TINYJ", .description = "Advanced Logic Corp. TinyJ embedded processor family"},
	{.key = 62, .value = "EM_X86_64", .description = "AMD x86-64 architecture"},
	{.key = 63, .value = "EM_PDSP", .description = "Sony DSP Processor"},
	{.key = 64, .value = "EM_PDP10", .description = "Digital Equipment Corp. PDP-10"},
	{.key = 65, .value = "EM_PDP11", .description = "Digital Equipment Corp. PDP-11"},
	{.key = 66, .value = "EM_FX66", .description = "Siemens FX66 microcontroller"},
	{.key = 67, .value = "EM_ST9PLUS", .description = "STMicroelectronics ST9+ 8/16 bit microcontroller"},
	{.key = 68, .value = "EM_ST7", .description = "STMicroelectronics ST7 8-bit microcontroller"},
	{.key = 69, .value = "EM_68HC16", .description = "Motorola MC68HC16 Microcontroller"},
	{.key = 70, .value = "EM_68HC11", .description = "Motorola MC68HC11 Microcontroller"},
	{.key = 71, .value = "EM_68HC08", .description = "Motorola MC68HC08 Microcontroller"},
	{.key = 72, .value = "EM_68HC05", .description = "Motorola MC68HC05 Microcontroller"},
	{.key = 73, .value = "EM_SVX", .description = "Silicon Graphics SVx"},
	{.key = 74, .value = "EM_ST19", .description = "STMicroelectronics ST19 8-bit microcontroller"},
	{.key = 75, .value = "EM_VAX", .description = "Digital VAX"},
	{.key = 77, .value = "EM_JAVELIN", .description = "Infineon Technologies 32-bit embedded processor"},
	{.key = 78, .value = "EM_FIREPATH", .description = "Element 14 64-bit DSP Processor"},
	{.key = 79, .value = "EM_ZSP", .description = "LSI Logic 16-bit DSP Processor"},
	{.key = 80, .value = "EM_MMIX", .description = "Donald Knuth's educational 64-bit processor"},
	{.key = 81, .value = "EM_HUANY", .description = "Harvard University machine-independent object files"},
	{.key = 82, .value = "EM_PRISM", .description = "SiTera Prism"},
	{.key = 83, .value = "EM_AVR", .description = "Atmel AVR 8-bit microcontroller"},
	{.key = 84, .value = "EM_FR30", .description = "Fujitsu FR30"},
	{.key = 85, .value = "EM_D10V", .description = "Mitsubishi D10V"},
	{.key = 86, .value = "EM_D30V", .description = "Mitsubishi D30V"},
	{.key = 87, .value = "EM_V850", .description = "NEC v850"},
	{.key = 88, .value = "EM_M32R", .description = "Mitsubishi M32R"},
	{.key = 89, .value = "EM_MN10300", .description = "Matsushita MN10300"},
	{.key = 90, .value = "EM_MN10200", .description = "Matsushita MN10200"},
	{.key = 91, .value = "EM_PJ", .description = "picoJava"},
	{.key = 92, .value = "EM_OPENRISC", .description = "OpenRISC 32-bit embedded processor"},
	{.key = 93, .value = "EM_ARC_A5", .description = "ARC Cores Tangent-A5"},
	{.key = 94, .value = "EM_XTENSA", .description = "Tensilica Xtensa Architecture"},
	{.key = 95, .value = "EM_VIDEOCORE", .description = "Alphamosaic VideoCore processor"},
	{.key = 96, .value = "EM_TMM_GPP", .description = "Thompson Multimedia General Purpose Processor"},
	{.key = 97, .value = "EM_NS32K", .description = "National Semiconductor 32000 series"},
	{.key = 98, .value = "EM_TPC", .description = "Tenor Network TPC processor"},
	{.key = 99, .value = "EM_SNP1K", .description = "Trebia SNP 1000 processor"},
	{.value = "EM_ST200", .key = 100, .description = "STMicroelectronics (www.st.com) ST200 microcontroller"},
};

struct elf32_word_descriptor e_version_des[] = {
    {.key = 0, .value = "EV_NONE", .description = "Invalid version"},
    {.key = 1, .value = "EV_CURRENT", .description = "Version 1."},
};

struct elf_uchar_descriptor ei_class_des[] = {
    {.key = 0, .value = "ELFCLASSNONE", .description = "Invalid class"},
    {.key = 1, .value = "ELFCLASS32", .description = "32-bit objects"},
    {.key = 2, .value = "ELFCLASS64", .description = "64-bit objects"},
};

struct elf_uchar_descriptor ei_data_des[] = {
    {.key = 0, .value = "ELFDATANONE", .description = "Invalid data encoding"},
    {.key = 1, .value = "ELFDATA2LSB", .description = "Least significant byte order"},
    // real value: 0x01_02_03_04
    // in file   :   04 03 02 01
    {.key = 2, .value = "ELFDATA2MSB", .description = "Most significant byte order"},
    // real value: 0x01_02_03_04
    // in file   :   01 02 03 04
};

#define ei_version_des e_version_des

struct elf_uchar_descriptor ei_osabi_des[] = {
    {.key = 0, .value = "ELFOSABI_NONE", .description = "No extensions or unspecified"},
	{.key = 1, .value = "ELFOSABI_HPUX", .description = "Hewlett-Packard HP-UX"},
	{.key = 2, .value = "ELFOSABI_NETBSD", .description = "NetBSD"},
	{.key = 3, .value = "ELFOSABI_LINUX", .description = "Linux"},
	{.key = 6, .value = "ELFOSABI_SOLARIS", .description = "Sun Solaris"},
	{.key = 7, .value = "ELFOSABI_AIX", .description = "AIX"},
	{.key = 8, .value = "ELFOSABI_IRIX", .description = "IRIX"},
	{.key = 9, .value = "ELFOSABI_FREEBSD", .description = "FreeBSD"},
	{.key = 10, .value = "ELFOSABI_TRU64", .description = "Compaq TRU64 UNIX"},
	{.key = 11, .value = "ELFOSABI_MODESTO", .description = "Novell Modesto"},
	{.key = 12, .value = "ELFOSABI_OPENBSD", .description = "Open BSD"},
	{.key = 13, .value = "ELFOSABI_OPENVMS", .description = "Open VMS"},
	{.key = 14, .value = "ELFOSABI_NSK", .description = "Hewlett-Packard Non-Stop Kernel"},
    // architecture-specific
};

// ELF Header
typedef struct {
    union {
        unsigned char raw[EI_NIDENT_SIZE];
        e_ident_fields coocked;
    } e_ident;
    Elf32_Half e_type; // type of object file.
    Elf32_Half e_machine; // specifies required machine architecture.
    Elf32_Word e_version; // specifies version of elf file.
    Elf32_Addr e_entry; // specifies virtual address to which the system first transfer control. If zero - file doesn't contains entry point.
    Elf32_Off e_phoff; // byte offset of program header table.
    Elf32_Off e_shoff; // byte offset of section header table
    Elf32_Word e_flags; // processor-specific flags ("EF_machine_flag").
    Elf32_Half e_ehsize; // ELF header size in bytes.
    Elf32_Half e_phentsize; // size in bytes of each entry of program header.
    Elf32_Half e_phnum; // number of entries in program header table.
    Elf32_Half e_shentsize; // size in bytes of each entry of section header.
    Elf32_Half e_shnum; // number of entries in section header table.
    Elf32_Half e_shstrndx; // index of 'section name string table' of section header table. If section name string table doesn't exists in this file = SHN_UNDEF.
} Elf32_Ehdr;


// elf64

typedef uint64_t Elf64_Addr; // Unsigned program address
typedef uint16_t Elf64_Half; // Unsigned medium integer
typedef uint64_t Elf64_Off; // Unsigned file offset
typedef int32_t  Elf64_Sword; // Signed integer
typedef uint32_t Elf64_Word; // Unsigned integer
typedef uint64_t Elf64_Xword; // unsigned long integer
typedef int64_t  Elf64_Sxword; // signed long integer

struct elf64_word_descriptor {
    Elf64_Word key;
    char* value;
    char* description;
};

typedef struct {
    union {
        unsigned char   raw[EI_NIDENT_SIZE];
        e_ident_fields coocked;
    }               e_ident;
    Elf64_Half      e_type;
    Elf64_Half      e_machine;
    Elf64_Word      e_version;
    Elf64_Addr      e_entry;
    Elf64_Off       e_phoff;
    Elf64_Off       e_shoff;
    Elf64_Word      e_flags;
    Elf64_Half      e_ehsize;
    Elf64_Half      e_phentsize;
    Elf64_Half      e_phnum;
    Elf64_Half      e_shentsize;
    Elf64_Half      e_shnum;
    Elf64_Half      e_shstrndx;
} Elf64_Ehdr;

// If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), e_shnum has the value SHN_UNDEF (0) and the actual number of section header table entries is contained in the sh_size field of the section header at index 0 (otherwise, the sh_size member of the initial entry contains 0). 

struct elf32_half_descriptor ssi_shn_des[] = {
    {.key = 0, .value = "SHN_UNDEF", .description = "This value marks an undefined, missing, irrelevant, or otherwise meaningless section reference."},
    {.key = 0xFF00, .value = "SHN_LORESERVE", .description = "This value specifies the lower bound of the range of reserved indexes."},
    {.key = 0xFF00, .value = "SHN_LOPROC", .description = "Values in this inclusive range(0xFF00...0xFF1F) are reserved for processor-specific semantics."},
    {.key = 0xFF1F, .value = "SHN_HIPROC", .description = "Values in this inclusive range(0xFF00...0xFF1F) are reserved for processor-specific semantics."},
    {.key = 0xFF20, .value = "SHN_LOOS", .description = "Values in this inclusive range are reserved for operating system-specific semantics."},
    {.key = 0xFF3F, .value = "SHN_HIOS", .description = "Values in this inclusive range are reserved for operating system-specific semantics."},
    {.key = 0xFFF1, .value = "SHN_ABS", .description = "This value specifies absolute values for the corresponding reference. For example, symbols defined relative to section number SHN_ABS have absolute values and are not affected by relocation."},
    {.key = 0xFFF2, .value = "SHN_COMMON", .description = "Symbols defined relative to this section are common symbols, such as FORTRAN COMMON or unallocated C external variables."},
    {.key = 0xFFFF, .value = "SHN_XINDEX", .description = "This value is an escape value. It indicates that the actual section header index is too large to fit in the containing field and is to be found in another location (specific to the structure where it appears)."},
    {.key = 0xFFFF, .value = "SHN_HIRESERVE", .description = "This value specifies the upper bound of the range of reserved indexes."},
};

typedef struct {
    Elf32_Word	sh_name; // name of the section. Contains index into the section header string table section, giving the location of null-terminated string.
    Elf32_Word	sh_type; // category of section
    Elf32_Word	sh_flags; // attributes of section
    Elf32_Addr	sh_addr; // if section will appear in process image, then this member gives first byte where section should reside in memory. Otherwise, 0
    Elf32_Off	sh_offset; // byte offset, starting from file begin, of section in this file. If section is SHT_NOBITS, then ignore(?)
    Elf32_Word	sh_size; // size of section in bytes. If section is SHT_NOBITS, then ignore.
    Elf32_Word	sh_link; // This member holds a section header table index link, whose interpretation depends on the section type.
    Elf32_Word	sh_info; // This member holds extra information, whose interpretation depends on the section type. If the sh_flags field for this section header includes the attribute SHF_INFO_LINK, then this member represents a section header table index.
    Elf32_Word	sh_addralign; // Some sections have address alignment constraints. For example, if a section holds a doubleword, the system must ensure doubleword alignment for the entire section. The value of sh_addr must be congruent to 0, modulo the value of sh_addralign. Currently, only 0 and positive integral powers of two are allowed. Values 0 and 1 mean the section has no alignment constraints.
    Elf32_Word	sh_entsize; // Some sections hold a table of fixed-size entries, such as a symbol table. For such a section, this member gives the size in bytes of each entry.
} Elf32_Shdr;

typedef struct {
    Elf64_Word	sh_name;
    Elf64_Word	sh_type;
    Elf64_Xword	sh_flags;
    Elf64_Addr	sh_addr;
    Elf64_Off	sh_offset;
    Elf64_Xword	sh_size;
    Elf64_Word	sh_link;
    Elf64_Word	sh_info;
    Elf64_Xword	sh_addralign;
    Elf64_Xword	sh_entsize;
} Elf64_Shdr;

struct elf64_word_descriptor sh_type_des[] = {
    {.key = 0, .value = "SHT_NULL", .description = ""},
	{.key = 1, .value = "SHT_PROGBITS", .description = ""},
	{.key = 2, .value = "SHT_SYMTAB", .description = ""},
	{.key = 3, .value = "SHT_STRTAB", .description = ""},
	{.key = 4, .value = "SHT_RELA", .description = ""},
	{.key = 5, .value = "SHT_HASH", .description = ""},
	{.key = 6, .value = "SHT_DYNAMIC", .description = ""},
	{.key = 7, .value = "SHT_NOTE", .description = ""},
	{.key = 8, .value = "SHT_NOBITS", .description = ""},
	{.key = 9, .value = "SHT_REL", .description = ""},
	{.key = 10, .value = "SHT_SHLIB", .description = ""},
	{.key = 11, .value = "SHT_DYNSYM", .description = ""},
	{.key = 14, .value = "SHT_INIT_ARRAY", .description = ""},
	{.key = 15, .value = "SHT_FINI_ARRAY", .description = ""},
	{.key = 16, .value = "SHT_PREINIT_ARRAY", .description = ""},
	{.key = 17, .value = "SHT_GROUP", .description = ""},
	{.key = 18, .value = "SHT_SYMTAB_SHNDX", .description = ""},
	{.key = 0x60000000, .value = "SHT_LOOS", .description = ""},
	{.key = 0x6fffffff, .value = "SHT_HIOS", .description = ""},
	{.key = 0x70000000, .value = "SHT_LOPROC", .description = ""},
	{.key = 0x7fffffff, .value = "SHT_HIPROC", .description = ""},
	{.key = 0x80000000, .value = "SHT_LOUSER", .description = ""},
    {.key = 0xffffffff, .value = "SHT_HIUSER", .description = ""},
};

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

int main(int inc, char* inv[]){
    FILE* inputFile = fopen("a.out", "rb");
    if(inputFile == NULL){
        printf("%s", strerror(errno));
        return 1;
    }

    e_ident_fields elf_identification = {};
    size_t readed = fread(&elf_identification, 1, 4, inputFile);
    if((readed != 4) || memcmp(ELFMAG, &elf_identification, 4)){
        printf("Not elf file!.");
        return 2;
    }

    readed = fread(((unsigned char*)(&elf_identification))+4, 1, sizeof(e_ident_fields)-4, inputFile);
    if(readed != sizeof(e_ident_fields)-4){
        printf("Error when reading elf identification bytes. Readed %d, when %d needed.", readed, sizeof(e_ident_fields)-4);
        return 3;
    }

    printf("ELF Mag: %c%c%c%c\n", elf_identification.ELFMAG[0],elf_identification.ELFMAG[1],elf_identification.ELFMAG[2],elf_identification.ELFMAG[3]);
    
    struct elf_uchar_descriptor class = ei_class_des[elf_identification.EI_CLASS];
    printf("EI_CLASS: %s -> %s\n", class.value, class.description);
    struct elf_uchar_descriptor data = ei_data_des[elf_identification.EI_DATA];
    printf("EI_DATA: %s -> %s\n", data.value, data.description);
    struct elf32_word_descriptor version = ei_version_des[elf_identification.EI_VERSION];
    printf("EI_VERSION: %s -> %s\n", version.value, version.description);
    struct elf_uchar_descriptor osabi = ei_osabi_des[elf_identification.EI_OSABI];
    printf("EI_OSABI: %s -> %s\n", osabi.value, osabi.description);
    unsigned char abiversion = 0;
    if(osabi.key != 0) abiversion = elf_identification.EI_ABIVERSION;
    printf("EI_ABIVERSION: %d\n", abiversion);

    if(class.key != 2) {
        printf("Unsupported file class");
        return 4;
    }

    Elf64_Ehdr elf_header = {0};
    elf_header.e_ident.coocked = elf_identification;
    readed = fread(((char*)(&elf_header)) + EI_NIDENT_SIZE, 1, sizeof(Elf64_Ehdr) - EI_NIDENT_SIZE, inputFile);
    if(readed != sizeof(Elf64_Ehdr) - EI_NIDENT_SIZE) {
        printf("Error when reading header");
        return 5;
    }

    printf("Type: %"PRIu16"\n", elf_header.e_type);
    printf("Machine: %"PRIu16"\n", elf_header.e_machine);
    printf("Version: %"PRIu32"\n", elf_header.e_version);
    printf("Entry: %"PRIu64"\n", elf_header.e_entry);
    printf("Phoff: %"PRIu64"\n", elf_header.e_phoff);
    printf("Shoff: %"PRIu64"\n", elf_header.e_shoff);
    printf("Flags: %"PRIu32"\n", elf_header.e_flags);
    printf("Ehsize: %"PRIu16"\n", elf_header.e_ehsize);
    printf("Phentsize: %"PRIu16"\n", elf_header.e_phentsize);
    printf("Phnum: %"PRIu16"\n", elf_header.e_phnum);
    printf("Shentsize: %"PRIu16"\n", elf_header.e_shentsize);
    printf("Shnum: %"PRIu16"\n", elf_header.e_shnum);
    printf("Shstrndx: %"PRIu16"\n", elf_header.e_shstrndx);

    fclose(inputFile);
    return 0;
}
