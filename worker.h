//
// Created by twilight on 9/16/26.
//

#ifndef LIBCOFF_DEFINITIONS_H
#define LIBCOFF_DEFINITIONS_H

/* The PE file header consists of a Microsoft MS-DOS stub, the PE signature, the COFF file header, and an optional
 * header. A COFF object file header consists of a COFF file header and an optional header. In both cases, the file
 * headers are followed immediately by section headers.
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */


/* Don't include windows.h along with this header it will probably fail to compile.
 * Use the library's API directly.
 */
#include <stdint.h>

#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef int32_t  LONG;
typedef int64_t  LONGLONG;

// Microsoft PE Format Documentation
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
typedef enum _IMAGE_FILE_MACHINE {
    IMAGE_FILE_MACHINE_UNKNOWN           = 0x0000,
    IMAGE_FILE_MACHINE_TARGET_HOST       = 0x0001, // interact with the host and not a WoW guest
    IMAGE_FILE_MACHINE_I386              = 0x014C, // Intel 386
    IMAGE_FILE_MACHINE_R3000             = 0x0162, // MIPS little-endian, 0x160 big-endian
    IMAGE_FILE_MACHINE_R4000             = 0x0166, // MIPS little-endian
    IMAGE_FILE_MACHINE_R10000            = 0x0168, // MIPS little-endian
    IMAGE_FILE_MACHINE_WCEMIPSV2         = 0x0169, // MIPS little-endian WCE v2
    IMAGE_FILE_MACHINE_ALPHA             = 0x0184, // Alpha_AXP
    IMAGE_FILE_MACHINE_SH3               = 0x01A2, // SH3 little-endian
    IMAGE_FILE_MACHINE_SH3DSP            = 0x01A3, // SH3DSP
    IMAGE_FILE_MACHINE_SH3E              = 0x01A4, // SH3E little-endian
    IMAGE_FILE_MACHINE_SH4               = 0x01A6, // SH4 little-endian
    IMAGE_FILE_MACHINE_SH5               = 0x01A8, // SH5
    IMAGE_FILE_MACHINE_ARM               = 0x01C0, // ARM Little-Endian
    IMAGE_FILE_MACHINE_THUMB             = 0x01C2, // ARM Thumb/Thumb-2 Little-Endian
    IMAGE_FILE_MACHINE_ARMNT             = 0x01C4, // ARM Thumb-2 Little-Endian
    IMAGE_FILE_MACHINE_AM33              = 0x01D3, // Matsushita AM33
    IMAGE_FILE_MACHINE_POWERPC           = 0x01F0, // IBM PowerPC Little-Endian
    IMAGE_FILE_MACHINE_POWERPCFP         = 0x01F1, // POWERPCFP
    IMAGE_FILE_MACHINE_IA64              = 0x0200, // Intel 64 (Itanium)
    IMAGE_FILE_MACHINE_MIPS16            = 0x0266, // MIPS
    IMAGE_FILE_MACHINE_ALPHA64           = 0x0284, // ALPHA64 (64-bit Alpha)
    IMAGE_FILE_MACHINE_AXP64             = 0x0284, // ALPHA64, legacy alias
    IMAGE_FILE_MACHINE_MIPSFPU           = 0x0366, // MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16         = 0x0466, // MIPS16 with FPU
    IMAGE_FILE_MACHINE_TRICORE           = 0x0520, // Infineon
    IMAGE_FILE_MACHINE_CEF               = 0x0CEF, // CEF (Common Executable Format)
    IMAGE_FILE_MACHINE_EBC               = 0x0EBC, // EFI Byte Code
    IMAGE_FILE_MACHINE_AMD64             = 0x8664, // AMD64 (K8)
    IMAGE_FILE_MACHINE_M32R              = 0x9041, // M32R little-endian
    IMAGE_FILE_MACHINE_ARM64             = 0xAA64, // ARM64 Little-Endian
    IMAGE_FILE_MACHINE_CEE               = 0xC0EE  // CEE (Common Language Runtime)
} IMAGE_FILE_MACHINE;

const uint16_t MACHINE_64BIT_TYPES[] = {
    IMAGE_FILE_MACHINE_IA64,      // 0x0200
    IMAGE_FILE_MACHINE_ALPHA64,   // 0x0284
    IMAGE_FILE_MACHINE_AMD64,     // 0x8664
    IMAGE_FILE_MACHINE_ARM64      // 0xAA64
};

const int MACHINE_64BIT_COUNT = sizeof(MACHINE_64BIT_TYPES) / sizeof(MACHINE_64BIT_TYPES[0]);

// IMAGE_FILE_HEADER.Characteristics field
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001 // Relocation info stripped from file
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002 // File is executable (no unresolved external references)
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004 // COFF line numbers stripped from file
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008 // COFF symbol table entries stripped from file
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010 // Aggressively trim working set (obsolete as of Windows 2000)
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020 // App can handle >2GB addresses
#define IMAGE_FILE_16BIT_MACHINE             0x0040 // not documented publicly, obsolete in practice but here for
                                                    // completeness
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080 // Bytes of word are reversed (obsolete)
#define IMAGE_FILE_32BIT_MACHINE             0x0100 // 32-bit word machine
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200 // Debugging info removed and stored in another file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400 // If on removable media, copy and run from swap file
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800 // If on network, copy and run from swap file
#define IMAGE_FILE_SYSTEM                    0x1000 // image is a system file
#define IMAGE_FILE_DLL                       0x2000 // image is a DLL
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000 // File should only be run on a uniprocessor machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000 // Bytes of word are reversed (Obsolete)


// IMAGE_SECTION_HEADER.Characteristics field
#define IMAGE_SCN_TYPE_REG                   0x00000000 // Reserved
#define IMAGE_SCN_TYPE_DSECT                 0x00000001 // Reserved
#define IMAGE_SCN_TYPE_NOLOAD                0x00000002 // Reserved
#define IMAGE_SCN_TYPE_GROUP                 0x00000004 // Reserved
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008 // Reserved (Replaced by IMAGE_SCN_ALIGN_1BYTES)
#define IMAGE_SCN_TYPE_COPY                  0x00000010 // Reserved

#define IMAGE_SCN_CNT_CODE                   0x00000020 // Contains executable code
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040 // Contains initialized data
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080 // Contains uninitialized data
#define IMAGE_SCN_LNK_INFO                   0x00000200 // Contains comments/info (object files)
#define IMAGE_SCN_LNK_REMOVE                 0x00000800 // Will not become part of image (object files)
#define IMAGE_SCN_LNK_COMDAT                 0x00001000 // Contains COMDAT data
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000 // Can be discarded after load
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000 // Cannot be cached
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000 // Cannot be paged
#define IMAGE_SCN_MEM_SHARED                 0x10000000 // Can be shared in memory
#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000 // Section contains extended relocations
#define IMAGE_SCN_MEM_EXECUTE                0x20000000 // Executable as code
#define IMAGE_SCN_MEM_READ                   0x40000000 // Readable
#define IMAGE_SCN_MEM_WRITE                  0x80000000 // Writable
#define IMAGE_SCN_LNK_OTHER                  0x00000100 // Reserved
#define IMAGE_SCN_LNK_OVER                   0x00000400 // Reserved

// obsolete
#define IMAGE_SCN_MEM_PROTECTED              0x00004000 // Obsolete
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000 // Reset speculative exceptions handling bits in the TLB entries
#define IMAGE_SCN_GPREL                      0x00008000 // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000 // Obsolete
#define IMAGE_SCN_MEM_SYSHEAP                0x00010000 // Obsolete
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000 // Obsolete
#define IMAGE_SCN_MEM_16BIT                  0x00020000 // Obsolete (Overlaps with PURGEABLE)
#define IMAGE_SCN_MEM_LOCKED                 0x00040000 // Obsolete
#define IMAGE_SCN_MEM_PRELOAD                0x00080000 // Obsolete

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000 // default alignment on most linkers
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000 // Mask for extracting alignment value


// IMAGE_OPTIONAL_HEADER.DllCharacteristics
#define IMAGE_LIBRARY_PROCESS_INIT           0x0001 // Reserved (Originally for process init callback)
#define IMAGE_LIBRARY_PROCESS_TERM           0x0002 // Reserved (Originally for process term callback)
#define IMAGE_LIBRARY_THREAD_INIT            0x0004 // Reserved (Originally for thread init callback)
#define IMAGE_LIBRARY_THREAD_TERM            0x0008 // Reserved (Originally for thread term callback)

#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020 // Image can handle a high entropy 64-bit VA space
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE       0x0040 // DLL can move (ASLR)
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080 // Code Integrity checks enforced
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT          0x0100 // Image is NX compatible (DEP)
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION       0x0200 // Isolation aware but do not isolate the image
#define IMAGE_DLLCHARACTERISTICS_NO_SEH             0x0400 // Does not use structured exception (SE) handling
#define IMAGE_DLLCHARACTERISTICS_NO_BIND            0x0800 // Do not bind the image
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER       0x1000 // Image must execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER         0x2000 // WDM driver
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF           0x4000 // image supports Control Flow Guard
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000 // Terminal Server aware

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;      // Magic number: "MZ" (0x5A4D)
    WORD e_cblp;       // Bytes on last page of file
    WORD e_cp;         // Pages in file
    WORD e_crlc;       // Relocations
    WORD e_cparhdr;    // Size of header in paragraphs
    WORD e_minalloc;   // Minimum extra paragraphs needed
    WORD e_maxalloc;   // Maximum extra paragraphs needed
    WORD e_ss;         // Initial (relative) SS value
    WORD e_sp;         // Initial SP value
    WORD e_csum;       // Checksum
    WORD e_ip;         // Initial IP value
    WORD e_cs;         // Initial (relative) CS value
    WORD e_lfarlc;     // File address of relocation table
    WORD e_ovno;       // Overlay number
    WORD e_res[4];     // Reserved words
    WORD e_oemid;      // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;    // OEM information; e_oemid specific
    WORD e_res2[10];   // Reserved words
    LONG e_lfanew;     // File address of new exe header (ptr to IMAGE_NT_HEADERS)
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress; // Relative Virtual Address (RVA)
    DWORD Size;           // Size in bytes
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD                 Magic;                       // 0x10B (PE32) or 0x107 (ROM)
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;         // RVA of entry point
    DWORD                BaseOfCode;
    DWORD                BaseOfData;                  // PE32 only
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;           // Reserved, must be 0
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;                 // Obsolete
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;                       // 0x20B (PE32+)
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    QWORD                ImageBase;                   // 64-bit
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    QWORD                SizeOfStackReserve;          // 64-bit
    QWORD                SizeOfStackCommit;           // 64-bit
    QWORD                SizeOfHeapReserve;           // 64-bit
    QWORD                SizeOfHeapCommit;            // 64-bit
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;                   // "PE\0\0" (0x00004550)
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define IMAGE_NT_SIGNATURE 0x00004550 // PE00

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;       // 0 for terminating null import descriptor
        DWORD OriginalFirstThunk;    // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD TimeDateStamp;             // 0 if not bound, -1 if bound, else real date/time
    DWORD ForwarderChain;            // -1 if no forwarders
    DWORD Name;                      // RVA to ASCII DLL name
    DWORD FirstThunk;                // RVA to IAT (if bound, this is the bound IAT)
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

// export dir
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;                      // RVA to DLL name
    DWORD Base;                      // Starting ordinal number
    DWORD NumberOfFunctions;         // Number of functions in EAT
    DWORD NumberOfNames;             // Number of entries in name table
    DWORD AddressOfFunctions;        // RVA of Export Address Table
    DWORD AddressOfNames;            // RVA of Export Name Pointer Table
    DWORD AddressOfNameOrdinals;     // RVA of Export Ordinal Table
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// relocation
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;            // RVA of the block
    DWORD SizeOfBlock;               // Size of the block in bytes
    // WORD TypeOffset[1];           // Array of relocation entries follows
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

#define IMAGE_REL_BASED_ABSOLUTE           0
#define IMAGE_REL_BASED_HIGH               1
#define IMAGE_REL_BASED_LOW                2
#define IMAGE_REL_BASED_HIGHLOW            3
#define IMAGE_REL_BASED_HIGHADJ            4
#define IMAGE_REL_BASED_DIR64              10

// dbg
typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Type;                      // Format of debug info, see IMAGE_DEBUG_TYPE_*
    DWORD SizeOfData;                // Size of debug data
    DWORD AddressOfRawData;          // RVA of debug data
    DWORD PointerToRawData;          // File pointer to debug data
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

// dbg type enum
#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2  // PDB/CodeView info
#define IMAGE_DEBUG_TYPE_FPO              3  // Frame Pointer Omission
#define IMAGE_DEBUG_TYPE_MISC             4  // Location of DBG file
#define IMAGE_DEBUG_TYPE_EXCEPTION        5  // Copy of .pdata section
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_REPRO            16 // PE determinism/reproducibility

// rsrc
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    WORD  NumberOfNamedEntries;
    WORD  NumberOfIdEntries;
    // IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset : 31;
            DWORD NameIsString : 1;
        } DUMMYSTRUCTNAME;
        DWORD Name;
        WORD  Id;
    } DUMMYUNIONNAME;
    union {
        DWORD OffsetToData;
        struct {
            DWORD OffsetToDirectory : 31;
            DWORD DataIsDirectory : 1;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

// .tls
typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD StartAddressOfRawData;
    DWORD EndAddressOfRawData;
    DWORD AddressOfIndex;
    DWORD AddressOfCallBacks;        // PIMAGE_TLS_CALLBACK *
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    QWORD StartAddressOfRawData;
    QWORD EndAddressOfRawData;
    QWORD AddressOfIndex;
    QWORD AddressOfCallBacks;        // PIMAGE_TLS_CALLBACK *
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

// TLS Callback Prototype
typedef void (__stdcall *PIMAGE_TLS_CALLBACK)(
    void* DllHandle,
    DWORD Reason,
    void* Reserved
);

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME]; // 8-byte null-padded UTF-8 string
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;               // Total size of section in memory
    } Misc;
    DWORD VirtualAddress;                // RVA of first byte in memory
    DWORD SizeOfRawData;                 // Size of initialized data on disk
    DWORD PointerToRawData;              // File pointer to raw data
    DWORD PointerToRelocations;          // File pointer to relocation entries
    DWORD PointerToLinenumbers;          // File pointer to line numbers
    WORD  NumberOfRelocations;           // Number of relocation entries
    WORD  NumberOfLinenumbers;           // Number of line number entries
    DWORD Characteristics;               // Section flags
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


// subsystems
#define IMAGE_SUBSYSTEM_UNKNOWN              0
#define IMAGE_SUBSYSTEM_NATIVE               1  // No subsystem required, drivers only
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2  // Windows GUI
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3  // Windows Console
#define IMAGE_SUBSYSTEM_POSIX_CUI            7  // POSIX Console
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9  // Windows CE
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10 // EFI Application
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

#endif //LIBCOFF_DEFINITIONS_H
