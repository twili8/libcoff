//
// Created by dev on 9/16/26.
//

#include "worker.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>


int set_libcoff_options() {

    return 0;
}

static inline int is_machine_64bit(const uint16_t machine_type) {
    for (int i = 0; i < MACHINE_64BIT_COUNT; i++) {
        if (MACHINE_64BIT_TYPES[i] == machine_type) {
            return 1;
        }
    }
    return 0;
}

static inline uint16_t get_machine_type(const void* image) {
    if (!image) return 0;

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    const uint32_t* pe_sig = (const uint32_t*)((const uint8_t*)image + dos->e_lfanew);
    if (*pe_sig != IMAGE_NT_SIGNATURE) return 0;

    const IMAGE_FILE_HEADER* fh = (const IMAGE_FILE_HEADER*)(pe_sig + 1);
    return fh->Machine;
}

static void* get_nt_headers(const void* image) {
    if (!image) return 0;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (void*)((uint8_t*)image + dos->e_lfanew);
}

int is_image_valid(const void* image) {
    if (!image) return 0;

    const uint16_t machine = get_machine_type(image);
    if (machine == 0) return 0;

    void* nt = get_nt_headers(image);
    if (!nt) return 0;

    return *(const uint32_t*)nt == IMAGE_NT_SIGNATURE;
}

int is_image_have_entry_point(const void* image) {
    const uint16_t machine = get_machine_type(image);
    if (machine == 0) return 0;

    void* nt = get_nt_headers(image);
    if (!nt) return 0;

    if (is_machine_64bit(machine)) {
        return ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.AddressOfEntryPoint != 0;
    } else {
        return ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.AddressOfEntryPoint != 0;
    }
}

static int image_how_many_sections(const IMAGE_FILE_HEADER* image) {
    return image->NumberOfSections;
}

struct libcoff_image_section {
    struct libcoff_image_section* next;
    uint32_t virtual_address;
    uint32_t size;
};

static struct libcoff_image_section build_image_section_struct(const uint32_t va, const uint32_t size) {
    return (struct libcoff_image_section) {
        .virtual_address = va,
        .size = size
    };
}

static struct libcoff_image_section* helper_image_find_sections(
    const IMAGE_FILE_HEADER* file_header,
    const uint8_t* section_table,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    int nb_sections = image_how_many_sections(file_header);
    struct libcoff_image_section* head = NULL;
    struct libcoff_image_section* tail = NULL;

    for (int i = 0; i < nb_sections; i++) {
        const IMAGE_SECTION_HEADER* section =
            (const IMAGE_SECTION_HEADER*)(section_table + i * sizeof(*section));
        const uint32_t section_characteristics = section->Characteristics;
        uint32_t section_flags = 0;

        if (section_characteristics & IMAGE_SCN_MEM_EXECUTE) section_flags |= find_x;
        if (section_characteristics & IMAGE_SCN_MEM_WRITE) section_flags |= find_w;
        if (section_characteristics & IMAGE_SCN_MEM_READ) section_flags |= find_r;
        if (!(section_characteristics & IMAGE_SCN_MEM_WRITE)) section_flags |= find_ro;
        if (section_flags != (find_x | find_w | find_r | find_ro)) continue;

        struct libcoff_image_section* result =
            (struct libcoff_image_section*)malloc(sizeof(*result));
        if (!result) break;

        *result = build_image_section_struct(section->VirtualAddress, section->Misc.VirtualSize);
        if (!head) {
            head = result;
        } else {
            tail->next = result;
        }
        tail = result;
    }

    return head;
}

struct libcoff_image_section* image_find_sections(const void* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    if (!is_image_valid(image)) return 0;

    const uint8_t* nt = (const uint8_t*)get_nt_headers(image);
    const IMAGE_FILE_HEADER* file_header =
        (const IMAGE_FILE_HEADER*)(nt + sizeof(uint32_t));
    const uint8_t* section_table = nt + sizeof(uint32_t) + sizeof(*file_header) +
        file_header->SizeOfOptionalHeader;
    return helper_image_find_sections(file_header, section_table,
        find_x, find_w, find_r, find_ro);
}


static inline char* copy_symbol_name(const char* name) {
    const size_t length = strlen(name);
    char* copy = (char*)malloc(length + 1);
    if (!copy) return NULL;

    memcpy(copy, name, length + 1);
    return copy;
}

static struct libcoff_symbol* append_symbol(struct libcoff_symbol** head,
    struct libcoff_symbol** tail,
    const char* name,
    uint32_t virtual_address) {
    struct libcoff_symbol* symbol = (struct libcoff_symbol*)malloc(sizeof(*symbol));
    if (!symbol) return NULL;

    symbol->name = copy_symbol_name(name);
    if (!symbol->name) {
        free(symbol);
        return NULL;
    }
    symbol->virtual_address = virtual_address;
    symbol->next = NULL;

    if (*head == NULL) {
        *head = symbol;
    } else {
        (*tail)->next = symbol;
    }
    *tail = symbol;
    return symbol;
}

static struct libcoff_symbol* helper_list_symbols(
    const void* image,
    const IMAGE_DATA_DIRECTORY* export_directory_entry) {
    if (export_directory_entry->VirtualAddress == 0 ||
        export_directory_entry->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return NULL;
    }

    const uint8_t* base = (const uint8_t*)image;
    const IMAGE_EXPORT_DIRECTORY* exports =
        (const IMAGE_EXPORT_DIRECTORY*)(base + export_directory_entry->VirtualAddress);
    const uint32_t* names = (const uint32_t*)(base + exports->AddressOfNames);
    const uint16_t* ordinals = (const uint16_t*)(base + exports->AddressOfNameOrdinals);
    const uint32_t* functions = (const uint32_t*)(base + exports->AddressOfFunctions);

    struct libcoff_symbol* head = NULL;
    struct libcoff_symbol* tail = NULL;
    for (uint32_t i = 0; i < exports->NumberOfNames; i++) {
        if (ordinals[i] >= exports->NumberOfFunctions) {
            continue;
        }

        const char* name = (const char*)(base + names[i]);
        if (!append_symbol(&head, &tail, name, functions[ordinals[i]])) {
            break;
        }
    }

    return head;
}

struct libcoff_symbol* list_symbols(const void* image) {
    if (!is_image_valid(image)) return NULL;

    const uint16_t machine = get_machine_type(image);
    const IMAGE_DATA_DIRECTORY* export_directory;
    if (is_machine_64bit(machine)) {
        const IMAGE_NT_HEADERS64* headers = (const IMAGE_NT_HEADERS64*)get_nt_headers(image);
        if (headers->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
            return NULL;
        }
        export_directory = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        const IMAGE_NT_HEADERS32* headers = (const IMAGE_NT_HEADERS32*)get_nt_headers(image);
        if (headers->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
            return NULL;
        }
        export_directory = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    return helper_list_symbols(image, export_directory);
}
