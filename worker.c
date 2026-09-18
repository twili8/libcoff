//
// Created by dev on 9/16/26.
//

#include "worker.h"
#include <stdlib.h>
#include <stddef.h>


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

static int detect_architecture(void* image) {
    if (!image) return 0;

    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)image;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    uint32_t* pe_sig_ptr = (uint32_t*)((uint8_t*)image + dos_header->e_lfanew);
    if (*pe_sig_ptr != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    const IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)(pe_sig_ptr + 1);

    return is_machine_64bit(file_header->Machine);
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
    return ((const IMAGE_NT_HEADERS*)image)->FileHeader.NumberOfSections;
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

#define SECTION_TABLE_OFFSET(IMG) \
        sizeof(IMAGE_FILE_HEADER) + \
        IMG->FileHeader.SizeOfOptionalHeader;

static struct libcoff_image_section* helper_image_find_sections_32(const IMAGE_NT_HEADERS32* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {


    int nb_sections = image_how_many_sections(&image->FileHeader);
    int matches = 0;
    uint32_t section_virtual_address = 0;
    uint32_t section_size = 0;

    struct libcoff_image_section* head = NULL;
    struct libcoff_image_section* tail = NULL;

    while (nb_sections--) {
        const uint32_t section_table_offset = SECTION_TABLE_OFFSET(image);
        const IMAGE_SECTION_HEADER* section =
            (const IMAGE_SECTION_HEADER*)(image + section_table_offset);

        const char* section_name = (const char*)section->Name;
        section_virtual_address = section->VirtualAddress;
        section_size = section->Misc.VirtualSize;
        uint32_t section_characteristics = section->Characteristics;
        uint32_t section_flags = 0;

        if (section_characteristics & IMAGE_SCN_MEM_EXECUTE) section_flags |= find_x;
        if (section_characteristics & IMAGE_SCN_MEM_WRITE) section_flags |= find_w;
        if (section_characteristics & IMAGE_SCN_MEM_READ) section_flags |= find_r;
        if (! (section_characteristics & IMAGE_SCN_MEM_WRITE)) section_flags |= find_ro;
        if (section_flags == (find_x | find_w | find_r | find_ro)) {
            matches++;
        }
    }

    while (matches--) {
        struct libcoff_image_section* section = (struct libcoff_image_section*)malloc(sizeof(struct libcoff_image_section));
        if (!section) {
            break;
        }
        *section = build_image_section_struct(section_virtual_address, section_size);
        section->next = NULL;

        if (head == NULL) {
            head = section;
            tail = section;
        } else {
            tail->next = section;
            tail = section;
        }
    }

    return head;
}

static struct libcoff_image_section* helper_image_find_sections_64(const IMAGE_NT_HEADERS64* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    int nb_sections = image_how_many_sections(&image->FileHeader);
    int matches = 0;
    uint32_t section_virtual_address = 0;
    uint32_t section_size = 0;
    struct libcoff_image_section* head = NULL;
    struct libcoff_image_section* tail = NULL;

    while (nb_sections--) {
        const uint32_t section_table_offset = SECTION_TABLE_OFFSET(image);
        const IMAGE_SECTION_HEADER* section =
            (const IMAGE_SECTION_HEADER*)(image + section_table_offset);

        const char* section_name = (const char*)section->Name;
        section_virtual_address = section->VirtualAddress;
        section_size = section->Misc.VirtualSize;
        uint32_t section_characteristics = section->Characteristics;
        uint32_t section_flags = 0;

        if (section_characteristics & IMAGE_SCN_MEM_EXECUTE) section_flags |= find_x;
        if (section_characteristics & IMAGE_SCN_MEM_WRITE) section_flags |= find_w;
        if (section_characteristics & IMAGE_SCN_MEM_READ) section_flags |= find_r;
        if (! (section_characteristics & IMAGE_SCN_MEM_WRITE)) section_flags |= find_ro;
        if (section_flags == (find_x | find_w | find_r | find_ro)) {
            matches++;
        }
    }

    while (matches--) {
        struct libcoff_image_section* section = (struct libcoff_image_section*)malloc(sizeof(struct libcoff_image_section));
        if (!section) {
            break;
        }
        *section = build_image_section_struct(section_virtual_address, section_size);
        section->next = NULL;

        if (head == NULL) {
            head = section;
            tail = section;
        } else {
            tail->next = section;
            tail = section;
        }
    }

    return head;
}

int image_find_sections(const void* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    if (!is_image_valid(image)) return 0;

    if (is_machine_64bit(get_machine_type(image))) {
        const IMAGE_NT_HEADERS64* i = image;
        return helper_image_find_sections_64(i, find_x, find_w, find_r, find_ro);
    } else {
        const IMAGE_NT_HEADERS32* i = image;
        return helper_image_find_sections_32(i, find_x, find_w, find_r, find_ro);
    }

    return 0;
}

struct libcoff_image_section {
    struct libcoff_image_section* next;
    uint32_t virtual_address;
    uint32_t size;
};