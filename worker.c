//
// Created by dev on 9/16/26.
//

#include "worker.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

typedef void (*libcoff_free_memory)(void* ptr);
static libcoff_free_memory g_libcoff_free_memory = NULL;

typedef void* (*libcoff_alloc_memory)(uint64_t amt);
static libcoff_alloc_memory g_libcoff_alloc_memory;

/*
 * g_libcoff_alloc_memory MUST return zero-initialised memory regions
 * Otherwise it's UB
 */

int set_libcoff_options(
    void (*free_mem_callback)(void*),
    void* (*alloc_mem_callback)(uint64_t amt)
    ) {
    g_libcoff_free_memory = free_mem_callback;
    g_libcoff_alloc_memory = alloc_mem_callback;
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

static const IMAGE_DATA_DIRECTORY* get_image_data_directory(const void* image,
    const uint32_t directory) {
    const uint16_t machine = get_machine_type(image);
    const void* nt = get_nt_headers(image);
    if (!machine || !nt) return NULL;

    if (is_machine_64bit(machine)) {
        const IMAGE_NT_HEADERS64* headers = (const IMAGE_NT_HEADERS64*)nt;
        if (directory >= headers->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        return &headers->OptionalHeader.DataDirectory[directory];
    }

    const IMAGE_NT_HEADERS32* headers = (const IMAGE_NT_HEADERS32*)nt;
    if (directory >= headers->OptionalHeader.NumberOfRvaAndSizes) return NULL;
    return &headers->OptionalHeader.DataDirectory[directory];
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
    const uint32_t required_flags = (uint32_t)(find_x | find_w | find_r | find_ro);
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
        if (section_flags != required_flags) continue;

        struct libcoff_image_section* result =
            (struct libcoff_image_section*)g_libcoff_alloc_memory(sizeof(*result));
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


#define DEFINE_NAME_COPY(NAME, STRIP_EXTENSION)                         \
    static char* NAME(const char* value) {                              \
        const char* end = (STRIP_EXTENSION) ? strrchr(value, '.') : 0; \
        const size_t length = end ? (size_t)(end - value) : strlen(value); \
        char* copy = (char*)g_libcoff_alloc_memory(length + 1);         \
        if (!copy) return NULL;                                         \
        memcpy(copy, value, length);                                    \
        copy[length] = '\0';                                            \
        return copy;                                                     \
    }

DEFINE_NAME_COPY(copy_symbol_name, 0)
DEFINE_NAME_COPY(copy_library_name, 1)

static struct libcoff_symbol* append_symbol(struct libcoff_symbol** head,
    struct libcoff_symbol** tail,
    const char* name,
    uint32_t virtual_address) {
    struct libcoff_symbol* symbol = (struct libcoff_symbol*)g_libcoff_alloc_memory(sizeof(*symbol));
    if (!symbol) return NULL;

    symbol->name = copy_symbol_name(name);
    if (!symbol->name) {
        g_libcoff_free_memory(symbol);
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
    if (!export_directory_entry || export_directory_entry->VirtualAddress == 0 ||
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

    const IMAGE_DATA_DIRECTORY* export_directory =
        get_image_data_directory(image, IMAGE_DIRECTORY_ENTRY_EXPORT);
    return helper_list_symbols(image, export_directory);
}

void* get_image_entry_point(void* image) {
    if (is_machine_64bit(get_machine_type(image))) {
        const IMAGE_NT_HEADERS64* headers = (const IMAGE_NT_HEADERS64*)get_nt_headers(image);
        return (void*)headers->OptionalHeader.AddressOfEntryPoint;
    } else {
        const IMAGE_NT_HEADERS32* headers = (const IMAGE_NT_HEADERS32*)get_nt_headers(image);
        return (void*)headers->OptionalHeader.AddressOfEntryPoint;
    }
}

char* get_image_architecture(const void* image) {
    if (!is_image_valid(image)) return NULL;

    const uint16_t machine = get_machine_type(image);
    if (is_machine_64bit(machine)) {
        return "x64";
    } else {
        return "x86"; // maybe this should return "Unknown"
    }
}

static void free_symbol_list(struct libcoff_symbol* symbols) {
    while (symbols) {
        struct libcoff_symbol* next = symbols->next;
        g_libcoff_free_memory(symbols->name);
        g_libcoff_free_memory(symbols);
        symbols = next;
    }
}

static void free_imported_library(struct libcoff_imported_library* library) {
    if (!library) return;
    g_libcoff_free_memory(library->name);
    free_symbol_list(library->sym);
    g_libcoff_free_memory(library);
}

static int append_imported_symbol(struct libcoff_imported_library* library,
    const char* name,
    uint32_t virtual_address) {
    struct libcoff_symbol* tail = library->sym;
    while (tail && tail->next) tail = tail->next;

    if (!append_symbol(&library->sym, &tail, name, virtual_address)) return 0;
    library->nb_of_functions_imported++;
    return 1;
}

struct libcoff_imported_library* libcoff_get_imported_libraries(const void* image) {
    if (!is_image_valid(image)) return NULL;

    const uint16_t machine = get_machine_type(image);
    const IMAGE_DATA_DIRECTORY* import_directory =
        get_image_data_directory(image, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!import_directory) return NULL;

    if (import_directory->VirtualAddress == 0 ||
        import_directory->Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return NULL;

    const uint8_t* base = (const uint8_t*)image;
    const IMAGE_IMPORT_DESCRIPTOR* descriptor =
        (const IMAGE_IMPORT_DESCRIPTOR*)(base + import_directory->VirtualAddress);
    struct libcoff_imported_library* head = NULL;
    struct libcoff_imported_library* tail = NULL;

    for (; descriptor->DUMMYUNIONNAME.OriginalFirstThunk || descriptor->Name ||
           descriptor->FirstThunk; descriptor++) {
        struct libcoff_imported_library* library =
            (struct libcoff_imported_library*)g_libcoff_alloc_memory(sizeof(*library));
        if (!library) break;

        library->name = copy_library_name((const char*)(base + descriptor->Name));
        if (!library->name) {
            free_imported_library(library);
            break;
        }

        const uint32_t thunk_rva = descriptor->DUMMYUNIONNAME.OriginalFirstThunk
            ? descriptor->DUMMYUNIONNAME.OriginalFirstThunk : descriptor->FirstThunk;
        if (is_machine_64bit(machine)) {
            const uint64_t* thunks = (const uint64_t*)(base + thunk_rva);
            for (uint32_t index = 0; thunks[index] != 0; index++) {
                if (thunks[index] & UINT64_C(0x8000000000000000)) continue;
                const char* function_name = (const char*)(base + (uint32_t)thunks[index] + sizeof(WORD));
                if (!append_imported_symbol(library, function_name,
                        descriptor->FirstThunk + index * sizeof(uint64_t))) {
                    free_imported_library(library);
                    library = NULL;
                    break;
                }
            }
        } else {
            const uint32_t* thunks = (const uint32_t*)(base + thunk_rva);
            for (uint32_t index = 0; thunks[index] != 0; index++) {
                if (thunks[index] & 0x80000000U) continue;
                const char* function_name = (const char*)(base + thunks[index] + sizeof(WORD));
                if (!append_imported_symbol(library, function_name,
                        descriptor->FirstThunk + index * sizeof(uint32_t))) {
                    free_imported_library(library);
                    library = NULL;
                    break;
                }
            }
        }

        if (!library) break;
        if (!head) head = library;
        else tail->next = library;
        tail = library;
    }

    return head;
}

void free_imported_libraries(struct libcoff_imported_library* libraries) {
    while (libraries) {
        struct libcoff_imported_library* next = libraries->next;
        free_imported_library(libraries);
        libraries = next;
    }
}
