#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <elf.h>
#include <string.h>

typedef struct SectionInfo {
    size_t addr;
    size_t size;
    size_t offset;
    char *name;
} SectionInfo;

typedef struct Node {
    Elf64_Xword d_val;
    struct Node *next;
} Node;

char **importedFunctions = NULL;
size_t importedFunctionNum = 0;
void **handles = NULL;
size_t handleNum = 0;

char *gotpltAddr = NULL;
size_t *rtld_ro = NULL;

void *dl_fixup(void *ptr, int index) {
    for(int i = 0; i < handleNum; i++) {
        size_t func = dlsym(handles[i], importedFunctions[index]);
        if(func) {
            *(size_t *)(gotpltAddr + (index + 3) * 8) = func;
            return (void *)func;
        }
    }
}

void __attribute__((naked)) LazyBinding() {
    asm volatile(
        "push   rbx\n"
        "mov    rbx,rsp\n"
        "and    rsp,0xffffffffffffffc0\n"
        "sub    rsp, 0x380\n"
        "mov    QWORD PTR [rsp],rax\n"
        "mov    QWORD PTR [rsp+0x8],rcx\n"
        "mov    QWORD PTR [rsp+0x10],rdx\n"
        "mov    QWORD PTR [rsp+0x18],rsi\n"
        "mov    QWORD PTR [rsp+0x20],rdi\n"
        "mov    QWORD PTR [rsp+0x28],r8\n"
        "mov    QWORD PTR [rsp+0x30],r9\n"
        "mov    eax,0xee\n"
        "xor    edx,edx\n"
        "mov    QWORD PTR [rsp+0x250],rdx\n"
        "mov    QWORD PTR [rsp+0x258],rdx\n"
        "mov    QWORD PTR [rsp+0x260],rdx\n"
        "mov    QWORD PTR [rsp+0x268],rdx\n"
        "mov    QWORD PTR [rsp+0x270],rdx\n"
        "mov    QWORD PTR [rsp+0x278],rdx\n"
        "xsavec [rsp+0x40]\n"
        "mov    rsi,QWORD PTR [rbx+0x10]\n"
        "mov    rdi,QWORD PTR [rbx+0x8]\n"
        "call   dl_fixup\n"
        "mov    r11,rax\n"
        "mov    eax,0xee\n"
        "xor    edx,edx\n"
        "xrstor [rsp+0x40]\n"
        "mov    r9,QWORD PTR [rsp+0x30]\n"
        "mov    r8,QWORD PTR [rsp+0x28]\n"
        "mov    rdi,QWORD PTR [rsp+0x20]\n"
        "mov    rsi,QWORD PTR [rsp+0x18]\n"
        "mov    rdx,QWORD PTR [rsp+0x10]\n"
        "mov    rcx,QWORD PTR [rsp+0x8]\n"
        "mov    rax,QWORD PTR [rsp]\n"
        "mov    rsp,rbx\n"
        "mov    rbx,QWORD PTR [rsp]\n"
        "add    rsp,0x18\n"
        "jmp    r11\n"
    );
}

char *LoadELF(char *image, size_t baseaddr, size_t *retSize, char *libpath[], size_t libpathSize) {
    int fd = open(image, O_RDONLY);
    struct stat st;
    stat(image, &st);

    char *elf = (char *)mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(elf + ehdr->e_shoff);
    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    char *sh_strtab_p = elf + sh_strtab->sh_offset;

    SectionInfo *sections = (SectionInfo *)malloc(sizeof(SectionInfo) * ehdr->e_shnum);

    Elf64_Shdr *iter = shdr;
    size_t size = 0;
    for(int i = 0; i < ehdr->e_shnum; i++) {
        sections[i].addr = iter->sh_addr;
        sections[i].size = iter->sh_size;
        sections[i].offset = iter->sh_offset;
        sections[i].name = sh_strtab_p + iter->sh_name;

        if(size <= iter->sh_addr) {
            size = iter->sh_addr + iter->sh_size;
        }

        iter++;
    }

    size -= baseaddr;
    size = (size / 0x1000 + 1) * 0x1000;

    *retSize = size;

    Elf64_Dyn *dynamic = NULL;
    Elf64_Sym *dynSym = NULL;
    char *dynstr = NULL;
    size_t dynNum = 0;
    size_t dynSymNum = 0;
    for(int i = 0; i < ehdr->e_shnum; i++) {
        if(!strcmp(sections[i].name, ".dynamic")) {
            dynamic = (Elf64_Dyn *)(elf + sections[i].offset);
            dynNum = sections[i].size / sizeof(Elf64_Dyn);
        }
        else if(!strcmp(sections[i].name, ".dynstr")) {
            dynstr = elf + sections[i].offset;
        }
        else if(!strcmp(sections[i].name, ".dynsym")) {
            dynSym = (Elf64_Sym *)(elf + sections[i].offset);
            dynSymNum = sections[i].size / sizeof(Elf64_Sym);
        }
    }

    Node *head = NULL;
    Node *tail = NULL;
    size_t nodeSize = 0;

    Elf64_Dyn *dynIter = dynamic;
    for(int i = 0; i < ehdr->e_shnum; i++) {
        if(dynIter->d_tag == DT_NEEDED) {
            Node *node = (Node *)malloc(sizeof(Node));
            node->d_val = dynIter->d_un.d_val;
            node->next = NULL;
            if(head == NULL) {
                head = tail = node;
            } else {
                tail->next = node;
                tail = node;
            }
            nodeSize++;
        }
        dynIter++;
    }

    handles = malloc(sizeof(size_t) * nodeSize);
    handleNum = nodeSize;

    Node *nodeIter = head;
    for(int p = 0; nodeIter != NULL; nodeIter = nodeIter->next, p++) {
        for(int i = 0; i < libpathSize; i++) {
            char *libname = dynstr + nodeIter->d_val;
            char *ptr = malloc(strlen(libpath[i]) + strlen(libname) + 1);
            sprintf(ptr, "%s/%s", libpath[i], libname);
            
            struct stat st;
            if(stat(ptr, &st) != -1) {
                // puts(ptr);
                handles[p] = dlopen(ptr, RTLD_LAZY | RTLD_NODELETE);
                free(ptr);
                break;
            }

            free(ptr);
        }
    }

    Elf64_Sym *dynSymIter = dynSym;
    for(int i = 0; i < dynSymNum; i++) {
        char *imported = dynstr + dynSymIter->st_name;
        if ((dynSymIter->st_info & STT_FUNC) && dynSymIter->st_value == 0) {
            importedFunctionNum++;
        }
        dynSymIter++;
    }

    importedFunctions = (char **)malloc(sizeof(size_t) * importedFunctionNum);

    dynSymIter = dynSym;
    for(int i = 0, k = 0; i < dynSymNum; i++) {
        char *imported = dynstr + dynSymIter->st_name;
        if ((dynSymIter->st_info & STT_FUNC) && dynSymIter->st_value == 0) {
            importedFunctions[k] = malloc(strlen(imported) + 1);
            strcpy(importedFunctions[k++], imported);
        }
        dynSymIter++;
    }

    char *virtImage = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    for(int i = 0; i < ehdr->e_shnum; i++) {
        if(!sections[i].size || !sections[i].addr)
            continue;

        memcpy(virtImage + sections[i].addr - baseaddr, elf + sections[i].offset, sections[i].size);
        if(!strcmp(sections[i].name, ".got.plt")) {
            gotpltAddr = virtImage + sections[i].addr - baseaddr;
            for(size_t k = 0; k < sections[i].size; k += 8) {
                size_t *ptr = (size_t *)(gotpltAddr + k);
                if(*ptr != 0) {
                    *ptr = *ptr + (size_t)virtImage - (size_t)baseaddr;
                }
                else {
                    *ptr = (size_t)LazyBinding;
                }
            }
        }
    }

    rtld_ro = malloc(0x380);

    Node *fptr = head;
    
    for(Node *fptr = head; fptr != NULL;) {
        Node *ptr = fptr->next;
        free(fptr);
        fptr = ptr;
    }

    munmap(elf, st.st_size);
    close(fd);

    return virtImage;
}