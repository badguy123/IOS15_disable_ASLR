#include <pongo.h>
#include "capstone/capstone.h"


char* module_name = "kdemo";

void __assert_rtn(const char *func, const char *file, int line, const char *expr) {
    // 打印断言失败信息到标准错误流
    fprintf(stderr, 
            "Assertion failed: (%s), function %s, file %s, line %d.\n",
            expr, func, file, line);
    
    // 终止程序（通常调用 abort()）
    fflush(stderr);  // 确保输出刷新
    abort();
}

void disassemble(const char *cmd, char *args) {
    csh handle = NULL;
    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
    if(err != CS_ERR_OK){
        printf("cs_open failed: %x\n", err);
        return;
    }

    uint64_t addr = strtoull(args, NULL, 16);
    uint64_t len = 0x60;
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));
    if (arg1) {
        len = strtoull(arg1, NULL, 10);
    }
    
    cs_insn* insn;
    size_t count = cs_disasm(handle, (unsigned char*)addr, len * 4, addr, 0, &insn);
    // printf("Got %d ins\n", count);
    if (count) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%llx  ", insn[j].address);
            for (int off = 0; off < insn[j].size; off++){
                printf("%02X ", insn[j].bytes[off]);
            }
            // printf("\t%s\t\t%s\n", insn[j].mnemonic, insn[j].op_str);
            printf("0x%llx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    
}

void kfind(const char* cmd, char* args){
    struct mach_header_64* hdr = xnu_header();
    xnu_pf_range_t* xnu_text_exec_range = xnu_pf_section(hdr, "__TEXT_EXEC", "__text");

    printf("xnu text device base: %x va: %x\n", xnu_text_exec_range->device_base, xnu_text_exec_range->va);
    printf("gDeviceTree: %x\n", gDeviceTree);
    printf("hdr %x\n", hdr);
    printf("gIOBase %x\n", gIOBase);
}
int my_isprint(int c) {
    // 可打印字符的ASCII范围通常是32（空格）到126（波浪号）
    if (c >= 32 && c <= 126) {
        return 1; // 是可打印字符
    } else {
        return 0; // 不是可打印字符
    }
}

#define HEXDUMP_COLS 16
// from https://gist.github.com/richinseattle/c527a3acb6f152796a580401057c78b4
void _hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;
    
    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++){
        /* print offset */
        if(i % HEXDUMP_COLS == 0){
                printf("0x%09llx: ", (((uint64_t)mem)+i));
        }

        /* print hex data */
        if(i < len){
                printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
                printf("   ");
        }
            
        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)){
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++){
                if(j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if(my_isprint(((char*)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char*)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}




void hexdump0(const char *cmd, char *args) {
    
    uint64_t base = strtoull(args, NULL, 16);
    uint64_t size = 0x60;
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));
    if (arg1) {
        size = strtoull(arg1, NULL, 16);
    }
    
    _hexdump(base, size);
    
}

uint32_t* find_next_insn(uint32_t* from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while(num)
    {
        if((*from & mask) == (insn & mask))
        {
            return from;
        }
        from++;
        num--;
    }
    return NULL;
}


bool aslr_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {

    uint32_t* aslr_ret = (uint32_t*)find_next_insn(opcode_stream, 0x10, 0xf94013ea, 0xFFFFFFFF);
    if(!aslr_ret){
        return false;
    }

    uint32_t* op1 = &opcode_stream[0];
    uint32_t* op3 = &opcode_stream[2];
    op3[0] = 0xd2800008;
    printf("Fond %x\n", *op1);
    _hexdump(op1, 0x50);
    return true;
}

void mem_patch(const char *cmd, char *args){
    /*

    0x4042fd658  88 A1 0B 1B 0x4042fd658:	msub    w8, w12, w11, w8
    0x4042fd65c  08 05 00 11 0x4042fd65c:	add		w8, w8, #1
    0x4042fd660  08 21 CA 9A 0x4042fd660:	lsl		x8, x8, x10
    0x4042fd664  EA 13 40 F9 0x4042fd664:	ldr		x10, [sp, #0x20]

    0x804d896e0  FF 5B 01 A9 0x804d896e0:	stp		xzr, x22, [sp, #0x10]
    0x804d896e4  E8 67 00 A9 0x804d896e4:	stp		x8, x25, [sp]
    0x804d896e8  E0 23 40 F9 0x804d896e8:	ldr		x0, [sp, #0x40]
    0x804d896ec  E1 03 15 AA 0x804d896ec:	mov		x1, x21
    0x804d896f0  E2 03 18 AA 0x804d896f0:	mov		x2, x24
    0x804d896f4  E4 03 1A AA 0x804d896f4:	mov		x4, x26
    0x804d896f8  E5 03 1B AA 0x804d896f8:	mov		x5, x27
    0x804d896fc  06 00 80 52 0x804d896fc:	mov		w6, #0
    0x804d89700  50 00 00 94 0x804d89700:	bl		#0x804d89840

    */
    uint64_t matches[] = {
        0x1b0ba188,  // MSUB W8, W12, W11, W8
        0x11000508,  // ADD W8, W8, #1
        0x9aca2108,  // LSL X8, X8, X10
    };
    uint64_t masks[] = {
        0x1b0ba188, 
        0x11000508,  
        0x9aca2108,  
        
    };
    xnu_pf_patchset_t *text_exec_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);

    struct mach_header_64* hdr = xnu_header();
    xnu_pf_range_t* text_exec_range = xnu_pf_section(hdr, "__TEXT_EXEC", "__text");
    printf("aslr %llx\n", text_exec_range->device_base + 0x4C56E4);
    //FF6700A9      stp xzr, x25, [sp]
    xnu_pf_maskmatch(text_exec_patchset, "disable_aslr", matches, masks,
                   sizeof(matches) / sizeof(uint64_t), false,
                   (void *)aslr_callback);

    xnu_pf_emit(text_exec_patchset);
    xnu_pf_apply(text_exec_range, text_exec_patchset);
    xnu_pf_patchset_destroy(text_exec_patchset);



}

void module_entry(){
	command_register("dis", "disassemble", disassemble);
	command_register("kfind", "kfind", kfind);
    command_register("hd", "hexdump", hexdump0);
    command_register("mpp", "mem patch", mem_patch);
    return;
}


struct pongo_exports exported_symbols[] = {
};