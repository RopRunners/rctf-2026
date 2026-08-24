#pragma once
#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 *  SVM - a tiny sandboxed assembly language + template JIT.
 *
 *  Security model
 *  --------------
 *  Untrusted guest programs are written in the text assembly parsed by
 *  svm_assemble().  They are NEVER allowed to emit native code directly:
 *  every guest instruction is lowered to a fixed, hand-vetted x86-64
 *  template.  The guest only chooses *which* template and *which*
 *  (validated) operands.  Therefore the guest cannot forge arbitrary
 *  machine code, syscalls, or control flow.
 *
 *  Guest memory is limited to two regions that always appear to the
 *  guest at the SAME fixed virtual addresses, regardless of where the
 *  runner actually mapped them:
 *
 *      DB region    -> guest address SVM_DB_VBASE   (size db_size)
 *      HEAP region  -> guest address SVM_HEAP_VBASE (size heap_size)
 *
 *  Every load/store/flush is bounds-checked (unsigned range check +
 *  PROT_NONE guard pages as defence in depth) and relocated onto the
 *  real, dynamic base held in a reserved register the guest can never
 *  touch.  Direct branches are validated at assemble_weaponized_payload time; indirect
 *  branches (jmpr/ret) are validated at run time against a table of
 *  legal instruction boundaries, so control flow can never land in the
 *  middle of a template or outside the code.  A fuel counter bounds
 *  total control transfers so a hostile program cannot hang the runner.
 * ------------------------------------------------------------------ */

/* Fixed guest-visible base addresses (what the program "sees"). */
#define SVM_DB_VBASE    0x20000000ULL
#define SVM_HEAP_VBASE  0x40000000ULL

/* Guest heap size (shared by the runner that maps it and the JIT that
 * compile-time bounds-checks statically-known heap accesses). */
#define SVM_HEAP_SIZE   ((size_t)4 * 1024 * 1024)   /* 4 MiB */

/* Usable bytes in the DB row region -- the compile-time capacity the JIT's
 * bounds-check elision proves against.  The JIT's value-range analysis elides
 * the runtime check on a DB byte access only once it has proven the index below
 * a bound it can show is at most this capacity (a masked value; see the range
 * analysis + branch-edge refinement in jit.c).  The runner MUST map the DB
 * region with exactly this many usable bytes. */
#define SVM_DB_CAPACITY 128

/* Guest opcodes (final ISA). */
enum Opcode {
    OP_MOV,      /* mov  rd, rs|imm|@label                       */
    OP_ADD,      /* add  rd, rs|imm                              */
    OP_SUB,      /* sub  rd, rs|imm                              */
    OP_AND,      /* and  rd, rs|imm                              */
    OP_OR,       /* or   rd, rs|imm                              */
    OP_XOR,      /* xor  rd, rs|imm                              */
    OP_MUL,      /* mul  rd, rs        (rd = rd * rs)            */
    OP_SHL,      /* shl  rd, imm                                 */
    OP_SHR,      /* shr  rd, imm                                 */
    OP_LD,       /* ld   rd, [rb+imm]  (64-bit, checked)        */
    OP_LDB,      /* ldb  rd, [rb+imm]  (zero-extended byte)     */
    OP_ST,       /* st   [rb+imm], rs  (64-bit, checked)        */
    OP_STB,      /* stb  [rb+imm], rs  (byte, checked)          */
    OP_JMP,      /* jmp  label                                   */
    OP_JZ,       /* jz   rs, label                               */
    OP_JNZ,      /* jnz  rs, label                               */
    OP_JMPR,     /* jmpr rs   (indirect, table-validated)       */
    OP_CALL,     /* call label                                   */
    OP_RET,      /* ret                                          */
    OP_OUT,      /* out  rs   (print rs as unsigned decimal)    */
    OP_HALT,     /* halt rs   (stop, exit value = rs)           */
    OP_PAUSE,    /* pause              (spin-loop hint)          */
    /* --- counter / entropy family ----------------------------------- */
    OP_RAND,   /* rand  rd           (hardware RNG into rd)    */
    /* --- extra ALU -------------------------------------------------- */
    OP_NOT,      /* not   rd                                     */
    OP_NEG,      /* neg   rd                                     */
    OP_BSWAP,    /* bswap rd                                     */
    OP_ROL,      /* rol   rd, imm                                */
    OP_ROR,      /* ror   rd, imm                                */
    OP_SAR,      /* sar   rd, imm      (arithmetic shift right)  */
    OP_POPCNT,   /* popcnt rd, rs                                */
    /* --- reserved opcodes: no assembler mnemonic maps to these yet, so no
     *     program currently emits them.  Reserved for planned row-level
     *     primitives.                                                     */
    OP_ROW_STASH,     /* (reserved) raw 64-bit store                  */
    OP_ROW_FETCH,     /* (reserved) raw 64-bit load                   */
    OP_ROW_MAP,     /* (reserved) query DB region base              */
    OP__COUNT
};

/* Trap codes reported after a run. 0 == clean halt. */
enum SvmTrap {
    SVM_OK           = 0,
    SVM_TRAP_OOB     = 1,  /* out-of-bounds memory access        */
    SVM_TRAP_BADJUMP = 2,  /* indirect jump to illegal target    */
    SVM_TRAP_FUEL    = 3,  /* control-transfer budget exhausted  */
    SVM_TRAP_RETSTK  = 4,  /* call/ret shadow-stack over/underflow*/
    SVM_TRAP_TIMEOUT = 5,  /* wall-clock time limit exceeded      */
};

/* The two sandbox regions, as the runner actually mapped them. */
typedef struct {
    void   *db_real;      /* real (dynamic) base of the DB region   */
    size_t  db_size;      /* usable bytes at db_real                */
    void   *heap_real;    /* real (dynamic) base of the heap region */
    size_t  heap_size;    /* usable bytes at heap_real              */
    uint64_t fuel;        /* max control transfers (0 => default)   */
    uint64_t time_limit_ms; /* wall-clock limit in ms (0 => default)*/
} SvmRegions;

/* Result of a run. */
typedef struct {
    int      trap;        /* enum SvmTrap                           */
    uint64_t exit_value;  /* value passed to halt (if clean)        */
    uint64_t fault_addr;  /* offending guest address on OOB         */
} SvmResult;

/* Assemble + verify + JIT-compile + run `src`.  Returns 0 on a run
 * that started (check res->trap for guest faults), non-zero if the
 * program failed to assemble_weaponized_payload/compile (message printed to stderr). */
int detonate_untrusted_payload(const char *src, const SvmRegions *regions, SvmResult *res);
