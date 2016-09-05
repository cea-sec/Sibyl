/* The file should be compiled with pin-3.0-76991-gcc-linux */


/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "pin.H"


KNOB<uint64_t> KnobFunctionAddr(KNOB_MODE_WRITEONCE, "pintool",
    "a", "0x0", "function address to trace");
uint64_t functionAddr = 0x0;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "out.trace", "outputfile");

FILE * trace;
unsigned char instrument = 0;
ADDRINT rspInit;

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size, char* disass)
{
	if( instrument ) {
		switch(size){
		case 1:fprintf(trace,"R %p %x %x %p\n", addr, size, *(uint8_t*)addr, ip);break;
		case 2:fprintf(trace,"R %p %x %x %p\n", addr, size, *(uint16_t*)addr, ip);break;
		case 4:fprintf(trace,"R %p %x %x %p\n", addr, size, *(uint32_t*)addr, ip);break;
        case 8:fprintf(trace,"R %p %x %lx %p\n", addr, size, *(uint64_t*)addr, ip);break;
        case 16:fprintf(trace,"R %p %x %lx%016lx %p\n", addr, size, *(((uint64_t*)addr)+1), *(uint64_t*)addr, ip);break;
		default: fprintf(stderr, "abort 1 :  [%p]%u @%p(%s)\n",addr,size,ip,disass);abort();
		}
	}
}

VOID * last_addr;
UINT32 last_size;
// Print a memory write record
VOID RecordMemWriteContent(VOID * ip)
{
	if( instrument ) {
		switch(last_size){
		case 1:fprintf(trace,"%x %p\n", *(uint8_t*)last_addr, ip);break;
		case 2:fprintf(trace,"%x %p\n", *(uint16_t*)last_addr, ip);break;
		case 4:fprintf(trace,"%x %p\n", *(uint32_t*)last_addr, ip);break;
		case 8:fprintf(trace,"%lx %p\n", *(uint64_t*)last_addr, ip);break;
        case 16:fprintf(trace,"%lx%016lx %p\n", *(((uint64_t*)last_addr)+1), *(uint64_t*)last_addr, ip);break;
		default: fprintf(stderr, "abort 2");abort();
		}
	}
}
// Print a memory write record
VOID RecordMemWriteAddr(VOID * ip, VOID * addr, UINT32 size)
{
	if( instrument ) {
		switch(size){
		case 1:fprintf(trace,"W %p %x ", addr, size);break;
		case 2:fprintf(trace,"W %p %x ", addr, size);break;
		case 4:fprintf(trace,"W %p %x ", addr, size);break;
		case 8:fprintf(trace,"W %p %x ", addr, size);break;
        case 16:fprintf(trace,"W %p %x ", addr, size);break;
		default: fprintf(stderr, "abort 3");abort();
		}
		last_size = size;
		last_addr = addr;
	}
}

static int first=1;
VOID DumpRegsI(VOID * ip, ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx, ADDRINT rsi, ADDRINT rdi, ADDRINT rbp, ADDRINT rsp, ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15) {
	if( !instrument && (uint64_t)ip == functionAddr ) {
		instrument = 1;
		fprintf(trace,"I %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx\n", rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15);
		rspInit = rsp;
	}
	if(first){
		FILE* file;
		pid_t pid = getpid();
		char map_filename[32];
		char * line = NULL;
		size_t len = 0;

		first = 0;
		
		snprintf(map_filename, 32, "/proc/%u/maps", pid);
		file = fopen(map_filename, "r");
		if(file != NULL) {

			while (getline(&line, &len, file) != -1) {
				fprintf(trace, line);
			}

			fclose(file);
			if( line )
				free(line);

			fprintf(trace, "\n");
		}
	}
}

VOID DumpRegsO(VOID * ip, ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx, ADDRINT rsi, ADDRINT rdi, ADDRINT rbp, ADDRINT rsp, ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15) {
	if( instrument ) {
		fprintf(trace,"@ %p\n", ip);
		if( rspInit < rsp ) {
			instrument = 0;
			fprintf(trace,"O %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx\n", rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15);
		}
	}
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{	
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpRegsI,
				   IARG_INST_PTR,
				   IARG_REG_VALUE, REG_RAX,
				   IARG_REG_VALUE, REG_RBX,
				   IARG_REG_VALUE, REG_RCX,
				   IARG_REG_VALUE, REG_RDX,
				   IARG_REG_VALUE, REG_RSI,
				   IARG_REG_VALUE, REG_RDI,
				   IARG_REG_VALUE, REG_RBP,
				   IARG_REG_VALUE, REG_RSP,
				   IARG_REG_VALUE, REG_R8,
				   IARG_REG_VALUE, REG_R9,
				   IARG_REG_VALUE, REG_R10,
				   IARG_REG_VALUE, REG_R11,
				   IARG_REG_VALUE, REG_R12,
				   IARG_REG_VALUE, REG_R13,
				   IARG_REG_VALUE, REG_R14,
				   IARG_REG_VALUE, REG_R15,
				   IARG_END);

	IPOINT ipt;
	if(INS_HasFallThrough(ins)) ipt = IPOINT_AFTER;
	else if(INS_IsBranchOrCall(ins) || INS_IsSysret(ins) || INS_IsRet(ins)) ipt = IPOINT_TAKEN_BRANCH;
	else ipt = IPOINT_BEFORE;
	
	INS_InsertCall(ins, ipt, (AFUNPTR)DumpRegsO,
				   IARG_INST_PTR,
				   IARG_REG_VALUE, REG_RAX,
				   IARG_REG_VALUE, REG_RBX,
				   IARG_REG_VALUE, REG_RCX,
				   IARG_REG_VALUE, REG_RDX,
				   IARG_REG_VALUE, REG_RSI,
				   IARG_REG_VALUE, REG_RDI,
				   IARG_REG_VALUE, REG_RBP,
				   IARG_REG_VALUE, REG_RSP,
				   IARG_REG_VALUE, REG_R8,
				   IARG_REG_VALUE, REG_R9,
				   IARG_REG_VALUE, REG_R10,
				   IARG_REG_VALUE, REG_R11,
				   IARG_REG_VALUE, REG_R12,
				   IARG_REG_VALUE, REG_R13,
				   IARG_REG_VALUE, REG_R14,
				   IARG_REG_VALUE, REG_R15,
				   IARG_END);
	
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	// Iterate over each memory operand of the instruction.
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertPredicatedCall(
									 ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
									 IARG_INST_PTR,
									 IARG_MEMORYOP_EA, memOp,
									 IARG_MEMORYREAD_SIZE,
									 IARG_PTR,strdup(INS_Disassemble(ins).c_str()),
									 IARG_END);
		}
		
		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			IPOINT ipt;
			ipt = INS_HasFallThrough(ins)? IPOINT_AFTER : IPOINT_TAKEN_BRANCH;
			INS_InsertPredicatedCall(
									 ins, ipt, (AFUNPTR)RecordMemWriteContent,
									 IARG_INST_PTR,
									 IARG_CALL_ORDER, CALL_ORDER_FIRST,
									 IARG_END);
			INS_InsertPredicatedCall(
									 ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWriteAddr,
									 IARG_INST_PTR,
									 IARG_MEMORYOP_EA, memOp,
									 IARG_MEMORYWRITE_SIZE,
									 IARG_CALL_ORDER, CALL_ORDER_LAST,
									 IARG_END);
		}
	}
}


VOID Fini(INT32 code, VOID *v)
{
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

	functionAddr = KnobFunctionAddr.Value();
	
    trace = fopen(KnobOutputFile.Value().c_str(), "w");
	
    INS_AddInstrumentFunction(Instruction, 0);	
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
