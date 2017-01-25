/* The file should be compiled with pin-3.0-76991-gcc-linux */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pin.H"

/* Set pin option and gobal variable for the address of the traced function */
KNOB<uint64_t> KnobFunctionAddr(KNOB_MODE_WRITEONCE, "pintool",
	"a", "0x0", "function address to trace");
uint64_t functionAddr = 0x0;

/* Set pin option and gobal variable for the output file */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "out.trace", "outputfile");
FILE * trace;

/* Boolean variable. True if traced function is currently executed (then tracer have to produce output), false else. */
unsigned char instrument = 0;

/* Value of RSP at the beginning of each function execution.
   It is used to detect the end of the function (initial rsp lower than current rsp)*/
ADDRINT rspInit;


/* Error checking functions */

#define check_error(func, func_name) { \
if((func) < 0){ \
	perror(func_name); \
	abort(); \
}}

#define check_fprintf_error(func) check_error(func, "fprintf")
#define check_snprintf_error(func) check_error(func, "snprintf")


/* Print a memory read record */
VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size, char* disass)
{
	if( instrument ) {
		switch(size){
		case 1: check_fprintf_error(fprintf(trace,"R %p %x %x %p\n", addr, size, *(uint8_t*)addr, ip)); break;
		case 2: check_fprintf_error(fprintf(trace,"R %p %x %x %p\n", addr, size, *(uint16_t*)addr, ip));break;
		case 4: check_fprintf_error(fprintf(trace,"R %p %x %x %p\n", addr, size, *(uint32_t*)addr, ip));break;
		case 8: check_fprintf_error(fprintf(trace,"R %p %x %lx %p\n", addr, size, *(uint64_t*)addr, ip));break;
		case 16: check_fprintf_error(fprintf(trace,"R %p %x %lx%016lx %p\n", addr, size, *(((uint64_t*)addr)+1), *(uint64_t*)addr, ip));break;
		default: fprintf(stderr, "abort: read size is not managed ([%p]%u @%p(%s))\n",addr,size,ip,disass);abort();
		}
	}
}

/* Global variables used to communicate between RecordMemWriteContent and RecordMemWriteAddr functions */
VOID * last_addr;
UINT32 last_size;

/* Print the written value and the address of the instruction of a memory write record */
VOID RecordMemWriteContent(VOID * ip)
{
	if( instrument ) {
		switch(last_size){
		case 1: check_fprintf_error(fprintf(trace,"%x %p\n", *(uint8_t*)last_addr, ip));break;
		case 2: check_fprintf_error(fprintf(trace,"%x %p\n", *(uint16_t*)last_addr, ip));break;
		case 4: check_fprintf_error(fprintf(trace,"%x %p\n", *(uint32_t*)last_addr, ip));break;
		case 8: check_fprintf_error(fprintf(trace,"%lx %p\n", *(uint64_t*)last_addr, ip));break;
		case 16: check_fprintf_error(fprintf(trace,"%lx%016lx %p\n", *(((uint64_t*)last_addr)+1), *(uint64_t*)last_addr, ip));break;
		default: fprintf(stderr, "abort: write size is not managed ([%p]%i @%p)\n", last_addr, last_size, ip); abort();
		}
	}
}

/* Print the written address and size of a memory write record */
VOID RecordMemWriteAddr(VOID * ip, VOID * addr, UINT32 size)
{
	if( instrument ) {
		switch(size){
		case 1: check_fprintf_error(fprintf(trace,"W %p %x ", addr, size));break;
		case 2: check_fprintf_error(fprintf(trace,"W %p %x ", addr, size));break;
		case 4: check_fprintf_error(fprintf(trace,"W %p %x ", addr, size));break;
		case 8: check_fprintf_error(fprintf(trace,"W %p %x ", addr, size));break;
		case 16: check_fprintf_error(fprintf(trace,"W %p %x ", addr, size));break;
		default: fprintf(stderr, "abort: write size is not managed ([%p]%i @%p)\n", addr, size, ip); abort();
		}
		last_size = size;
		last_addr = addr;
	}
}

VOID DumpRegsI(VOID * ip, ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx, ADDRINT rsi, ADDRINT rdi, ADDRINT rbp, ADDRINT rsp, ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15) {
	static int first=1;

	/* If this is the first execution of an instruction, /proc/maps of the process is dumped */
	if(first){
		FILE* file;
		pid_t pid = getpid();
		char map_filename[32];
		char * line = NULL;
		size_t len = 0;

		first = 0;

		check_snprintf_error(snprintf(map_filename, 32, "/proc/%u/maps", pid));
		file = fopen(map_filename, "r");
		if(file != NULL) {

			while (getline(&line, &len, file) != -1) {
				check_fprintf_error(fprintf(trace, "%s", line));
			}

			fclose(file);
			if( line )
				free(line);

			check_fprintf_error(fprintf(trace, "\n"));
		}
		else {
			perror("fopen");
			abort();
		}
	}

	/* If the function is not already begun and IP is at its first instruction,
	   we log input registers */
	if( !instrument && (uint64_t)ip == functionAddr ) {
		instrument = 1;
		check_fprintf_error(fprintf(trace,"I %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx\n", rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15));
		rspInit = rsp;
	}
}

VOID DumpRegsO(VOID * ip, ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx, ADDRINT rsi, ADDRINT rdi, ADDRINT rbp, ADDRINT rsp, ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15) {
	/* If the function was running*/
	if( instrument ) {
		/* Log the executed instruction address */
		fprintf(trace,"@ %p\n", ip);

		/* If the function is finished */
		if( rspInit < rsp ) {
			/* Log output registers */
			instrument = 0;
			check_fprintf_error(fprintf(trace,"O %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx\n", rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15));
		}
	}
}

/* Is called for every instruction and instruments reads and writes accesses */
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


	/* Iterate over each memory operand of the instruction */
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {

		/* If it is a read operand, log it */
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
									 IARG_INST_PTR,
									 IARG_MEMORYOP_EA, memOp,
									 IARG_MEMORYREAD_SIZE,
									 IARG_PTR,strdup(INS_Disassemble(ins).c_str()),
									 IARG_END);
		}

		/* If it is a write operand, log it */
		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			IPOINT ipt;
			ipt = INS_HasFallThrough(ins)? IPOINT_AFTER : IPOINT_TAKEN_BRANCH;
			INS_InsertPredicatedCall(ins, ipt, (AFUNPTR)RecordMemWriteContent,
									 IARG_INST_PTR,
									 IARG_CALL_ORDER, CALL_ORDER_FIRST,
									 IARG_END);
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWriteAddr,
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

INT32 Usage()
{
	PIN_ERROR( "This Pintool prints a trace of the read/write accesses and executed instructions during the execution of a specific function.\n"
			  + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

int main(int argc, char *argv[])
{
	if (PIN_Init(argc, argv)) return Usage();

	functionAddr = KnobFunctionAddr.Value();

	trace = fopen(KnobOutputFile.Value().c_str(), "w");
	if( trace == NULL ){
		perror("fopen");
		abort();
	}

	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	fprintf(stderr, "This point should never be reached");
	abort();

	return 0;
}
