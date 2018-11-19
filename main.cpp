#include <Windows.h>
#include <iostream>
#include "VirtualMachine.h"

using namespace std;

class test
{
public:
	static void validate_data_stream(call_context call_context);
};

virtual_machine* vm;
void print_number(call_context call_context);
void sleep_and_clear(call_context call_context);
void check_for_debugger(call_context call_context);
void protect_memory(call_context call_context);

/// Protection shit
int get_proc_addr(const char* dll, const char* name);
__declspec(noinline) HMODULE WINAPI load_library_wrapper(LPCWSTR lp_lib_filename);
void get_proc_asm();
__declspec(noinline) void encrypt(char* dst, int max_size);
LONG WINAPI unhandled_excep_filter(PEXCEPTION_POINTERS p_excep_pointers);
bool hide_thread(HANDLE h_thread);
inline bool check_output_debug_string(LPCTSTR string);
bool is_dbg_present_prefix_check();
inline bool debug_object_check();

int globals[] = { reinterpret_cast<int>(print_number), reinterpret_cast<int>(sleep_and_clear), reinterpret_cast<int>(protect_memory) };
int globals1[] = { 0, reinterpret_cast<int>(check_for_debugger) };
int globals2[] = { 42069, reinterpret_cast<int>(test::validate_data_stream) };
int* _globals[] = { globals, globals1, globals2 };

#define JUNK_CODE_ONE        \
    __asm{push eax}            \
    __asm{xor eax, eax}        \
    __asm{setpo al}            \
    __asm{push edx}            \
    __asm{xor edx, eax}        \
    __asm{sal edx, 2}        \
    __asm{xchg eax, edx}    \
    __asm{pop edx}            \
    __asm{or eax, ecx}        \
    __asm{pop eax}

#define JUNK_CODE_TWO \
__asm{push eax} \
 __asm{xor eax, eax} \
__asm{mov eax,12} \
__asm{pop eax}

#define THE_VALUE 1337

		int data[] = { 
		/// OPCODE	/// HASH		SIZE	STORED	OFFSET	GLOBALS	PARAMETER
		-0x2,		0x1337,		0,		0,		0,		1,		0,					/// LABEL 0 = Store label in slot 0 (we use globals 1 here)
		-0x4,		0x1337,		0,		0,		0,		2,		0,		THE_VALUE,	/// STORE 1337 GLOBALS2[0] = Store 1337 in globals2 at slot 0
		-0x7,		0x1337,		0,		0,		0,		2,		0,					/// LOAD GLOBALS2[0] = Load variable from globals 2 slot 0
		-0x6,		0x1337,		0,		0,		0,		0,							/// PUSH = Push loaded variable onto stack
		-0x1,		0x55,		0x1,	0,		0,		1,		1,					/// CALL GLOBALS1[1]		(CheckForDebugger)
		-0x8,		0x1337,		0,		0,		0,		0,		10,					/// INT3 (we pass a parameter to break the offset after being executed)
		-0x1,		0x55,		0x1,	0,		0,		2,		1,					/// CALL GLOBALS2[1]			(ValidateDataStream)
/*CHANGED*/-0x6,		0x1337,		0x6,		0,		0,		0,		0,					/// CALLS 0 = Call 0 from globals0 using stack (PrintNumber)
		-0x1,		0x55,		0x1,	0,		0,		0,		1,		10,			/// CALL 1 10 = Call second function with 10 as param (we use globals 0 here) (SleepAndClear)
		-0x1,		0x55,		0x1,	0,		0,		0,		2,					/// CALL globals0[2] = ProtectMemory
/*GLOBALS CHANGED*/		-0x3,		0x1337,		0,		0,		0,		2,		0,					/// JMP 0 = Jump to label 0 (we use globals 1 here)


		-0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD	/// END
	};

int main()
{	
	FindWindowA("", nullptr);

	/// Force load DLL
	FindWindowA("", nullptr);

	/// Create VM
	vm = new virtual_machine();
	vm->initialize(static_cast<void*>(data), sizeof data);

	for (auto& global : _globals)
	{
		vm->add_globals(global);
	}

	_globals[2][0] = 694201337;

	while (true)
	{
		if (!vm->run())
		{
			break;
		}
	}

	vm->shutdown();
	delete vm;
	vm = nullptr;
}

void print_number(const call_context call_context)
{
	cout << call_context.arguments[1];

	vm->adjust_instruction_code(-0x1);

	/// Adjust (two arguments)
	vm->adjust_data_offset(0);
}

void sleep_and_clear(const call_context call_context)
{
	Sleep(call_context.arguments[1]);
	system("cls");

	/// Adjust (two arguments)
	vm->adjust_data_offset(8);
}

void test::validate_data_stream(call_context call_context)
{
	/// Undone at the end
	vm->adjust_call_target(-1);

	/// Perform anti debugging check
	_asm
	{
		MOV		ebx, DWORD PTR FS:[18h]
		ADD		ebx, 13h /// === Useless; add 10h to TEB
		MOV ebx, DWORD PTR DS:[ebx+1Dh] /// === PEB; would be MOV EAX, DWORD PTR DS:[EAX+30] if we hadn't already added 10
		MOVZX ebx, BYTE PTR DS:[ebx+2] 
		test	ebx, ebx
		jz		no_debugger
	}
	return;

	no_debugger:

	/// Hash is different when obfuscated data is used. We subtract the hash of the data
	vm->adjust_data_offset(-34778 - THE_VALUE);
	vm->adjust_call_target(0x5);

	JUNK_CODE_ONE
	hide_thread(nullptr);
	auto* data = static_cast<int*>(vm->get_data_stream());

	/// Hash
	auto hash = 0;
	for (auto i = 0; i < 80; i++)
	{
		hash += data[i];
	}

	/// We add the hash of the data back. If data has been changed, offset will be wrong
	vm->adjust_data_offset(hash + 4);

	/// If obfuscated, this is needed in order to turn the next instruction in the data into a valid one
	vm->adjust_instruction_code(0x1);

	/// If no differnce, 1 will be added. If there is a difference, 0 will be added
	int difference = _globals[2][0] == THE_VALUE;
	vm->adjust_call_target(difference);
}

void check_for_debugger(call_context call_context)
{
	/// Skip own argument
	vm->adjust_data_offset(4);

	char olly_dbg[] = "DGGROIL";

	char class_name[] = "\\beod|"; /// "Window";
	char cheat_engine60_name[] = "Hcnj+Nelben+=%;"; ////"Cheat Engine 6.0";
	char cheat_engine61_name[] = "Hcnj+Nelben+=%:"; ////"Cheat Engine 6.1";
	char cheat_engine62_name[] = "Hcnj+Nelben+=%9"; ////"Cheat Engine 6.2";
	char cheat_engine63_name[] = "Hcnj+Nelben+=%8"; ////"Cheat Engine 6.3";
	encrypt(class_name, sizeof class_name);
	encrypt(cheat_engine60_name, sizeof cheat_engine60_name);
	encrypt(cheat_engine61_name, sizeof cheat_engine61_name);
	encrypt(cheat_engine62_name, sizeof cheat_engine62_name);
	encrypt(cheat_engine63_name, sizeof cheat_engine63_name);

	JUNK_CODE_ONE

	char user32_dll[] = "^xny89%ogg";
	char find_window_a[] = "Mbeo\\beod|J";
	char get_window_text_a[] = "Ln\\beod|_nsJ";
	encrypt(user32_dll, sizeof user32_dll);
	encrypt(find_window_a, sizeof find_window_a);
	encrypt(get_window_text_a, sizeof get_window_text_a);

	auto *address(LPCSTR, LPCSTR) = reinterpret_cast<HWND (WINAPI*)(LPCSTR, LPCSTR)>(get_proc_addr(user32_dll, find_window_a));
	HWND cheat_engine_window = address(class_name, nullptr);
	if (cheat_engine_window != nullptr)
	{
		char window_text[128] = {};
		auto *address2(HWND, LPSTR, int) = reinterpret_cast<int (WINAPI*)(HWND, LPSTR, int)>(get_proc_addr(user32_dll, get_window_text_a));
		address2(cheat_engine_window, window_text, sizeof window_text);
		if (strcmp(window_text, cheat_engine60_name) == 0 ||
			strcmp(window_text, cheat_engine61_name) == 0 ||
			strcmp(window_text, cheat_engine62_name) == 0 ||
			strcmp(window_text, cheat_engine63_name) == 0)
		{
			return;
		}
	}

	encrypt(olly_dbg, sizeof olly_dbg);

	if (address(olly_dbg, nullptr) != nullptr)
	{
		return;
	}

	/// Skip half of instruction INT 3 (20 bytes)
	vm->adjust_data_offset(_globals[2][0] - (THE_VALUE - 20));
#ifdef OBFUSCATE
	if (debug_object_check())
	{
		vm->adjust_instruction_code(0x3);
	}
#endif

	JUNK_CODE_ONE

	/// Skip other half of instruction INT 3 (8 bytes)
	vm->adjust_data_offset(8 + is_dbg_present_prefix_check());
}

void protect_memory(call_context call_context)
{
	typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *pSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter); 

	char kernel32[] = "`nyeng89%ogg";
	char set_unhandled_exception_filter[] = "Xn^ecjeognoNshn{bdeMbgny";
	encrypt(kernel32, sizeof kernel32);
	encrypt(set_unhandled_exception_filter, sizeof set_unhandled_exception_filter);

	/// Changed back in hide thread
	vm->adjust_call_target(0x5);

	/// Since data is changed, we have to adjust the globals here
	vm->adjust_globals_offset(-0x1);
		reinterpret_cast<pSetUnhandledExceptionFilter>(get_proc_addr(kernel32, set_unhandled_exception_filter))(unhandled_excep_filter);
    __asm{xor eax, eax}
    __asm{div eax}

	JUNK_CODE_TWO
	hide_thread(nullptr);
	JUNK_CODE_ONE

	/// Skip own argument
	vm->adjust_data_offset(4);
}

LONG WINAPI unhandled_excep_filter(PEXCEPTION_POINTERS p_excep_pointers)
{
	typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *pSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter); 

	char kernel32[] = "`nyeng89%ogg";
	char set_unhandled_exception_filter[] = "Xn^ecjeognoNshn{bdeMbgny";
	encrypt(kernel32, sizeof kernel32);
	encrypt(set_unhandled_exception_filter, sizeof set_unhandled_exception_filter);

	JUNK_CODE_TWO

	/// Restore old UnhandledExceptionFilter
	reinterpret_cast<pSetUnhandledExceptionFilter>(get_proc_addr(kernel32, set_unhandled_exception_filter))(reinterpret_cast<LPTOP_LEVEL_EXCEPTION_FILTER>(p_excep_pointers->ContextRecord->Eax));


    /// Skip the exception code
    p_excep_pointers->ContextRecord->Eip += 2;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/// HideThread will attempt to use
/// NtSetInformationThread to hide a thread
/// from the debugger, Passing NULL for
/// hThread will cause the function to hide the thread
/// the function is running in. Also, the function returns
/// false on failure and true on success
__forceinline bool hide_thread(HANDLE h_thread)
{
    typedef NTSTATUS (NTAPI *p_nt_set_information_thread)(HANDLE, UINT, PVOID, ULONG); 
    NTSTATUS status; 

	typedef HANDLE (WINAPI *p_get_current_thread)(); 

	char ntdll[] = "eogg%ogg";
	char nt_set_information_thread[] = "EXnBemdyfjbde_cynjo";
	encrypt(ntdll, sizeof ntdll);
	encrypt(nt_set_information_thread, sizeof nt_set_information_thread);

	char kernel32[] = "`nyeng89%ogg";
	char get_current_thread[] = "LnH~yyne_cynjo";
	encrypt(kernel32, sizeof kernel32);
	encrypt(get_current_thread, sizeof get_current_thread);

	JUNK_CODE_TWO

    /// Get NtSetInformationThread
	auto nt_sit = reinterpret_cast<p_nt_set_information_thread>(get_proc_addr(ntdll, nt_set_information_thread));
	auto getCurrentThread = reinterpret_cast<p_get_current_thread>(get_proc_addr(kernel32, get_current_thread));

	JUNK_CODE_TWO

    /// Set the thread info
    if (h_thread == nullptr)
	{
		JUNK_CODE_ONE
		vm->adjust_call_target(-0x5);
        status = nt_sit(getCurrentThread(), 0x11, nullptr, 0); /// HideThreadFromDebugger
	}
    else
	{
		vm->adjust_call_target(-0x5);
        status = nt_sit(h_thread, 0x11, nullptr, 0); 
	}

	return status == 0x00000000;
}

/// CheckOutputDebugString checks whether or 
/// OutputDebugString causes an error to occur
/// and if the error does occur then we know 
/// there's no debugger, otherwise if there IS
/// a debugger no error will occur
inline bool check_output_debug_string(LPCTSTR string)
{
	return false;
	char kernel32[] = "`nyeng89%ogg";
	char output_debug_string_w[] = "D~{~Oni~lXybel\\";
	char get_last_error[] = "LnGjxNyydy";
	encrypt(kernel32, sizeof kernel32);
	encrypt(output_debug_string_w, sizeof output_debug_string_w);
	encrypt(get_last_error, sizeof get_last_error);

	typedef void (WINAPI *p_output_debug_string)(PCTSTR lpOutputString);
	reinterpret_cast<p_output_debug_string>(get_proc_addr(kernel32, output_debug_string_w))(string);

	JUNK_CODE_TWO

	typedef DWORD (WINAPI *p_get_last_error)();

	return reinterpret_cast<p_get_last_error>(get_proc_addr(kernel32, get_last_error))() == 0;
}

/// This function uses NtQuerySystemInformation
/// to try to retrieve a handle to the current
/// process's debug object handle. If the function
/// is successful it'll return true which means we're
/// being debugged or it'll return false if it fails
/// or the process isn't being debugged
__forceinline bool debug_object_check()
{
    /// Much easier in ASM but C/C++ looks so much better
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)
            (HANDLE ,UINT ,PVOID ,ULONG , PULONG); 

	typedef HANDLE (WINAPI *pGetCurrentProcess)(void);

    HANDLE h_debug_object = nullptr;

	char ntdll[] = "eogg%ogg";
	char nt_query_information_process[] = "EZ~nyrBemdyfjbde[ydhnxx";
	char get_current_process[] = "LnH~yyne[ydhnxx";
	char kernel32[] = "`nyeng89%ogg";
	encrypt(ntdll, sizeof ntdll);
	encrypt(nt_query_information_process, sizeof nt_query_information_process);
	encrypt(get_current_process, sizeof get_current_process);
	encrypt(kernel32, sizeof kernel32);

	/// Get NtQueryInformationProcess
	const auto nt_qip = reinterpret_cast<pNtQueryInformationProcess>(get_proc_addr(ntdll, nt_query_information_process));
	const auto get_curr_proc = reinterpret_cast<pGetCurrentProcess>(get_proc_addr(kernel32, get_current_process));

	const auto status = nt_qip(get_curr_proc(),
                            0x1e, /// ProcessDebugObjectHandle
                            &h_debug_object, 4, nullptr); 
    
    if (status != 0x00000000)
        return false;

	return h_debug_object != nullptr;
}

/// The IsDbgPresentPrefixCheck works in at least two debuggers
/// OllyDBG and VS 2008, by utilizing the way the debuggers handle
/// prefixes we can determine their presence. Specifically if this code
/// is ran under a debugger it will simply be stepped over;
/// however, if there is no debugger SEH will fire :D
__forceinline bool is_dbg_present_prefix_check()
{
    __try
    {
		__asm pushad
		__asm popad
        __asm __emit 0xF3 /// 0xF3 0x64 disassembles as PREFIX REP:
        __asm __emit 0x64
        __asm __emit 0xF1 /// One byte INT 1
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    return true;
}

int __cdecl get_proc_addr(const char* dll, const char* name)
{
	auto address = 0;
	_asm
	{
		push dll
		push name
		call get_proc_asm
		mov	address, eax
	}

	return address;
}

__declspec(noinline) HMODULE WINAPI load_library_wrapper(const LPCWSTR lp_lib_filename)
{
	LoadLibraryW(lp_lib_filename);
}

__declspec(naked) __forceinline void get_proc_asm()
{
	_asm
	{
       add    esp,-2*4-4*4              ; room for 4 registers and 2 local variables
       mov    [esp+2*4+0*4], edi        ; saving registers
       mov    [esp+2*4+1*4], ebp        ;
       mov    [esp+2*4+2*4], esi        ;
       mov    [esp+2*4+3*4], ebx        ;
       mov    dword ptr [esp+1*4], 0    ; [esp+1*4]-> clear flag for forwarded proc
GetStart:                               ;
       mov    edx, [esp+2*4+4*4+2*4]    ; edx->lp Dll name
       mov    ebp, 20h                  ; ebp-> BaseDllName address (Unicode)
       cmp    byte ptr [edx+1], 3Ah     ; "c:\...." Is it full path or just dll name?
       jne    a                        ;
       mov    ebp, 18h                  ; ebp-> FullDllName (Unicode)
a:                                     ;
; Get module base address...............;
       mov    eax, fs:[30h]             ; PEB base in eax
       cmp    dword ptr [esp+1*4], -1   ; If it is forwarded esi->ntdll.dll
       mov    eax, [eax+0Ch]            ; eax-> PEB_LDR_DATA
       mov    edi, edx                  ; edi->lp Dll name
       mov    esi, [eax+1Ch]            ; esi-> 1st entry in InitOrderModuleList
       je     b                        ; else
       mov    esi, [esi]                ; esi->Kernel32.dll
b:                                     ;
       mov    eax, [esi+ebp]            ; eax-> BaseDllName or FullDllName (Unicode)
       mov    ebx, esi                  ; ebx-> the 1st LDR_MODULE in the chain
; Comparing strings ....................;
                                        ;
FindNextCharw:                          ;
       mov    ch,  [eax]                ; eax-> BaseDllName or FullDllName (Unicode)
       add    eax, 2                    ;
       cmp    ch,  5Ah                  ;
       ja     c                        ;
       cmp    ch,  41h                  ;
       jl     c                        ;
       or     ch,  20h                  ;
c:                                     ;
       mov    cl,  [edx]                ; edx->lp dll name string "." or zero ended
       add    edx, 1                    ;
       cmp    cl,  5Ah                  ;
       ja     d                        ;
       cmp    cl,  41h                  ;
       jl     d                        ;
       or     cl,  20h                  ;
d:                                     ;
       cmp    cl,  ch                   ;
       jne    Next_LDRw                 ;
       test   ch,  ch                   ;
       je     e                        ;
       cmp    ch,  2Eh                  ; "."
       jne    FindNextCharw             ;
       cmp    dword ptr [esp+1*4], -1   ; flag for forwarded proc ->  If it is forwarded
       jne    FindNextCharw             ;           copy until "." , else until zero
e:                                     ;
       mov    ebx, [esi+8]              ; ebx-> Base Dll Name address
       je     GetNextApi                ;
                                        ;
; Next forward LDR_MODULE ..............;
Next_LDRw:                              ;
       mov    esi, [esi]                ; we go forwards
       mov    edx, edi                  ; edx->lp Dll name
       mov    eax, [esi+ebp]            ; eax-> BaseDllName or FullDllName (Unicode) address
	   test   eax, eax
	   jz	  Next_LDRw
	   cmp    ebx, esi                  ; If current module = 1st module -> Dll is Not Loaded
       jne    FindNextCharw             ;
                                        ; 
; The module is not loaded in memory and;
; we will try LoadLibrary to load it....;
	jmp End_NotFound	                ;  Disabled for now
       cmp    dword ptr [esp+1*4],-1    ; If it is forwarded
       je     Forwarded_Dll             ; copy dll name in the stack and call oadLibrary
       xor    ebx, ebx                  ; ebx = 0
	   push		edx
       call LoadLibraryWrapper          ; call API
       add    ebx, eax                  ; ebx-> BaseDllName address or zero
       je     End_NotFound              ; No such dll -> exit with ebx=0-> error
; End of Get module base address........;
                                        ;
GetNextApi:                             ;
       mov    edx, [ebx+3Ch]            ; edx-> beginning of PE header
       mov    esi, ebx                  ; ebp-> current dll base address
       mov    edi, [ebx+edx+78h]        ; edi-> RVA of ExportDirectory -> 78h
       mov    ecx, [ebx+edx+7Ch]        ; ecx-> RVA of ExportDirectorySize ->7Ch
       add    esi, [ebx+edi+20h]        ; esi-> AddressOfNames ->20h
       add    edi, ebx                  ; ebx-> current dll base address
       movd   MM5, edi                  ; MM5-> edi-> ExportDirectory
       mov    ebp, [esp+1*4+(4*4+2*4)]  ; ebp->proc name address or ordinal value
       add    ecx, edi                  ; ecx= ExportDirectory address + ExportDirectorySize
       mov    eax, [edi+18h]            ; eax = num of API Names-> nMax NumberOfNames->18h
       test   ebp, 0ffff0000h           ; is it proc name address or ordinal value?
       mov    [esp+0*4], ecx            ; [esp+0*4] = ExportDirectory address + ExportDirectorySize
       je     GetByOrdinal              ;GetProcAddress by Ordinal
                                        ;   
; Binary search ........................;GetProcAddress by Name
       movd   MM7, esp                  ; save the stack here
       movzx  ecx, byte ptr [ebp]       ; ebp->proc name address
       lea    edi, [esi+4]              ;      cl-> 1st character of the proc name 
       mov    esp, ebx                  ; esp-> current dll base address
       neg    edi                       ; set carry flag
       movd   MM6, edi                  ; MM6= -(esi+4]
Bin_Search:                             ; 
      ;cmova  esi, edx                  ; see Note 1
       sbb    edi, edi                  ; edi->mask  -1 or 0
       xor    esi, edx                  ; mix esi and edx
       and    esi, edi                  ; esi=esi or esi=0
       mov    ebx, esp                  ; ebx-> current dll base address
       xor    esi, edx                  ; esi=esi or esi=edx
       shr    eax, 1                    ;
       je     End_ZeroIndex             ;
IndexIsZero:                            ;
       add    ebx, [esi+4*eax]          ;
       lea    edx, [esi+4*eax+4]        ;
       cmp    cl,  [ebx]                ; ebx-> API Names Table 
       jne    Bin_Search                ;
; End Binary search ....................;
                                        ;
; Compare next bytes of two strings.....;
       lea    edi, [ebp+1]              ;     
f:                                     ;
       mov    ch,  [edi]                ; comparing bytes   
       add    ebx, 1                    ;   
       cmp    ch,  [ebx]                ; ebx-> API Names Table 
       jne    Bin_Search                ;
       add    edi, 1                    ;   
       test   ch,  ch                   ;   
       jne    f                        ;
                                        ;
; Extract the index from EDX to get proc address   
       movd   esi, MM5                  ; esi-> ExportDirectory
       movd   eax, MM6                  ; eax-> -(AddressOfNames+4)
       mov    edi, [esi+24h]            ; edi->AddressOfNameOrdinals ->24h
       mov    ecx, esp                  ; ecx-> current dll base address
       add    ecx, [esi+1Ch]            ; ecx-> AddressOfFunctions->1Ch
       add    eax, edx                  ; edx-> [esi+4*eax+4]
       shr    eax, 1                    ; eax->index-> eax*2 for word table
       add    edi, esp                  ; esp-> current dll base address
       movzx  eax, word ptr [eax+edi]   ; eax = Ordinal number for this index
       mov    ebx, esp                  ; ebx-> current dll base address
       add    ebx, [ecx+eax*4]          ; ebx-> proc address
       movd   esp, MM7                  ; restore the stack
;.......................................;
Is_it_Forwarded:                        ; check if proc address is inside export directory
       cmp    esi, ebx                  ; esi-> ExportDirectory
       jnl    EndProc                   ;
       cmp    ebx, [esp+0*4]            ; [esp+0*4] = ExportDirectory address + ExportDirectorySize
       jl     Forwarded                 ;
;.......................................;
EndProc:                                ;
       mov    edi, [esp+2*4+0*4]        ; restoring registers
       mov    eax, ebx                  ; eax->proc address  or zero
       mov    ebp, [esp+2*4+1*4]        ;
       mov    esi, [esp+2*4+2*4]        ;
       mov    ebx, [esp+2*4+3*4]        ;
       add    esp, 2*4+4*4              ;
       ret    2*4                       ;
;.......................................;
End_ZeroIndex:                          ;   
       jc     IndexIsZero               ; if it is 1st time zero->return, 
       movd   esp, MM7                  ; else (2nd time zero)-> restore the stack 
End_NotFound:                           ; and exit
       xor    ebx, ebx                  ; ebx=0 -> flag not found
       je     EndProc                   ;
;.......................................;
GetByOrdinal:                           ;
       cmp    ebp, [esi+14h]
       jnl    End_NotFound              ; esi-> ExportDirectory
       sub    ebp, [esi+10h]
       mov    eax, ebx                  ; eax-> current dll base address
       add    eax, [esi+1Ch]
       add    ebx, [eax + ebp*4]        ; ebx-> proc address
       jne    Is_it_Forwarded           ;
;.......................................;
Forwarded_Dll:                          ;
; Copy dll name in the stack............;
       xor    eax, eax                  ; eax->index = 0
       sub    esp, 2048                 ; room for dll name in the stack
       xor    ebx, ebx                  ; ebx=0
g:                                     ;
       mov    cl,  [edx+eax]            ; edx->lp Dll name->source
       add    eax, 1                    ;
       mov    [esp+eax-1], cl           ; esp->lp target buffer
       test   cl,  cl                   ;
       je     h                        ;
       cmp    cl,  2Eh                  ; "."
       jne    g                        ;
       mov    [esp+eax-1], ebx          ; ebx=0
h:                                     ;
	   push esp
       call LoadLibraryWrapper          ; call API
       add    esp, 2048                 ; restore the stack
       add    ebx, eax                  ; ebx-> BaseDllName address or zero
       jne    GetNextApi                ;
       je     End_NotFound              ; No such dll -> exit with ebx=0-> error
;.......................................;
Forwarded:                              ;
       mov    eax, ebx                  ; eax->proc address 
; Call the proc "recursively"...........;
i:                                     ;
       cmp    byte ptr [eax], 2Eh       ; looking for "."
       lea    eax, [eax+1]              ;
       jne    i                        ;
       cmp    byte ptr [eax], 23h       ; Is it forwarded by ordinal?  Ex: "ntdll.#12"
       je     j                        ;
GetProc:                               ;
       mov    dword ptr [esp+1*4], -1   ; set flag -> it is forwarded
       mov    [esp+1*4+(4*4+2*4)], eax  ; eax->offset of proc name or ordinal value
       mov    [esp+2*4+(4*4+2*4)], ebx  ; ebx->lp Dll name
       jmp    GetStart                  ; start it again with new proc name and Dll name and flag
j:                                     ;
; A2Dw..................................;
       lea    edx, [eax+1]              ;
       xor    eax, eax                  ;
k:                                     ;
       movzx  ecx, byte ptr [edx]       ;
       add    edx, 1                    ;
       test   ecx, ecx                  ;
       je     GetProc                  ;
       lea    eax, [eax+4*eax]          ;
       lea    eax, [ecx+2*eax-30h]      ; eax=(eax*10 +ecx-30h)
       jne    k                        ;
; End A2Dw..............................;
	}
}

__declspec(noinline) void encrypt(char* dst, const int max_size)
{
	for (auto i = 0; i < max_size; i++)
	{
		auto chr = dst[i];
		if(chr == '\0')
		{
			break;
		}

		chr = chr ^ 11;
		dst[i] = chr;
	}
}