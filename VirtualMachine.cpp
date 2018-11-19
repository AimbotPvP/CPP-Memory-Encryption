#include <Windows.h>
#include <winternl.h>
#include "VirtualMachine.h"

inline PEB* get_peb();

virtual_machine::virtual_machine()
{
	const auto useless = 54309543.f * 645645.f;
	if (useless == 54309543.f * 645645.f)
	{
		/// Force loading kernel32
		Beep(0, 0);
		next_instruction_align_ = 0;
		call_target_align_ = 0;
		instruction_data_offset_ = 0;
		globals_offset_align_ = 0;
		stack_ = static_cast<int*>(malloc(10 * 4)); /// Limited to 10 items
		stack_count_ = 0;
		temp_value_ = 0;
	}
}


virtual_machine::~virtual_machine()
= default;

void virtual_machine::initialize(void* instruction_data, int size)
{
	/// Initialize array
	for (auto& i : globalsPtr)
	{
		i = nullptr;
	}

	_asm
	{
		MOV		ebx, DWORD PTR FS:[18h]
		ADD		ebx, 10h /// === Useless; add 10h to TEB
		MOV ebx, DWORD PTR DS:[ebx+20h] /// === PEB; would be MOV EAX, DWORD PTR DS:[EAX+30] if we hadn't already added 10
		MOVZX ebx, BYTE PTR DS:[ebx+2] 
		test	ebx, ebx
		jz		no_debugger
	}
	return;

	no_debugger:
	/// Copy data
	instruction_data_ = malloc(size);
	memcpy(instruction_data_, instruction_data, size);
}

bool virtual_machine::run()
{
	/// Fetch next instruction
	auto next_instruction = get_next_instruction();

	/// Note: This is used to change the actual instruction by the function used before, be careful when using this
	auto next_instruction_code = next_instruction->code + next_instruction_align_;

	/// Execute
	switch (next_instruction_code)
	{
		/// CALL
	case -0x1:
		{
			/// Decode target
			auto globals = globalsPtr[next_instruction->call_context.globals + globals_offset_align_];
			globals_offset_align_ = 0;
			auto target_number = next_instruction->call_context.arguments[0];
			auto function = globals[target_number + call_target_align_];

			/// Validate call
			auto* memory = static_cast<int*>(malloc(next_instruction->call_context.function_size));
			memcpy(memory, reinterpret_cast<void*>(function), next_instruction->call_context.function_size);

			/// If call starts with JUMP (E9), trace
			if (*reinterpret_cast<BYTE*>(function) == 0xE9)
			{
				auto jump_target = *reinterpret_cast<DWORD*>(function + 1);
				DWORD address = function;
				jump_target = address + jump_target + 5; /// Calculate target by using the current address + the offset + 5 to skip the jump instruction

				memcpy(memory, reinterpret_cast<void*>(jump_target), next_instruction->call_context.function_size);
			}

			/// cout << "Hashing " << nextInstruction->callContext.hash << endl;

			/// Hash memory
			auto hash = 0;
			for (auto i = 0; i < next_instruction->call_context.function_size; i++)
			{
				/// cout << (BYTE)(memory)[i] << " ";
				hash += static_cast<BYTE>(memory[i]);
			}
			/// cout << endl;
			if (hash < 0)
			{
				hash *= -1;
			}

			/// cout << hash << " (" << nextInstruction->callContext.functionSize << ")" << endl;

			if (hash == next_instruction->call_context.hash)
			{
				/// cout << "Calling" << endl;
				auto
				= reinterpret_cast<void (*)(call_context call_context)>(function);
				funcPtr(next_instruction->call_context);
			}
			else
			{
				/// cout << "Call suppressed" << endl;
			}
			/// cin.get();

			/// Free temp memory
			free(memory);
		}
		break;

		/// LABEL
	case -0x2:
		{
			/// Decode target
			auto globals = globalsPtr[next_instruction->call_context.globals + globals_offset_align_];
			globals_offset_align_ = 0;
			auto target_number = next_instruction->call_context.arguments[0];

			/// Get current offset (+ 4 to skip the parameter)
			instruction_data_offset_ += 4;
			auto offset = instruction_data_offset_;

			/// Save offset
			globals[target_number] = offset;
		}
		break;

		/// JMP
	case -0x3:
		{
			/// Decode target
			auto globals = globalsPtr[next_instruction->call_context.globals + globals_offset_align_];
			globals_offset_align_ = 0;
			auto target_number = next_instruction->call_context.arguments[0];
			instruction_data_offset_ = globals[target_number];
		}
		break;

		/// STORE
	case -0x4:
		{
			/// Decode target
			auto globals = globalsPtr[next_instruction->call_context.globals + globals_offset_align_];
			globals_offset_align_ = 0;
			auto target_number = next_instruction->call_context.arguments[0];
			globals[target_number] = next_instruction->call_context.arguments[1];

			instruction_data_offset_ += 8;
		}

		break;
	
		/// CALLS
	case -0x5:
		{
			/// Decode target
			auto globals = globalsPtr[next_instruction->call_context.globals + globals_offset_align_];
			globals_offset_align_ = 0;
			auto target_number = next_instruction->call_context.arguments[0];
			auto function = globals[target_number + call_target_align_];

			/// Validate call
			auto memory = malloc(next_instruction->call_context.function_size);
			memcpy(memory, reinterpret_cast<void*>(function), next_instruction->call_context.function_size);

			/// Hash memory
			auto hash = next_instruction->call_context.hash;

			if (hash == next_instruction->call_context.hash)
			{
				/// Append stack to arguments (4 = first argument (the target number) + all arguments on the stack * 4)
				auto temp_memory = malloc(4 + stack_count_ * 4);
				memcpy(temp_memory, next_instruction->call_context.arguments, 4);
				memcpy(reinterpret_cast<void*>(reinterpret_cast<int>(temp_memory) + 0x4), stack_, stack_count_ * 4);

				/// Free old arguments
				free(next_instruction->call_context.arguments);

				/// Store new
				next_instruction->call_context.arguments = static_cast<int*>(temp_memory);
				stack_count_ = 0;

				/// Call function
				auto call_func = reinterpret_cast<void (*)(call_context call_context)>(function);
				func_ptr(next_instruction->call_context);

				/// Targets called using stack don't have their arguments in the raw byte data, so we only have to skip 4 bytes everytime
				instruction_data_offset_ += 4;
			}

			/// Free temp memory
			free(memory);
		}
		break;

		/// PUSH
	case -0x6:
		{
			stack_[stack_count_] = temp_value_;
			stack_count_++;
		}

		break;

		/// LOAD
	case -0x7:
		{
			/// Decode target
			auto globals = globalsPtr[next_instruction->call_context.globals + globals_offset_align_];
			globals_offset_align_ = 0;
			auto target_number = next_instruction->call_context.arguments[0];
			temp_value_ = globals[target_number];

			instruction_data_offset_ += 4;
		}

		break;

		/// INT3
	case -0x8:
		_asm INT 3
		break;

	}

	/// Free arguments
	free(next_instruction->call_context.arguments);

	/// Discard instruction
	delete next_instruction;
	next_instruction = nullptr;

	return next_instruction_code != -0xDEAD;
}

void virtual_machine::shutdown() const
{
	free(stack_);
	free(instruction_data_);
}

void* virtual_machine::get_data_stream() const
{
	return instruction_data_;
}

void virtual_machine::add_globals(int* globals)
{
	for (auto& i : globalsPtr)
	{
		if (i == nullptr)
		{
			i = globals;
			break;
		}
	}
}

instruction* virtual_machine::get_next_instruction()
{
	/// Allocate 4 bytes for the code (integer)
	auto instruction_code = malloc(4);
	auto first_instruction = 0;
	auto address = reinterpret_cast<int>(instruction_data_) + instruction_data_offset_ + get_peb()->BeingDebugged;
	auto times_read = 0;

	/// Read until negative code (so an instruction) is present a second time
	while (true)
	{
		memcpy(instruction_code, reinterpret_cast<void*>(address + times_read * 4), sizeof instruction_code);
		const auto code = *static_cast<int*>(instruction_code);

		auto func_ptr = &virtual_machine::is_dbg_present_prefix_check;
		const auto p_ptr = *reinterpret_cast<BYTE*&>(func_ptr);
		if (p_ptr != 0x55)
		{
			*static_cast<int*>(instruction_code) = *static_cast<int*>(instruction_code) - 1;
		}

		/// If code below 0, so an instruction
		if (code < 0)
		{
			/// If first time, store instruction
			if (times_read == 0)
			{
				first_instruction = *static_cast<int*>(instruction_code);
			}
			else
			{
				/// If not the first time, we have reached another instruction, so we abort
				if (times_read > 0)
				{
					break;
				}
			}
		}

		/// If end of stream, abort
		if (code == -0xDEAD)
		{
			break;
		}

		times_read++;
	}

	/// Adjust offset for the next time, however we don't take the arguments into account but the fixed size of 6 for the context (5) and instruction (1)
	/// The offset for the arguments has to be adjusted by the called function
	instruction_data_offset_ += 24;

	/// Build instruction
	auto* instruction = new instruction();
	instruction->code = first_instruction;
	auto param_count = times_read - 6;
	if (param_count < 0) param_count = 0;

	/// Subtract 24 to get rid of recently added offset
	address = reinterpret_cast<int>(instruction_data_) + instruction_data_offset_ + is_dbg_present_prefix_check() + 4 - 24;
	memcpy(&instruction->call_context.hash, reinterpret_cast<void*>(address), 4);
	memcpy(&instruction->call_context.function_size, reinterpret_cast<void*>(address + 4), 4);
	memcpy(&instruction->call_context.stored_bytes, reinterpret_cast<void*>(address + 8), sizeof instruction->call_context.stored_bytes);
	memcpy(&instruction->call_context.bytes_offset, reinterpret_cast<void*>(address + 8 + sizeof instruction->call_context.stored_bytes), 4);
	memcpy(&instruction->call_context.globals, reinterpret_cast<void*>(address + 12 + sizeof instruction->call_context.stored_bytes), 4);
	instruction->call_context.arguments = static_cast<int*>(malloc(param_count * 4));
	memcpy(instruction->call_context.arguments, reinterpret_cast<void*>(address + 16 + sizeof instruction->call_context.stored_bytes), param_count * 4);

	free(instruction_code);
	return instruction;
}

void virtual_machine::adjust_data_offset(const int offset)
{
	instruction_data_offset_ += offset;
}

void virtual_machine::adjust_instruction_code(const int offset)
{
	next_instruction_align_ += offset;
}

void virtual_machine::adjust_call_target(const int offset)
{
	call_target_align_ += offset;
}

void virtual_machine::adjust_globals_offset(const int offset)
{
	globals_offset_align_ += offset;
}

inline PEB* get_peb()
{
__asm
	{
		mov EAX, fs:30h
	}
}

/// The IsDbgPresentPrefixCheck works in at least two debuggers
/// OllyDBG and VS 2008, by utilizing the way the debuggers handle
/// prefixes we can determine their presence. Specifically if this code
/// is ran under a debugger it will simply be stepped over;
/// however, if there is no debugger SEH will fire :D
__forceinline bool virtual_machine::is_dbg_present_prefix_check()
{
    __try
    {
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