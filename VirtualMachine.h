#pragma once

struct call_context
{
	int hash;
	int function_size;
	int stored_bytes[1];
	int bytes_offset;
	int globals;
	int* arguments; 
};

struct instruction
{
	int code;
	call_context call_context;
};

class virtual_machine
{
public:
	virtual_machine();
	~virtual_machine();

	void initialize(void* instruction_data, int size);
	bool run();
	void shutdown() const;
	void* get_data_stream() const;
	void add_globals(int* globals);
	void adjust_data_offset(int offset);
	void adjust_instruction_code(int offset);
	void adjust_call_target(int offset);
	void adjust_globals_offset(int offset);
	static bool is_dbg_present_prefix_check();

private:
	int next_instruction_align_;
	int call_target_align_;
	int globals_offset_align_;

	int* globalsPtr[255]{};
	void* instruction_data_{};
	int instruction_data_offset_;

	int* stack_;
	int stack_count_;
	int temp_value_;

	instruction* get_next_instruction();
};

class virtual_machine_impl : public virtual_machine
{
	/// TODO:
};
