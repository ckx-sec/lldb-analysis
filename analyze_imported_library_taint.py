# analyze_imported_library_taint.py
# Analyzes taint propagation starting from the outputs of calls to functions 
# imported from a user-specified third-party library.
# Outputs results to a JSON file.
# Based on function-taint-interprocedural.py logic.

# Import necessary Ghidra modules
from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable
from ghidra.program.model.listing import Function, Instruction, VariableStorage
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Pointer
import ghidra.program.model.pcode # For ghidra.program.model.pcode.HighLocal, HighOther
import traceback
import sys
import json # Added for JSON output

# -------------------
# Global Configuration & State
# -------------------
MAX_RECURSION_DEPTH = 5
UNRESOLVED_CALL_EXPLORE_BUDGET = 3
all_tainted_usages = [] 
visited_function_states = set()

# -------------------
# Global Helper Functions (Copied and modified from function-taint-interprocedural.py)
# -------------------
def get_varnode_representation(varnode_obj, high_function_context, current_program_ref):
    if varnode_obj is None: return "None"
    if high_function_context:
        actual_high_var_target = varnode_obj
        if not isinstance(varnode_obj, HighVariable):
            actual_high_var_target = varnode_obj.getHigh()
        if actual_high_var_target:
            display_name = actual_high_var_target.getName()
            storage_info_str = None
            symbol = actual_high_var_target.getSymbol()
            if symbol:
                if symbol.getName() and symbol.getName() != "UnnamedSymbol":
                    if not display_name or ("Unnamed" in display_name and "Unnamed" not in symbol.getName()):
                        display_name = symbol.getName()
                elif not display_name:
                    display_name = symbol.getName()
                try:
                    vs = symbol.getStorage()
                    if vs and not vs.isInvalidStorage():
                        storage_info_str = vs.toString()
                except AttributeError: pass
            if storage_info_str is None:
                rep_vn = actual_high_var_target.getRepresentative()
                if rep_vn:
                    if rep_vn.isRegister():
                        reg = current_program_ref.getLanguage().getRegister(rep_vn.getAddress(), rep_vn.getSize())
                        storage_info_str = reg.getName() if reg else "Register"
                    elif rep_vn.getAddress() is not None and rep_vn.getAddress().isStackAddress():
                        storage_info_str = "Stack[{:#x}]".format(actual_high_var_target.getStackOffset()) if hasattr(actual_high_var_target, 'getStackOffset') else "StackDirect[{}]".format(rep_vn.getAddress().toString(True))
                    elif rep_vn.isUnique():
                        storage_info_str = "UniquePcode[0x{:x}]".format(rep_vn.getOffset())
                    elif rep_vn.isConstant():
                        storage_info_str = "Constant"
                    elif rep_vn.getAddress() is not None and rep_vn.getAddress().isMemoryAddress() and not rep_vn.getAddress().isStackAddress():
                         storage_info_str = "GlobalMem[{}]".format(rep_vn.getAddress().toString(True))
                if storage_info_str is None and isinstance(actual_high_var_target, ghidra.program.model.pcode.HighOther):
                     storage_info_str = "HighOther"
            if display_name is None : display_name = "UnnamedHighVar"
            if storage_info_str:
                return "{}({})".format(display_name, storage_info_str)
            else:
                return "{} (HighVar Repr)".format(display_name)
    if varnode_obj.isRegister():
        reg = current_program_ref.getLanguage().getRegister(varnode_obj.getAddress(), varnode_obj.getSize())
        return reg.getName() if reg else "reg_vn:{}".format(varnode_obj.getAddress())
    if varnode_obj.isConstant():
        return "const_vn:0x{:x}".format(varnode_obj.getOffset())
    if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isStackAddress():
        return "stack_vn_direct:{}".format(varnode_obj.getAddress().toString(True))
    if varnode_obj.isUnique():
        def_op = varnode_obj.getDef()
        if def_op:
            return "unique_vn:{}(def:{}) (size {})".format(varnode_obj.getOffset(), def_op.getMnemonic(), varnode_obj.getSize())
        return "unique_vn:{} (size {})".format(varnode_obj.getOffset(), varnode_obj.getSize())
    if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isMemoryAddress():
        return "mem_vn:{}".format(varnode_obj.getAddress().toString(True))
    return varnode_obj.toString()

def print_tainted_value_usage_results(results_list, println_func, is_global_print=False):
    # (Content of this function remains largely the same as in the previous script version)
    # ... (omitted for brevity in this diff, but it's the same as before) ...
    if not results_list:
        if not is_global_print: 
            println_func("\\nNo specific usages (CALL args, STOREs, CBRANCH conditions, RETURNs) of the tainted value found within the current function scope.")
        return

    if is_global_print:
        println_func("\\n--- All Detected Tainted Value Usages (Interprocedural) ---")
    else:
        println_func("\\n--- Detected Tainted Value Usages (Current Function Scope) ---")

    included_usage_types = [
        "BRANCH_CONDITION_TAINTED",
        "TAINTED_ARG_TO_CALL_RECURSION",
        "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
        "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP",
        "TAINTED_ARG_TO_UNRESOLVED_CALL",
        "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
        "RETURN_TAINTED_VALUE"
    ]
    cpu_flag_core_names = [
        "tmpcy", "ng", "zf", "cf", "of", "sf", "pf", 
        "tmpnz", "tmpov", "tmpca", "af", 
        "cc_n", "cc_z", "cc_c", "cc_v"
    ]
    filtered_results_to_print = []
    for res in results_list:
        include_this_result = False
        if res["usage_type"] in included_usage_types:
            include_this_result = True
            if res["usage_type"] == "BRANCH_CONDITION_TAINTED":
                is_cpu_flag_component = False
                tainted_comp_repr = res.get("tainted_component_repr", "")
                lc_tainted_comp_repr = tainted_comp_repr.lower()
                for flag_name in cpu_flag_core_names:
                    if "({}".format(flag_name) in lc_tainted_comp_repr and lc_tainted_comp_repr.endswith(")"):
                        last_paren_open_idx = lc_tainted_comp_repr.rfind('(')
                        if last_paren_open_idx != -1 and lc_tainted_comp_repr[-1] == ')':
                            content_in_paren = lc_tainted_comp_repr[last_paren_open_idx+1:-1]
                            if content_in_paren == flag_name:
                                is_cpu_flag_component = True; break
                    if lc_tainted_comp_repr == flag_name:
                        is_cpu_flag_component = True; break
                if is_cpu_flag_component:
                    # println_func("DEBUG: Filtering out BRANCH_CONDITION_TAINTED for CPU flag: {} (Original: {})".format(lc_tainted_comp_repr, tainted_comp_repr))
                    include_this_result = False
        if include_this_result:
            filtered_results_to_print.append(res)

    if not filtered_results_to_print and is_global_print:
        println_func("No usages matching the current filter (BRANCH, CALL, RETURN_TAINTED_VALUE related) were found.")
        return

    usage_counter = 0
    for res in filtered_results_to_print:
        usage_counter += 1
        println_func("Usage #{}:".format(usage_counter))
        if "originating_imported_function_name" in res:
             println_func("  Originating Lib Call: {}".format(res["originating_imported_function_name"]))
        if "function_name" in res:
            println_func("  Found In Function:   {} at {}".format(res["function_name"], res.get("function_entry", "N/A")))
        println_func("  Instruction Address: {}".format(res["address"]))
        println_func("    PCode Op:            {}".format(res["pcode_op_str"]))
        println_func("    Usage Type:          {}".format(res["usage_type"]))
        if "tainted_component_repr" in res:
             println_func("    Tainted Component:   {}".format(res["tainted_component_repr"]))
        if "destination_repr" in res:
             println_func("    Destination Address: {}".format(res["destination_repr"]))
        if "compared_operands" in res:
             println_func("    Compared Operands:   {} vs {}".format(res["compared_operands"][0], res["compared_operands"][1]))
        if "details" in res and res["details"] is not None:
             println_func("    Details:             {}".format(res["details"]))
        println_func("-" * 40)

def get_initial_taint_source(parent_high_function, call_site_address_obj, printerr_func, println_func):
    # (Content of this function remains the same)
    # ... (omitted for brevity) ...
    if parent_high_function is None:
        printerr_func("Helper Function Error: Provided HighFunction is None (in get_initial_taint_source).")
        return None, None
    target_call_pcode_op = None
    op_iter = parent_high_function.getPcodeOps(call_site_address_obj)
    while op_iter.hasNext():
        pcode_op = op_iter.next()
        if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
            target_call_pcode_op = pcode_op
            break
    if target_call_pcode_op is None:
        printerr_func("Helper Function Error: No CALL or CALLIND PcodeOp found at call site: {}.".format(call_site_address_obj))
        return None, None
    num_inputs = target_call_pcode_op.getNumInputs()
    if num_inputs < 2: 
        println_func("Helper Function Info: Call instruction at {} does not have enough parameters (Pcode inputs: {}). Cannot get last parameter.".format(call_site_address_obj, num_inputs))
        return None, target_call_pcode_op
    last_param_varnode = target_call_pcode_op.getInput(num_inputs - 1) 
    return last_param_varnode, target_call_pcode_op

def find_highlocal_for_output_slot(high_func, V_ref_to_output_slot, local_var_name_hint, println, current_program):
    # (Content of this function remains the same)
    # ... (omitted for brevity) ...
    println("DEBUG: Locating HighLocal for output variable, reference param is V_ref_to_output_slot: {}".format(
                get_varnode_representation(V_ref_to_output_slot, high_func, current_program)))
    if local_var_name_hint:
        lsm = high_func.getLocalSymbolMap()
        symbols_iter = lsm.getSymbols()
        while symbols_iter.hasNext():
            symbol = symbols_iter.next()
            if symbol and symbol.getName() == local_var_name_hint:
                hv = symbol.getHighVariable()
                if hv and isinstance(hv, ghidra.program.model.pcode.HighLocal):
                    println("DEBUG: Found HighLocal '{}' by provided name for output variable.".format(local_var_name_hint))
                    return hv
        println("DEBUG: Could not find HighLocal by name '{}'. Will attempt to find via V_ref_to_output_slot's HighVariable or SP-relative logic.".format(local_var_name_hint))
    v_ref_high = V_ref_to_output_slot.getHigh()
    if v_ref_high and isinstance(v_ref_high, ghidra.program.model.pcode.HighLocal):
        println("DEBUG: Directly found HighLocal for V_ref_to_output_slot: {}".format(get_varnode_representation(v_ref_high, high_func, current_program)))
        return v_ref_high
    def_op = V_ref_to_output_slot.getDef()
    pcode_derived_name_hint = None 
    if def_op:
        mnemonic = def_op.getMnemonic()
        if mnemonic in ["PTRADD", "PTRSUB", "INT_ADD", "INT_SUB"] and def_op.getNumInputs() == 2:
            op_in0 = def_op.getInput(0); op_in1 = def_op.getInput(1)
            sp_reg = current_program.getRegister("SP"); fp_reg = current_program.getRegister("X29") 
            base_reg_vn = None; pcode_offset_vn = None 
            if op_in0.isRegister() and op_in1.isConstant():
                base_reg_vn = op_in0; pcode_offset_vn = op_in1
            elif op_in1.isRegister() and op_in0.isConstant() and mnemonic not in ["PTRSUB", "INT_SUB"]:
                base_reg_vn = op_in1; pcode_offset_vn = op_in0
            if base_reg_vn and pcode_offset_vn:
                pcode_offset_val = pcode_offset_vn.getOffset() 
                pcode_offset_vn_repr_str = get_varnode_representation(pcode_offset_vn, high_func, current_program)
                offset_vn_high = pcode_offset_vn.getHigh()
                if "(" in pcode_offset_vn_repr_str and pcode_offset_vn_repr_str.endswith("(Constant)"):
                    name_part = pcode_offset_vn_repr_str[:-len("(Constant)")]
                    if name_part and name_part != "UnnamedSymbol" and "Unnamed" not in name_part and "const_" not in name_part:
                        pcode_derived_name_hint = name_part
                elif offset_vn_high and offset_vn_high.getName() and "Constant" not in offset_vn_high.getName() and "Unnamed" not in offset_vn_high.getName() and "const_" not in offset_vn_high.getName():
                     pcode_derived_name_hint = offset_vn_high.getName()
                is_sp_base = sp_reg and base_reg_vn.getAddress().equals(sp_reg.getAddress())
                is_fp_base = fp_reg and base_reg_vn.getAddress().equals(fp_reg.getAddress())
                if is_sp_base or is_fp_base:
                    base_reg_name_for_debug = "SP" if is_sp_base else "FP(X29)"
                    effective_stack_offset_calc = pcode_offset_val
                    if mnemonic in ["PTRSUB", "INT_SUB"] and base_reg_vn.equals(op_in0): effective_stack_offset_calc = -pcode_offset_val
                    println("DEBUG: V_ref_to_output_slot {} is {}-relative. Effective P-code offset: {:#x}".format(get_varnode_representation(V_ref_to_output_slot, high_func, current_program), base_reg_name_for_debug, effective_stack_offset_calc))
                    lsm = high_func.getLocalSymbolMap(); symbols_iter = lsm.getSymbols()
                    while symbols_iter.hasNext():
                        high_symbol_obj = symbols_iter.next()
                        if high_symbol_obj:
                            hv = high_symbol_obj.getHighVariable()
                            if hv and isinstance(hv, ghidra.program.model.pcode.HighLocal) and hasattr(hv, 'getStackOffset'):
                                try:
                                    hv_stack_offset = hv.getStackOffset()
                                    if abs(hv_stack_offset) == abs(effective_stack_offset_calc):
                                        println("DEBUG: Found potential HighLocal '{}' by matching ABSOLUTE stack offset ({:#x})".format(hv.getName(), abs(hv_stack_offset)))
                                        return hv
                                except Exception as e_offset_check: println("DEBUG: Error checking stack offset for {}: {}".format(hv.getName(), e_offset_check))                            
    if pcode_derived_name_hint and not local_var_name_hint: 
        println("DEBUG: Attempting fallback using P-code derived name hint: '{}'".format(pcode_derived_name_hint))
        lsm = high_func.getLocalSymbolMap(); symbols_iter = lsm.getSymbols()
        while symbols_iter.hasNext():
            symbol = symbols_iter.next() 
            if symbol and symbol.getName() == pcode_derived_name_hint:
                hv = symbol.getHighVariable()
                if hv and isinstance(hv, ghidra.program.model.pcode.HighLocal):
                    println("DEBUG: Found HighLocal '{}' by P-code derived name hint.".format(pcode_derived_name_hint)); return hv
    println("DEBUG: Could not automatically determine target HighLocal for output variable for {}.".format(get_varnode_representation(V_ref_to_output_slot,high_func,current_program)))
    return None

def log_unresolved_call_with_tainted_args(pcode_op, current_high_func, prog, tainted_hvs_from_caller, 
                                        current_func_name, current_func_entry_addr_obj, op_addr_obj, 
                                        println_func, originating_imported_func_name_for_log, context_msg=""):
    global all_tainted_usages
    target_addr_vn = pcode_op.getInput(0)
    for arg_idx in range(1, pcode_op.getNumInputs()):
        arg_vn = pcode_op.getInput(arg_idx)
        arg_hv = arg_vn.getHigh() if arg_vn else None
        if arg_hv and arg_hv in tainted_hvs_from_caller:
            details_str = "Tainted argument #{} ({}) passed to unresolved call (target: {}). {}".format(
                arg_idx - 1,
                get_varnode_representation(arg_vn, current_high_func, prog),
                get_varnode_representation(target_addr_vn, current_high_func, prog),
                context_msg
            )
            all_tainted_usages.append({
                "originating_imported_function_name": originating_imported_func_name_for_log,
                "function_name": current_func_name, 
                "function_entry": current_func_entry_addr_obj.toString(),
                "address": op_addr_obj.toString(), 
                "pcode_op_str": str(pcode_op),
                "usage_type": "TAINTED_ARG_TO_UNRESOLVED_CALL",
                "tainted_component_repr": get_varnode_representation(arg_vn, current_high_func, prog),
                "details": details_str.strip()
            })
            println_func("WARN: [{} @ {}] {}. Cannot recurse or explore further.".format(current_func_name, op_addr_obj.toString(), details_str.strip()))
            break 

# -------------------
# Core Taint Tracing Logic
# -------------------
def trace_taint_in_function(
    high_func_to_analyze,
    initial_tainted_hvs, 
    pcode_op_start_taint, 
    current_program,
    decompiler_ref, 
    println_func,
    printerr_func,
    monitor_ref, 
    originating_imported_func_name_for_log, # New parameter
    current_depth=0,
    func_manager_ref=None, 
    sub_recursion_budget=None, 
    current_sub_depth=0 
):
    global all_tainted_usages, visited_function_states 
    # ... (rest of the function setup, depth checks, state checks are the same)
    if current_depth > MAX_RECURSION_DEPTH:
        println_func("DEBUG: Max recursion depth ({}) reached.".format(MAX_RECURSION_DEPTH))
        return

    if sub_recursion_budget is not None and current_sub_depth >= sub_recursion_budget:
        println_func("DEBUG: Sub-recursion budget ({}) reached. Stopping this sub-path for {}.".format(
            sub_recursion_budget, high_func_to_analyze.getFunction().getName()
        ))
        return

    func_entry_addr = high_func_to_analyze.getFunction().getEntryPoint()
    func_name = high_func_to_analyze.getFunction().getName()

    initial_tainted_hvs_repr_list = sorted([get_varnode_representation(hv, high_func_to_analyze, current_program) for hv in initial_tainted_hvs])
    initial_tainted_hvs_repr_tuple = tuple(initial_tainted_hvs_repr_list)
    current_state_key = (func_entry_addr.toString(), initial_tainted_hvs_repr_tuple, originating_imported_func_name_for_log) # Add origin to state key

    if current_state_key in visited_function_states:
        println_func("DEBUG: Already analyzed function {} with initial taints {} (origin: {}). Skipping.".format(func_name, initial_tainted_hvs_repr_tuple, originating_imported_func_name_for_log))
        return
    visited_function_states.add(current_state_key)

    println_func("\\n>>> Analyzing function: {} (Depth: {}) at {} (Originating from: {}) with initial taints: {}".format(
        func_name, current_depth, func_entry_addr, originating_imported_func_name_for_log,
        ", ".join([get_varnode_representation(hv, high_func_to_analyze, current_program) for hv in initial_tainted_hvs])
    ))

    current_func_input_param_hvs = set()
    try:
        local_symbol_map = high_func_to_analyze.getLocalSymbolMap()
        if local_symbol_map:
            symbol_iterator = local_symbol_map.getSymbols()
            while symbol_iterator.hasNext():
                sym = symbol_iterator.next()
                if sym and sym.isParameter():
                    hv = sym.getHighVariable()
                    if hv: current_func_input_param_hvs.add(hv)
    except Exception as e:
        printerr_func("Error getting input parameters for {}: {}".format(func_name, e))

    tainted_high_vars_in_current_func = set(initial_tainted_hvs)
    tainted_high_var_representations_in_current_func = set()
    for hv_init in initial_tainted_hvs:
        tainted_high_var_representations_in_current_func.add(
            get_varnode_representation(hv_init, high_func_to_analyze, current_program)
        )

    op_iter_for_analysis = high_func_to_analyze.getPcodeOps()
    encountered_start_op = pcode_op_start_taint is None
    
    if pcode_op_start_taint:
        println_func("DEBUG: Starting taint in {} from PcodeOp: {} at {}".format(func_name, pcode_op_start_taint, pcode_op_start_taint.getSeqnum().getTarget()))
    else:
        println_func("DEBUG: Starting taint analysis from the beginning of function {}.".format(func_name))

    for current_pcode_op in op_iter_for_analysis:
        current_op_address = current_pcode_op.getSeqnum().getTarget()
        current_op_address_str = current_op_address.toString()

        if not encountered_start_op:
            if current_pcode_op.getSeqnum().equals(pcode_op_start_taint.getSeqnum()):
                encountered_start_op = True
                println_func("\\nDEBUG: Reached specified start PcodeOp {} at {} in {}, subsequent ops will be processed.".format(
                    current_pcode_op, current_op_address_str, func_name
                ))
            else:
                continue
        
        output_vn = current_pcode_op.getOutput()
        output_hv = output_vn.getHigh() if output_vn else None
        mnemonic = current_pcode_op.getMnemonic()

        # Modify all all_tainted_usages.append calls to include originating_imported_func_name_for_log
        if mnemonic == "CBRANCH":
            condition_vn = current_pcode_op.getInput(1)
            condition_hv = condition_vn.getHigh() if condition_vn else None
            condition_is_tainted = False; condition_hv_repr = "N/A"
            if condition_hv:
                condition_hv_repr = get_varnode_representation(condition_hv, high_func_to_analyze, current_program)
                if (condition_hv in tainted_high_vars_in_current_func or condition_hv_repr in tainted_high_var_representations_in_current_func): condition_is_tainted = True
            if condition_is_tainted:
                details_cbranch = "Tainted condition for branch."; compared_ops_repr = ["N/A", "N/A"]
                def_op_cond = condition_vn.getDef()
                if def_op_cond and def_op_cond.getNumInputs() >= 2 and def_op_cond.getMnemonic() in ["INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_AND", "BOOL_OR"]:
                    op1_vn_cond = def_op_cond.getInput(0); op2_vn_cond = def_op_cond.getInput(1)
                    compared_ops_repr = [get_varnode_representation(op1_vn_cond, high_func_to_analyze, current_program), get_varnode_representation(op2_vn_cond, high_func_to_analyze, current_program)]
                skip_this_cbranch_report_due_to_assembly = False
                instruction_at_op = currentProgram.getListing().getInstructionAt(current_op_address)
                if instruction_at_op and instruction_at_op.getMnemonicString().lower() in ["cbz", "cbnz"]: skip_this_cbranch_report_due_to_assembly = True
                if not skip_this_cbranch_report_due_to_assembly:
                    all_tainted_usages.append({
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                        "usage_type": "BRANCH_CONDITION_TAINTED", "tainted_component_repr": condition_hv_repr, 
                        "compared_operands": compared_ops_repr, "details": details_cbranch
                    })
                    println_func("INFO: [{} @ {}] Taint reached CBRANCH. Operands: {}.".format(func_name, current_op_address_str, compared_ops_repr))

        if mnemonic == "STORE":
            stored_value_vn = current_pcode_op.getInput(2)
            stored_value_hv = stored_value_vn.getHigh() if stored_value_vn else None
            if stored_value_hv and stored_value_hv in tainted_high_vars_in_current_func:
                dest_addr_vn = current_pcode_op.getInput(1)
                dest_hv = dest_addr_vn.getHigh() if dest_addr_vn else None
                usage_entry_store = {
                    "originating_imported_function_name": originating_imported_func_name_for_log,
                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                    "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                    "tainted_component_repr": get_varnode_representation(stored_value_vn, high_func_to_analyze, current_program),
                    "destination_repr": get_varnode_representation(dest_addr_vn, high_func_to_analyze, current_program)
                }
                if dest_hv and dest_hv in current_func_input_param_hvs and dest_hv not in initial_tainted_hvs:
                    details_store_term = "Tainted value stored into input parameter {} of {}. Path terminated.".format(get_varnode_representation(dest_hv, high_func_to_analyze, current_program), func_name)
                    usage_entry_store["usage_type"] = "TAINT_REACHED_INPUT_PARAMETER_TERMINATION"
                    usage_entry_store["details"] = details_store_term
                    all_tainted_usages.append(usage_entry_store)
                    println_func("INFO: [{} @ {}] {}.".format(func_name, current_op_address_str, details_store_term))
                    return 
                else:
                    usage_entry_store["usage_type"] = "STORE_TAINTED_VALUE"
                    usage_entry_store["details"] = "Tainted value stored."
                    all_tainted_usages.append(usage_entry_store)

        elif mnemonic == "RETURN":
            if current_pcode_op.getNumInputs() > 1:
                returned_value_vn = current_pcode_op.getInput(1)
                returned_value_hv = returned_value_vn.getHigh() if returned_value_vn else None
                if returned_value_hv and returned_value_hv in tainted_high_vars_in_current_func:
                    all_tainted_usages.append({
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                        "usage_type": "RETURN_TAINTED_VALUE", 
                        "tainted_component_repr": get_varnode_representation(returned_value_vn, high_func_to_analyze, current_program)
                    })
        
        if mnemonic in ["CALL", "CALLIND"]:
            called_function_obj = None; target_func_addr_vn = current_pcode_op.getInput(0)
            if mnemonic == "CALL" and target_func_addr_vn.isConstant():
                try:
                    called_func_address = current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                    if called_func_address and func_manager_ref: called_function_obj = func_manager_ref.getFunctionAt(called_func_address)
                except: pass
            if called_function_obj is None and func_manager_ref:
                ref_iter = current_program.getReferenceManager().getReferencesFrom(current_op_address, 0)
                for ref in ref_iter: 
                    if ref.getReferenceType().isCall():
                        func_from_ref = func_manager_ref.getFunctionAt(ref.getToAddress())
                        if func_from_ref: called_function_obj = func_from_ref; break
            
            memcpy_special_handling_applied = False
            if called_function_obj and called_function_obj.getName() == "memcpy":
                if current_pcode_op.getNumInputs() >= 4:
                    dest_vn_memcpy = current_pcode_op.getInput(1); src_vn_memcpy = current_pcode_op.getInput(2)
                    dest_hv_memcpy = dest_vn_memcpy.getHigh(); src_hv_memcpy = src_vn_memcpy.getHigh()
                    src_is_tainted_memcpy = False; src_hv_repr_memcpy = "N/A"
                    if src_hv_memcpy:
                        src_hv_repr_memcpy = get_varnode_representation(src_hv_memcpy, high_func_to_analyze, current_program)
                        if src_hv_memcpy in tainted_high_vars_in_current_func or src_hv_repr_memcpy in tainted_high_var_representations_in_current_func: src_is_tainted_memcpy = True
                    if src_is_tainted_memcpy:
                        memcpy_special_handling_applied = True
                        if dest_hv_memcpy:
                            dest_hv_repr_memcpy = get_varnode_representation(dest_hv_memcpy, high_func_to_analyze, current_program)
                            if not (dest_hv_memcpy in tainted_high_vars_in_current_func or dest_hv_repr_memcpy in tainted_high_var_representations_in_current_func):
                                tainted_high_vars_in_current_func.add(dest_hv_memcpy)
                                tainted_high_var_representations_in_current_func.add(dest_hv_repr_memcpy)
                                println_func("DEBUG: [memcpy Special Handling] Tainted src. Marking dest '{}' as tainted.".format(dest_hv_repr_memcpy))
                        else: printerr_func("WARN: [memcpy Special Handling] Tainted src, but dest HighVar N/A.")
                if memcpy_special_handling_applied: continue

            if called_function_obj:
                high_called_func = None
                try:
                    decompile_res_callee = decompiler_ref.decompileFunction(called_function_obj, 60, monitor_ref)
                    if decompile_res_callee and decompile_res_callee.getHighFunction(): high_called_func = decompile_res_callee.getHighFunction()
                except Exception as de: printerr_func("ERROR: Decompile callee {}: {}".format(called_function_obj.getName(), de))
                if high_called_func:
                    callee_func_proto = high_called_func.getFunctionPrototype()
                    num_formal_params = callee_func_proto.getNumParams() if callee_func_proto else 0
                    newly_tainted_callee_hvs = set()
                    tainted_arg_details_for_no_map = []
                    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()): 
                        caller_arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                        caller_arg_hv = caller_arg_vn.getHigh()
                        if caller_arg_hv and caller_arg_hv in tainted_high_vars_in_current_func:
                            conceptual_arg_idx = pcode_arg_idx - 1
                            tainted_arg_details_for_no_map.append("PCodeArg#{}:{}".format(conceptual_arg_idx, get_varnode_representation(caller_arg_vn, high_func_to_analyze, current_program)))
                            if callee_func_proto and conceptual_arg_idx < num_formal_params:
                                callee_param_symbol = callee_func_proto.getParam(conceptual_arg_idx)
                                hv_to_taint = callee_param_symbol.getHighVariable() if callee_param_symbol else None
                                if hv_to_taint: newly_tainted_callee_hvs.add(hv_to_taint)
                                else: println_func("WARN: Tainted arg for {}, but no HighVar for callee param #{}.".format(called_function_obj.getName(),conceptual_arg_idx ))
                            else: 
                                pass # Will be logged below if newly_tainted_callee_hvs is empty but tainted_arg_details_for_no_map is not
                    if newly_tainted_callee_hvs:
                        all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_RECURSION",
                            "details": "Recursive call to {} ({}) with taints: {}.".format(called_function_obj.getName(), mnemonic, ", ".join([get_varnode_representation(h, high_called_func, current_program) for h in newly_tainted_callee_hvs]))
                        })
                        trace_taint_in_function(high_called_func, newly_tainted_callee_hvs, None, current_program, decompiler_ref, println_func, printerr_func, monitor_ref, originating_imported_func_name_for_log, current_depth + 1, func_manager_ref, sub_recursion_budget=sub_recursion_budget, current_sub_depth=current_sub_depth +1 if sub_recursion_budget is not None else 0)
                    elif tainted_arg_details_for_no_map: # Tainted args exist but couldn't be mapped
                        all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
                            "details": "Tainted PCode args ({}) to {} ({}) cannot map to HighProto (count {}).".format(", ".join(tainted_arg_details_for_no_map), called_function_obj.getName(), mnemonic, num_formal_params)
                        })
            else: # Unresolved call
                potential_target_addr_to_explore = None; exploration_context_msg = ""
                if target_func_addr_vn.isConstant():
                    try:
                        addr = current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                        if addr: potential_target_addr_to_explore = addr; exploration_context_msg = "PCode target const addr {}".format(addr)
                    except: pass
                elif target_func_addr_vn.isAddress() and target_func_addr_vn.getAddress().isMemoryAddress() and not target_func_addr_vn.getAddress().isStackAddress():
                    pointer_loc_addr = target_func_addr_vn.getAddress()
                    try:
                        mem = current_program.getMemory()
                        ptr_val = mem.getLong(pointer_loc_addr) if current_program.getDefaultPointerSize() == 8 else (mem.getInt(pointer_loc_addr) & 0xFFFFFFFF)
                        addr = current_program.getAddressFactory().getAddress(hex(ptr_val))
                        if addr: potential_target_addr_to_explore = addr; exploration_context_msg = "PCode target RAM {}, read ptr {} -> target {}".format(pointer_loc_addr, hex(ptr_val), addr)
                    except: pass
                if potential_target_addr_to_explore and func_manager_ref and decompiler_ref and (current_depth < MAX_RECURSION_DEPTH):
                    attempted_func_obj = func_manager_ref.getFunctionAt(potential_target_addr_to_explore)
                    if attempted_func_obj:
                        high_attempted_func = None
                        try:
                            decompile_res_attempt = decompiler_ref.decompileFunction(attempted_func_obj, 60, monitor_ref)
                            if decompile_res_attempt and decompile_res_attempt.getHighFunction(): high_attempted_func = decompile_res_attempt.getHighFunction()
                        except: pass
                        if high_attempted_func:
                            attempted_callee_proto = high_attempted_func.getFunctionPrototype()
                            num_formal_attempted = attempted_callee_proto.getNumParams() if attempted_callee_proto else 0
                            newly_tainted_attempt = set(); any_tainted_arg_for_attempt = False; tainted_arg_details_attempt_no_map = []
                            for arg_idx_pcode_attempt in range(1, current_pcode_op.getNumInputs()):
                                arg_vn_attempt = current_pcode_op.getInput(arg_idx_pcode_attempt)
                                arg_hv_attempt = arg_vn_attempt.getHigh()
                                if arg_hv_attempt and arg_hv_attempt in tainted_high_vars_in_current_func:
                                    any_tainted_arg_for_attempt = True
                                    tainted_arg_details_attempt_no_map.append("PCodeArg#{}:{}".format(arg_idx_pcode_attempt-1, get_varnode_representation(arg_vn_attempt, high_func_to_analyze, current_program)))
                                    if attempted_callee_proto and (arg_idx_pcode_attempt -1) < num_formal_attempted:
                                        param_sym_att = attempted_callee_proto.getParam(arg_idx_pcode_attempt -1)
                                        hv_to_taint_att = param_sym_att.getHighVariable() if param_sym_att else None
                                        if hv_to_taint_att: newly_tainted_attempt.add(hv_to_taint_att)
                            if newly_tainted_attempt:
                                all_tainted_usages.append({"originating_imported_function_name": originating_imported_func_name_for_log, "function_name": func_name, "function_entry": func_entry_addr.toString(), "address": current_op_address_str, "pcode_op_str": str(current_pcode_op), "usage_type": "EXPLORING_INITIALLY_UNRESOLVED_CALL", "details": "Exploring {} to {} ({}) with taints. Budget: {}.".format(mnemonic, attempted_func_obj.getName(), exploration_context_msg, UNRESOLVED_CALL_EXPLORE_BUDGET)})
                                trace_taint_in_function(high_attempted_func, newly_tainted_attempt, None, current_program, decompiler_ref, println_func, printerr_func, monitor_ref, originating_imported_func_name_for_log, current_depth + 1, func_manager_ref, sub_recursion_budget=UNRESOLVED_CALL_EXPLORE_BUDGET, current_sub_depth=0)
                            elif any_tainted_arg_for_attempt:
                                 all_tainted_usages.append({"originating_imported_function_name": originating_imported_func_name_for_log, "function_name": func_name, "function_entry": func_entry_addr.toString(), "address": current_op_address_str, "pcode_op_str": str(current_pcode_op), "usage_type": "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP", "details": "Tainted args ({}) to {} (resolved to {}), but no HighProto map. {}".format(", ".join(tainted_arg_details_attempt_no_map), mnemonic, attempted_func_obj.getName(), exploration_context_msg)})
                        else: log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, originating_imported_func_name_for_log, "(decomp failed for explored {})".format(exploration_context_msg))
                    else: log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, originating_imported_func_name_for_log, "(no func obj at explored {})".format(exploration_context_msg))
                else: log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, originating_imported_func_name_for_log, "(cannot explore target)")

        if output_hv and output_hv not in tainted_high_vars_in_current_func:
            is_newly_tainted = False; source_of_taint_repr = "N/A"
            unary_ops = ["COPY", "CAST", "INT_NEGATE", "INT_2COMP", "POPCOUNT", "INT_ZEXT", "INT_SEXT", "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND", "INT2FLOAT", "FLOAT2INT", "BOOL_NEGATE"]
            multi_ops = ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "MULTIEQUAL", "PIECE", "SUBPIECE"]
            load_op = "LOAD"; inputs_to_check = []
            if mnemonic == load_op and current_pcode_op.getNumInputs() > 1: inputs_to_check.append(current_pcode_op.getInput(1))
            elif mnemonic in unary_ops and current_pcode_op.getNumInputs() > 0: inputs_to_check.append(current_pcode_op.getInput(0))
            elif mnemonic in multi_ops:
                if mnemonic == "SUBPIECE" and current_pcode_op.getNumInputs() > 0: inputs_to_check.append(current_pcode_op.getInput(0))
                else: 
                    for i in range(current_pcode_op.getNumInputs()): inputs_to_check.append(current_pcode_op.getInput(i))
            for input_vn in inputs_to_check:
                if input_vn:
                    input_hv = input_vn.getHigh()
                    if input_hv:
                        input_hv_repr = get_varnode_representation(input_hv, high_func_to_analyze, current_program)
                        if (mnemonic == load_op and (input_hv_repr in tainted_high_var_representations_in_current_func or input_hv in tainted_high_vars_in_current_func)) or (mnemonic != load_op and input_hv in tainted_high_vars_in_current_func):
                            is_newly_tainted = True; source_of_taint_repr = input_hv_repr; break
            if is_newly_tainted:
                should_add_taint_prop = True; is_strlen_call_output = False
                if mnemonic in ["CALL", "CALLIND"] and output_vn and output_vn.getHigh() == output_hv:
                    called_func_strlen_check = None; target_vn_strlen = current_pcode_op.getInput(0)
                    if mnemonic == "CALL" and target_vn_strlen.isConstant():
                        try:
                            addr_strlen = current_program.getAddressFactory().getAddress(hex(target_vn_strlen.getOffset()))
                            if addr_strlen and func_manager_ref: called_func_strlen_check = func_manager_ref.getFunctionAt(addr_strlen)
                        except: pass
                    elif func_manager_ref:
                        ref_iter_strlen = current_program.getReferenceManager().getReferencesFrom(current_op_address, 0)
                        for ref_strlen in ref_iter_strlen:
                            if ref_strlen.getReferenceType().isCall():
                                func_from_ref_strlen = func_manager_ref.getFunctionAt(ref_strlen.getToAddress())
                                if func_from_ref_strlen: called_func_strlen_check = func_from_ref_strlen; break
                    if called_func_strlen_check and called_func_strlen_check.getName() == "strlen": is_strlen_call_output = True
                if is_strlen_call_output:
                    println_func("DEBUG: [STRLEN SUPPRESSION] Output of strlen CALL {} will NOT be tainted.".format(get_varnode_representation(output_hv, high_func_to_analyze, current_program)))
                    should_add_taint_prop = False
                if should_add_taint_prop:
                    tainted_high_vars_in_current_func.add(output_hv)
                    output_hv_repr_set = get_varnode_representation(output_hv, high_func_to_analyze, current_program)
                    tainted_high_var_representations_in_current_func.add(output_hv_repr_set)
                    println_func("DEBUG: [{} @ {}] Taint propagated from {} to {} via {}.".format(func_name, current_op_address_str, source_of_taint_repr, output_hv_repr_set, mnemonic))

        if output_hv and output_hv in tainted_high_vars_in_current_func:
            if output_hv in current_func_input_param_hvs and output_hv not in initial_tainted_hvs:
                details_param_term = "Taint propagated to input parameter {} of {}. Path terminated.".format(get_varnode_representation(output_hv, high_func_to_analyze, current_program), func_name)
                all_tainted_usages.append({
                    "originating_imported_function_name": originating_imported_func_name_for_log,
                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                    "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                    "usage_type": "TAINT_REACHED_INPUT_PARAMETER_TERMINATION",
                    "tainted_component_repr": get_varnode_representation(output_hv, high_func_to_analyze, current_program),
                    "details": details_param_term
                })
                println_func("INFO: [{} @ {}] {}.".format(func_name, current_op_address_str, details_param_term))
                return 
    println_func("<<< Finished analyzing function: {}.".format(func_name))

# -------------------
# JSON Output Function
# -------------------
def save_results_to_json(usages_list, println_func, printerr_func, askFile_func):
    if not usages_list:
        println_func("No tainted usages to save to JSON.")
        return

    output_file_path = None
    if askFile_func is None:
        printerr_func("askFile function not available. Cannot prompt for JSON output file.")
        # Fallback to a default filename if askFile is not available
        output_file_path = "taint_analysis_results.json"
        println_func("Will attempt to save JSON to default path: {}".format(output_file_path))
    else:
        try:
            output_file_obj = askFile_func("Save Taint Analysis JSON Output", "Save")
            if not output_file_obj:
                println_func("JSON output cancelled by user.")
                return
            output_file_path = output_file_obj.getAbsolutePath()
        except Exception as e_askfile: # Catch any error during askFile_func usage
            printerr_func("Error using askFile function: {}. Falling back to default path.".format(e_askfile))
            output_file_path = "taint_analysis_results.json"
            println_func("Will attempt to save JSON to default path: {}".format(output_file_path))
    
    if not output_file_path: # Should not happen if logic above is correct, but as a safeguard
        printerr_func("Error: Output file path for JSON was not determined. Cannot save results.")
        return

    # Define filtering criteria similar to print_tainted_value_usage_results
    included_usage_types_for_json = [
        "BRANCH_CONDITION_TAINTED",
        "TAINTED_ARG_TO_CALL_RECURSION",
        "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
        "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP",
        "TAINTED_ARG_TO_UNRESOLVED_CALL",
        "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
        "RETURN_TAINTED_VALUE"
    ]
    cpu_flag_core_names_for_json = [
        "tmpcy", "ng", "zf", "cf", "of", "sf", "pf", 
        "tmpnz", "tmpov", "tmpca", "af", 
        "cc_n", "cc_z", "cc_c", "cc_v"
    ]

    all_simplified_usages = [] 
    for usage in usages_list: # This is all_tainted_usages from the global scope
        # Apply filtering
        should_include_this_usage = False
        current_usage_type = usage.get("usage_type")

        if current_usage_type in included_usage_types_for_json:
            should_include_this_usage = True
            if current_usage_type == "BRANCH_CONDITION_TAINTED":
                is_cpu_flag_component = False
                tainted_comp_repr = usage.get("tainted_component_repr", "")
                lc_tainted_comp_repr = tainted_comp_repr.lower()
                for flag_name in cpu_flag_core_names_for_json:
                    if "({}".format(flag_name) in lc_tainted_comp_repr and lc_tainted_comp_repr.endswith(")"):
                        last_paren_open_idx = lc_tainted_comp_repr.rfind('(')
                        if last_paren_open_idx != -1 and lc_tainted_comp_repr[-1] == ')':
                            content_in_paren = lc_tainted_comp_repr[last_paren_open_idx+1:-1]
                            if content_in_paren == flag_name:
                                is_cpu_flag_component = True; break
                    if lc_tainted_comp_repr == flag_name:
                        is_cpu_flag_component = True; break
                if is_cpu_flag_component:
                    should_include_this_usage = False
        
        if not should_include_this_usage:
            continue # Skip this usage if it doesn't pass filters

        # Construct a more detailed entry for each usage (that passed filtering)
        usage_entry_for_json = {
            "originating_imported_function_name": usage.get("originating_imported_function_name", "Unknown_Origin"),
            "found_in_function_name": usage.get("function_name", "N/A"),
            "found_in_function_entry": usage.get("function_entry", "N/A"), # Added
            "instruction_address": usage.get("address", "N/A"),          # Clarified key name
            "pcode_operation": usage.get("pcode_op_str", "N/A"),         # Clarified key name
            "usage_type": usage.get("usage_type", "N/A"),
            "tainted_component": usage.get("tainted_component_repr", "N/A")
        }

        # Add optional fields if they exist in the original usage dictionary
        if "details" in usage and usage["details"] is not None:
            usage_entry_for_json["details"] = usage["details"]
        
        if usage.get("usage_type") == "STORE_TAINTED_VALUE" and "destination_repr" in usage:
            usage_entry_for_json["store_destination"] = usage["destination_repr"]
        
        if usage.get("usage_type") == "BRANCH_CONDITION_TAINTED" and "compared_operands" in usage:
            usage_entry_for_json["branch_compared_operands"] = usage["compared_operands"]
            
        all_simplified_usages.append(usage_entry_for_json)

    try:
        with open(output_file_path, 'w') as f:
            json.dump(all_simplified_usages, f, indent=4) # Dump the list
        println_func("Taint analysis results saved to: {}".format(output_file_path))
    except IOError as e:
        printerr_func("Failed to write JSON output to file {}: {}".format(output_file_path, e))
    except Exception as e:
        printerr_func("An unexpected error occurred while writing JSON output: {}".format(e))

# -------------------
# Main script logic
# -------------------
def run_analysis():
    global all_tainted_usages, visited_function_states
    all_tainted_usages = []
    visited_function_states = set()
    decompiler = None
    func_manager = None
    
    try:
        # Resolve currentProgram and other essential Ghidra variables.
        # These will be populated from globals() or imported from __main__.
        currentProgram = None
        println = None
        printerr = None
        askString = None
        monitor = None
        getFunctionManager = None
        Address = None
        DecompInterface = None
        DecompileOptions = None
        askFile = None

        # Attempt to get variables from globals first
        _cp_g = globals().get('currentProgram')
        _pl_g = globals().get('println')
        _pe_g = globals().get('printerr')

        if _cp_g is not None and _pl_g is not None and _pe_g is not None:
            # Assume if currentProgram, println, printerr are global, others are too.
            currentProgram = _cp_g
            println = _pl_g
            printerr = _pe_g
            askString = globals().get('askString')
            monitor = globals().get('monitor')
            getFunctionManager = globals().get('getFunctionManager')
            Address = globals().get('Address')
            DecompInterface = globals().get('DecompInterface')
            DecompileOptions = globals().get('DecompileOptions')
            askFile = globals().get('askFile')
        else:
            # Need to import from __main__
            try:
                from __main__ import (
                    currentProgram as main_currentProgram,
                    askString as main_askString,
                    println as main_println,
                    printerr as main_printerr,
                    monitor as main_monitor,
                    getFunctionManager as main_getFunctionManager,
                    Address as main_Address,
                    DecompInterface as main_DecompInterface,
                    DecompileOptions as main_DecompileOptions,
                    askFile as main_askFile
                )
                currentProgram = main_currentProgram
                println = main_println
                printerr = main_printerr
                askString = main_askString
                monitor = main_monitor
                getFunctionManager = main_getFunctionManager
                Address = main_Address
                DecompInterface = main_DecompInterface
                DecompileOptions = main_DecompileOptions
                askFile = main_askFile
            except ImportError:
                # Use a basic print if printerr itself couldn't be imported/resolved
                sys.stderr.write("Error: Critical Ghidra variables could not be imported from __main__.\\n")
                return

        # Final checks for essential variables
        if currentProgram is None:
            (printerr if printerr else lambda msg: sys.stderr.write(msg + "\\n"))(
                "Error: 'currentProgram' is not defined. This script must be run in Ghidra."
            )
            return
        if println is None or printerr is None:
            sys.stderr.write("Error: 'println' or 'printerr' functions are not available.\\n")
            return
        
        # Check other critical utilities that don't have safe fallbacks like print
        # and are needed for core functionality.
        missing_utils = []
        if DecompInterface is None: missing_utils.append("DecompInterface")
        if DecompileOptions is None: missing_utils.append("DecompileOptions")
        if askString is None: missing_utils.append("askString")
        # func_manager is derived later, monitor can be None for some operations but good to check
        if monitor is None: missing_utils.append("monitor") # Or handle its absence more gracefully where used
        if askFile is None: missing_utils.append("askFile") # For JSON saving

        if missing_utils:
            printerr("Error: Missing essential Ghidra utilities: {}. Script cannot proceed fully.".format(", ".join(missing_utils)))
            # Depending on severity, might need to return, or proceed with limited functionality if possible.
            # For now, DecompInterface, DecompileOptions, askString, askFile are critical.
            if "DecompInterface" in missing_utils or "DecompileOptions" in missing_utils or "askString" in missing_utils or "askFile" in missing_utils:
                 return


        println_func = println
        printerr_func = printerr
        
        decompiler = DecompInterface()
        options = DecompileOptions()
        decompiler.setOptions(options)
        if not decompiler.openProgram(currentProgram): printerr_func("Failed to open program with decompiler."); return

        try: func_manager = currentProgram.getFunctionManager()
        except AttributeError: 
            if 'getFunctionManager' in globals() and getFunctionManager is not None: func_manager = getFunctionManager()
        if not func_manager: printerr_func("FATAL: Could not get FunctionManager."); return

        target_library_input_name = askString("Target Library Name", "Enter library name (e.g., libcrypto.so):")
        if not target_library_input_name or not target_library_input_name.strip(): println_func("No library name. Exiting."); return
        target_library_name = target_library_input_name.strip()
        println_func("DEBUG: Target library: '{}'".format(target_library_name))

        external_manager = currentProgram.getExternalManager()
        imported_function_symbols = []
        if target_library_name in external_manager.getExternalLibraryNames():
            ext_loc_iter = external_manager.getExternalLocations(target_library_name)
            while ext_loc_iter.hasNext():
                ext_loc = ext_loc_iter.next()
                imported_function_symbols.append( (ext_loc.getLabel(), ext_loc) )
        else:
            printerr_func("ERROR: Library '{}' not found.".format(target_library_name)); return

        if not imported_function_symbols: println_func("INFO: No imported symbols for '{}'.".format(target_library_name)); return
        println_func("INFO: Found {} imported symbols from '{}'. Analyzing call sites...".format(len(imported_function_symbols), target_library_name))

        total_call_sites_processed = 0
        for imported_func_label, _ext_loc_obj in imported_function_symbols: # _ext_loc_obj may not be used directly for getAddress now
            println_func("\\n--- Matching imported function label: '{}' (from library '{}') with program functions ---".format(imported_func_label, target_library_name))

            # Search for functions in the current program that match imported_func_label
            target_functions_in_program = []
            all_functions_iter = func_manager.getFunctions(True) # True to include non-primary/external placeholders if needed
            while all_functions_iter.hasNext():
                f = all_functions_iter.next()
                # We are looking for functions DEFINED in the program that might be stubs/wrappers for the import
                if f.getName() == imported_func_label:
                    target_functions_in_program.append(f)
            
            if not target_functions_in_program:
                println_func("INFO: No function named '{}' found defined within the current program that matches the import label. Skipping.".format(imported_func_label))
                continue

            # --- Modification: If multiple functions match, select only the first one, similar to FTI's behavior --- 
            selected_program_func_to_analyze = None
            if len(target_functions_in_program) > 1:
                # Sort by entry point to ensure consistent selection (e.g., lowest address)
                # FTI log indicated it used the one at 0010a3e0. Let's try to be consistent.
                # Sorting helps, but if addresses are not the sole criteria for FTI, this might still differ.
                # For now, sorting by address is a reasonable heuristic for "first".
                target_functions_in_program.sort(key=lambda fn: fn.getEntryPoint())
                selected_program_func_to_analyze = target_functions_in_program[0]
                printerr_func("WARN: Multiple functions found for name '{}'. Using the first one by address: {} at {}.".format(
                    imported_func_label, selected_program_func_to_analyze.getName(), selected_program_func_to_analyze.getEntryPoint()
                ))
            else: # Only one found
                selected_program_func_to_analyze = target_functions_in_program[0]
            # --- End Modification ---

            # Replace the loop with processing only the selected_program_func_to_analyze
            # for program_func_match in target_functions_in_program: # Old loop
            program_func_match = selected_program_func_to_analyze # Use the selected one
            
            # Check if a function was actually selected (should always be true if target_functions_in_program was not empty)
            if not program_func_match:
                printerr_func("INTERNAL ERROR: No program function selected for label '{}' despite matches found. Skipping.".format(imported_func_label))
                continue

            println_func("DEBUG: Analyzing program function '{}' at {} (selected for import label '{}'). Analyzing its call sites.".format(
                program_func_match.getName(), program_func_match.getEntryPoint(), imported_func_label
            ))

            # Now, find references TO THIS PROGRAM FUNCTION
            references_to_program_func = currentProgram.getReferenceManager().getReferencesTo(program_func_match.getEntryPoint())
            call_site_addresses_for_this_program_func = []
            for ref in references_to_program_func:
                if ref.getReferenceType().isCall():
                    caller_func_check = func_manager.getFunctionContaining(ref.getFromAddress())
                    if caller_func_check:
                        call_site_addresses_for_this_program_func.append(ref.getFromAddress())
            
            if not call_site_addresses_for_this_program_func:
                println_func("INFO: No direct call sites found for program function '{}' (matching import label '{}').".format(program_func_match.getName(), imported_func_label))
                continue
            
            println_func("INFO: Found {} call site(s) for program function '{}'. Analyzing each:".format(
                len(call_site_addresses_for_this_program_func), program_func_match.getName()
            ))

            # Process these call sites
            for i, call_site_addr in enumerate(call_site_addresses_for_this_program_func):
                total_call_sites_processed += 1
                # The 'imported_func_name' for logging within this specific call site analysis
                # should be the name of the function actually being called, i.e., program_func_match.getName()
                # The 'originating_imported_func_name_for_log' for trace_taint_in_function will be imported_func_label.
                
                println_func("\\n--- Analyzing Call Site #{} to program function '{}' (Call at {}) ---".format(
                    i + 1, program_func_match.getName(), call_site_addr
                ))
                parent_of_call_site_func = func_manager.getFunctionContaining(call_site_addr)
                if not parent_of_call_site_func: 
                    printerr_func("ERROR: No parent function for call site {}. Skipping.".format(call_site_addr))
                    continue
                println_func("DEBUG: Parent (caller): {} at {}".format(parent_of_call_site_func.getName(), parent_of_call_site_func.getEntryPoint()))

                decompile_results_parent = decompiler.decompileFunction(parent_of_call_site_func, 60, monitor)
                if not decompile_results_parent or decompile_results_parent.getHighFunction() is None: 
                    printerr_func("Failed to decompile {}. Skipping.".format(parent_of_call_site_func.getName()))
                    continue
                high_parent_function = decompile_results_parent.getHighFunction()
                
                current_initial_taint_source_hv_set = set()
                current_start_pcode_op_for_trace = None
                
                V_addr_of_output_ptr_var, identified_call_op = get_initial_taint_source(high_parent_function, call_site_addr, printerr_func, println_func)

                if V_addr_of_output_ptr_var and identified_call_op:
                    H_output_var = find_highlocal_for_output_slot(high_parent_function, V_addr_of_output_ptr_var, None, println_func, currentProgram)
                    if H_output_var:
                        current_initial_taint_source_hv_set.add(H_output_var)
                        current_start_pcode_op_for_trace = identified_call_op
                        println_func(
                            "DEBUG: Initial taint (via last param output slot) for call to {}: {}. Analysis in {} after PCodeOp {} (Seq: {})."
                            .format(
                                program_func_match.getName(), 
                                get_varnode_representation(H_output_var, high_parent_function, currentProgram), 
                                parent_of_call_site_func.getName(), 
                                current_start_pcode_op_for_trace,
                                current_start_pcode_op_for_trace.getSeqnum().toString() if current_start_pcode_op_for_trace else "N/A"
                            )
                        )
                    else: 
                        # This error occurs if find_highlocal_for_output_slot fails after get_initial_taint_source succeeds.
                        printerr_func(
                            "ERROR: Could not determine HighLocal for last param output slot for call site {} (to {}) V_ref {}. No initial taint."
                            .format(
                                call_site_addr, program_func_match.getName(), 
                                get_varnode_representation(V_addr_of_output_ptr_var, high_parent_function, currentProgram) if V_addr_of_output_ptr_var else "None"
                            )
                        )
                        # Skip this call site as we couldn't resolve the HighLocal needed for taint source
                        println_func("INFO: Skipping call site {} due to failure to resolve HighLocal for output.".format(call_site_addr))
                        continue # Continue to the next call site
                else:
                    # This error occurs if get_initial_taint_source itself fails (e.g., not enough PCode inputs)
                    # The get_initial_taint_source function would have printed its own specific info/error message already.
                    printerr_func(
                        "ERROR: Could not identify a suitable reference parameter (last PCode input) or PCodeOp for call site {} (to {}) in {}. No initial taint from this mechanism."
                        .format(call_site_addr, program_func_match.getName(), parent_of_call_site_func.getName())
                    )
                    # As per making it consistent with FTI, if this primary mechanism fails, we don't try others.
                    # We will fall through to the final check which will then skip this call site.

                # Final check: If no taint source was set by the primary mechanism, skip this call site.
                if not current_initial_taint_source_hv_set or not current_start_pcode_op_for_trace:
                    println_func(
                        "INFO: No initial taint source established for call site {} (to {}) in {}. Analysis not started for this site."
                        .format(call_site_addr, program_func_match.getName(), parent_of_call_site_func.getName())
                    )
                    continue # Skip to next call site
                
                # If we have a taint source, proceed with analysis
                println_func("\n--- Initiating Taint Analysis for: {} calling {} (call at {}) ---".format(
                    parent_of_call_site_func.getName(), program_func_match.getName(), call_site_addr
                ))
                trace_taint_in_function(
                    high_parent_function, current_initial_taint_source_hv_set, current_start_pcode_op_for_trace, 
                    currentProgram, decompiler, println_func, printerr_func, monitor, 
                    originating_imported_func_name_for_log=imported_func_label, # Use the original label from the library for tracking origin
                    current_depth=0, func_manager_ref=func_manager
                )
    
        if total_call_sites_processed == 0: 
            println_func("INFO: No call sites processed for '{}'.".format(target_library_name))

        println_func("\n--- Taint Analysis Run Complete ---")
        if all_tainted_usages:
            print_tainted_value_usage_results(all_tainted_usages, println_func, is_global_print=True)
            save_results_to_json(all_tainted_usages, println_func, printerr_func, askFile)
        else:
            println_func("No tainted value usages detected for library '{}'.".format(target_library_name))

    except Exception as e:
        def _safe_printerr(msg): sys.stderr.write(str(msg) + "\\n")
        def _safe_println(msg): sys.stdout.write(str(msg) + "\\n")
        _effective_printerr = globals().get('printerr', _safe_printerr)
        _effective_println = globals().get('println', _safe_println)
        _effective_printerr("An unhandled error occurred:")
        _effective_printerr(str(e))
        try:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            for line in tb_lines: _effective_printerr(line.rstrip())
        except: _effective_printerr("Error printing traceback.")
    finally:
        if decompiler is not None:
            decompiler.dispose()
            globals().get('println', lambda x: None)("DEBUG: Decompiler disposed.")

if __name__ == "__main__":
    if 'currentProgram' in globals() and currentProgram is not None:
        run_analysis()
    else:
        print("This script must be run from within Ghidra.")
    if 'println' in globals():
        println("analyze_imported_library_taint.py finished.")
    else:
        print("analyze_imported_library_taint.py finished (println not available).") 