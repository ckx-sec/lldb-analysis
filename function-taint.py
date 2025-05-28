# -- coding: utf-8 -*-
# ARMv8TaintTracer_Combined_Sourcing_V2.py
# MODIFIED FOR VALUE TAINT TRACKING & ENHANCED STORE ANALYSIS
# VERSION: Combined Taint Sourcing with Corrected P-code Mnemonics and Enhanced Store Classification
# INTERPROCEDURAL ANALYSIS ADDED

# Import necessary Ghidra modules
from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable
from ghidra.program.model.listing import Function, Instruction, VariableStorage
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Pointer # Added for checking pointer types

# -------------------
# Global Configuration & State
# -------------------
MAX_RECURSION_DEPTH = 5
UNRESOLVED_CALL_EXPLORE_BUDGET = 3 # Budget for exploring initially unresolved calls
all_tainted_usages = [] # Global list to store all results
visited_function_states = set() # To avoid redundant analysis cycles (function_entry, initial_tainted_high_vars_tuple)

# -------------------
# Global Helper Functions
# -------------------
def get_initial_taint_source(parent_high_function, call_site_address_obj, printerr_func, println_func):
    # Identifies the last PcodeOp input to a CALL/CALLIND, assumed to be the reference to the output slot.
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
    if num_inputs < 2: # Needs at least target address + 1 parameter
        println_func("Helper Function Info: Call instruction at {} does not have enough parameters (Pcode inputs: {}). Cannot get last parameter.".format(call_site_address_obj, num_inputs))
        return None, target_call_pcode_op
    last_param_varnode = target_call_pcode_op.getInput(num_inputs - 1)
    return last_param_varnode, target_call_pcode_op

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
                        storage_info_str = "UniquePcode"
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
    if not results_list:
        if not is_global_print: # Only print this if it's a per-function call and no results found for that function
            println_func("\nNo specific usages (CALL args, STOREs, CBRANCH conditions, RETURNs) of the tainted value found within the current function scope.")
        return

    if is_global_print:
        println_func("\n--- All Detected Tainted Value Usages (Interprocedural) ---")
    else:
        println_func("\n--- Detected Tainted Value Usages (Current Function Scope) ---")

    for i, res in enumerate(results_list):
        println_func("Usage #{}:".format(i + 1))
        # Add function context to results if not already there (will be added by trace_taint_in_function)
        if "function_name" in res:
            println_func("  Function:            {} at {}".format(res["function_name"], res.get("function_entry", "N/A")))
        println_func("  Instruction Address: {}".format(res["address"]))
        println_func("    PCode Op:            {}".format(res["pcode_op_str"]))
        println_func("    Usage Type:          {}".format(res["usage_type"]))
        if "tainted_component_repr" in res:
             println_func("    Tainted Component:   {}".format(res["tainted_component_repr"]))
        if "destination_repr" in res:
             println_func("    Destination Address: {}".format(res["destination_repr"]))
        if "compared_operands" in res: # For CBRANCH
             println_func("    Compared Operands:   {} vs {}".format(res["compared_operands"][0], res["compared_operands"][1]))
        if "details" in res and res["details"] is not None:
             println_func("    Details:             {}".format(res["details"]))
        println_func("-" * 40)

def find_highlocal_for_output_slot(high_func, V_ref_to_output_slot, local_var_name_hint, println, current_program):
    println("DEBUG: Locating HighLocal for output variable (e.g., 'local_68'), "
            "reference param is V_ref_to_output_slot (e.g., '&local_var'): {}".format(
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
            op_in0 = def_op.getInput(0)
            op_in1 = def_op.getInput(1)
            sp_reg = current_program.getRegister("SP")
            fp_reg = current_program.getRegister("X29") 

            base_reg_vn = None
            pcode_offset_vn = None 

            if op_in0.isRegister() and op_in1.isConstant():
                base_reg_vn = op_in0
                pcode_offset_vn = op_in1
            elif op_in1.isRegister() and op_in0.isConstant() and mnemonic not in ["PTRSUB", "INT_SUB"]:
                base_reg_vn = op_in1
                pcode_offset_vn = op_in0
            
            if base_reg_vn and pcode_offset_vn:
                pcode_offset_val = pcode_offset_vn.getOffset() 
                
                # Attempt to derive name hint from pcode_offset_vn's representation or its HighVariable
                pcode_offset_vn_repr_str = get_varnode_representation(pcode_offset_vn, high_func, current_program)
                offset_vn_high = pcode_offset_vn.getHigh()

                if "(" in pcode_offset_vn_repr_str and pcode_offset_vn_repr_str.endswith("(Constant)"):
                    name_part = pcode_offset_vn_repr_str[:-len("(Constant)")]
                    if name_part and name_part != "UnnamedSymbol" and "Unnamed" not in name_part and "const_" not in name_part:
                        pcode_derived_name_hint = name_part
                        println("DEBUG: P-code derived name hint by parsing representation '{}': {}".format(pcode_offset_vn_repr_str, pcode_derived_name_hint))
                elif offset_vn_high and offset_vn_high.getName() and \
                     "Constant" not in offset_vn_high.getName() and \
                     "Unnamed" not in offset_vn_high.getName() and \
                     "const_" not in offset_vn_high.getName():
                     pcode_derived_name_hint = offset_vn_high.getName()
                     println("DEBUG: P-code derived name hint from offset_vn_high.getName(): {}".format(pcode_derived_name_hint))
                else:
                    println("DEBUG: Could not derive a useful name hint from P-code offset varnode. Representation: '{}', HighVarName: '{}'".format(
                        pcode_offset_vn_repr_str,
                        offset_vn_high.getName() if offset_vn_high else "N/A"
                    ))

                is_sp_base = sp_reg and base_reg_vn.getAddress().equals(sp_reg.getAddress())
                is_fp_base = fp_reg and base_reg_vn.getAddress().equals(fp_reg.getAddress())

                if is_sp_base or is_fp_base:
                    base_reg_name_for_debug = "SP" if is_sp_base else "FP(X29)"
                    effective_stack_offset_calc = pcode_offset_val
                    if mnemonic in ["PTRSUB", "INT_SUB"]:
                        if base_reg_vn.equals(op_in0):
                             effective_stack_offset_calc = -pcode_offset_val
                    
                    println("DEBUG: V_ref_to_output_slot {} is {}-relative: {} {} {}. Effective P-code offset: {:#x} ({})".format(
                        get_varnode_representation(V_ref_to_output_slot, high_func, current_program),
                        base_reg_name_for_debug,
                        get_varnode_representation(base_reg_vn, high_func, current_program),
                        mnemonic,
                        pcode_offset_vn_repr_str, # Use the already obtained representation
                        effective_stack_offset_calc, effective_stack_offset_calc
                    ))

                    lsm = high_func.getLocalSymbolMap()
                    symbols_iter = lsm.getSymbols()
                    while symbols_iter.hasNext():
                        high_symbol_obj = symbols_iter.next()
                        if high_symbol_obj:
                            hv = high_symbol_obj.getHighVariable()
                            if hv and isinstance(hv, ghidra.program.model.pcode.HighLocal) and hasattr(hv, 'getStackOffset'):
                                try:
                                    hv_stack_offset = hv.getStackOffset()
                                    println("DEBUG:   Comparing with HighLocal '{}' (StackOffset: {:#x} ({})) HighSymbolName: {}, HV Storage: {}".format(
                                        hv.getName(), hv_stack_offset, hv_stack_offset, 
                                        high_symbol_obj.getName(), hv.getStorage().toString() if hv.getStorage() else "N/A"
                                    ))
                                    if abs(hv_stack_offset) == abs(effective_stack_offset_calc):
                                        println("DEBUG: Found potential HighLocal '{}' by matching ABSOLUTE stack offset ({:#x}) with P-code derived ABS offset ({:#x}) from {}-relative address.".format(
                                            hv.getName(), abs(hv_stack_offset), abs(effective_stack_offset_calc), base_reg_name_for_debug
                                        ))
                                        return hv
                                except Exception as e_offset_check:
                                    println("DEBUG: Error checking stack offset for {}: {}".format(hv.getName(), e_offset_check))                            
                    println("DEBUG: No HighLocal found by matching ABSOLUTE stack offsets for {}-relative address.".format(base_reg_name_for_debug))
    
    if pcode_derived_name_hint and not local_var_name_hint: 
        println("DEBUG: Attempting fallback using P-code derived name hint: '{}'".format(pcode_derived_name_hint))
        lsm = high_func.getLocalSymbolMap()
        symbols_iter = lsm.getSymbols()
        while symbols_iter.hasNext():
            symbol = symbols_iter.next() 
            if symbol and symbol.getName() == pcode_derived_name_hint:
                hv = symbol.getHighVariable()
                if hv and isinstance(hv, ghidra.program.model.pcode.HighLocal):
                    println("DEBUG: Found HighLocal '{}' by P-code derived name hint.".format(pcode_derived_name_hint))
                    return hv
        println("DEBUG: P-code derived name hint '{}' did not yield a HighLocal.".format(pcode_derived_name_hint))

    if local_var_name_hint is None:
        println("DEBUG: Could not automatically determine target HighLocal for output variable for {}. Failed all auto-detect methods (direct, SP/FP-relative offset, P-code name hint).".format(get_varnode_representation(V_ref_to_output_slot,high_func,current_program)))
    elif not (v_ref_high and isinstance(v_ref_high, ghidra.program.model.pcode.HighLocal)):
        println("DEBUG: After failing to find by name '{}', could not map V_ref_to_output_slot {} to a HighLocal via other methods.".format(local_var_name_hint, get_varnode_representation(V_ref_to_output_slot,high_func,current_program)))
        
    return None

# -------------------
# Core Taint Tracing Logic
# -------------------
def trace_taint_in_function(
    high_func_to_analyze,
    initial_tainted_hvs, # This is now a set of HighVariables
    pcode_op_start_taint, # PcodeOp where taint begins (e.g., the CALL site in the initial call, or None if starting from function entry params)
    current_program,
    decompiler_ref, # Pass decompiler for recursive calls
    println_func,
    printerr_func,
    monitor_ref, # Pass monitor for decompilation
    current_depth=0,
    func_manager_ref=None, # Pass function manager for recursive calls
    sub_recursion_budget=None, # Active budget for a special sub-path
    current_sub_depth=0      # Current depth within that sub-path budget
):
    global all_tainted_usages, visited_function_states # Use global variables

    # Check main recursion depth
    if current_depth > MAX_RECURSION_DEPTH:
        println_func("DEBUG: Max recursion depth ({}) reached. Stopping analysis path.".format(MAX_RECURSION_DEPTH))
        return

    # Check sub-recursion budget if active
    if sub_recursion_budget is not None and current_sub_depth >= sub_recursion_budget:
        println_func("DEBUG: Sub-recursion budget ({}) reached at sub-depth {}. Stopping this sub-path for {}.".format(
            sub_recursion_budget, current_sub_depth, high_func_to_analyze.getFunction().getName()
        ))
        return

    func_entry_addr = high_func_to_analyze.getFunction().getEntryPoint()
    func_name = high_func_to_analyze.getFunction().getName()

    initial_tainted_hvs_repr_list = sorted([get_varnode_representation(hv, high_func_to_analyze, current_program) for hv in initial_tainted_hvs])
    initial_tainted_hvs_repr_tuple = tuple(initial_tainted_hvs_repr_list)
    current_state_key = (func_entry_addr.toString(), initial_tainted_hvs_repr_tuple)

    if current_state_key in visited_function_states:
        println_func("DEBUG: Already analyzed function {} with initial taints {}. Skipping to avoid cycle.".format(func_name, initial_tainted_hvs_repr_tuple))
        return
    visited_function_states.add(current_state_key)

    println_func("\\n>>> Analyzing function: {} (Depth: {}, SubDepth: {}/{}) at {} with initial taints: {}".format(
        func_name, current_depth, current_sub_depth, sub_recursion_budget if sub_recursion_budget is not None else "N/A",
        func_entry_addr,
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
                    if hv:
                        current_func_input_param_hvs.add(hv)
            println_func("DEBUG: Identified {} input parameters for function {}.".format(len(current_func_input_param_hvs), func_name))
    except Exception as e:
        printerr_func("Error getting input parameters for {}: {}".format(func_name, e))

    tainted_high_vars_in_current_func = set(initial_tainted_hvs)

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
                println_func("\\nDEBUG: Reached specified start PcodeOp {} at {} in {}, subsequent ops will be processed for taint.".format(
                    current_pcode_op, current_op_address_str, func_name
                ))
            else:
                continue

        if not encountered_start_op: continue # Should not happen if logic above is correct

        output_vn = current_pcode_op.getOutput()
        output_hv = output_vn.getHigh() if output_vn else None
        mnemonic = current_pcode_op.getMnemonic()

        # --- TAINT USAGE & TERMINATION CHECKS ---
        if mnemonic == "CBRANCH":
            condition_vn = current_pcode_op.getInput(1)
            condition_hv = condition_vn.getHigh() if condition_vn else None
            if condition_hv and condition_hv in tainted_high_vars_in_current_func:
                details_cbranch = "Tainted condition for branch."
                compared_ops_repr = ["N/A", "N/A"]
                def_op_cond = condition_vn.getDef()
                if def_op_cond and def_op_cond.getNumInputs() >= 2 and def_op_cond.getMnemonic() in [
                    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
                    "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_AND", "BOOL_OR" 
                ]:
                    op1_vn_cond = def_op_cond.getInput(0)
                    op2_vn_cond = def_op_cond.getInput(1)
                    compared_ops_repr = [
                        get_varnode_representation(op1_vn_cond, high_func_to_analyze, current_program),
                        get_varnode_representation(op2_vn_cond, high_func_to_analyze, current_program)
                    ]
                    details_cbranch = "Tainted condition for branch ({}). Comparing: ({}) and ({}).".format(
                        def_op_cond.getMnemonic(), compared_ops_repr[0], compared_ops_repr[1]
                    )
                
                all_tainted_usages.append({
                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                    "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                    "usage_type": "BRANCH_CONDITION_TERMINATION",
                    "tainted_component_repr": get_varnode_representation(condition_vn, high_func_to_analyze, current_program),
                    "compared_operands": compared_ops_repr,
                    "details": details_cbranch
                })
                println_func("INFO: [{} @ {}] Taint reached CBRANCH condition. Operands: {}. Analysis path terminated.".format(
                    func_name, current_op_address_str, compared_ops_repr
                ))
                return # Terminate this analysis path

        # --- Store, Return (Non-terminating, just for logging interest) --- 
        # Based on original script, adapt if needed or remove if only termination/recursion matters
        if mnemonic == "STORE":
            stored_value_vn = current_pcode_op.getInput(2)
            stored_value_hv = stored_value_vn.getHigh() if stored_value_vn else None
            if stored_value_hv and stored_value_hv in tainted_high_vars_in_current_func:
                dest_addr_vn = current_pcode_op.getInput(1)
                dest_hv = dest_addr_vn.getHigh() if dest_addr_vn else None

                # Check if the destination of the STORE is an input parameter (and not an initial taint for this function call)
                if dest_hv and dest_hv in current_func_input_param_hvs and dest_hv not in initial_tainted_hvs:
                    details_store_to_param_term = "Tainted value {} stored into input parameter {} of function {}. Analysis path terminated.".format(
                        get_varnode_representation(stored_value_vn, high_func_to_analyze, current_program),
                        get_varnode_representation(dest_hv, high_func_to_analyze, current_program),
                        func_name
                    )
                    # Find callers
                    calling_functions_info_store = []
                    function_being_analyzed_store = high_func_to_analyze.getFunction()
                    if func_manager_ref: # Ensure func_manager_ref is available
                        references_to_function_store = current_program.getReferenceManager().getReferencesTo(function_being_analyzed_store.getEntryPoint())
                        for ref_store in references_to_function_store:
                            if ref_store.getReferenceType().isCall():
                                caller_func_store = func_manager_ref.getFunctionContaining(ref_store.getFromAddress())
                                if caller_func_store:
                                    calling_functions_info_store.append("{} at {}".format(caller_func_store.getName(), caller_func_store.getEntryPoint().toString()))
                    if calling_functions_info_store:
                        details_store_to_param_term += " Called by: [{}].".format(", ".join(calling_functions_info_store))
                    else:
                        details_store_to_param_term += " No direct callers found in program."
                    
                    all_tainted_usages.append({
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                        "usage_type": "TAINT_REACHED_INPUT_PARAMETER_TERMINATION",
                        "tainted_component_repr": get_varnode_representation(stored_value_vn, high_func_to_analyze, current_program),
                        "destination_repr": get_varnode_representation(dest_hv, high_func_to_analyze, current_program),
                        "details": details_store_to_param_term
                    })
                    println_func("INFO: [{} @ {}] {}. Analysis path terminated.".format(
                        func_name, current_op_address_str, details_store_to_param_term
                    ))
                    return # Terminate this analysis path
                else:
                    # Standard STORE of a tainted value (not to a non-initial input parameter)
                    all_tainted_usages.append({
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                        "usage_type": "STORE_TAINTED_VALUE", 
                        "tainted_component_repr": get_varnode_representation(stored_value_vn, high_func_to_analyze, current_program),
                        "destination_repr": get_varnode_representation(dest_addr_vn, high_func_to_analyze, current_program), # Using dest_addr_vn here for original full repr
                        "details": "Tainted value stored."
                    })
        elif mnemonic == "RETURN":
            if current_pcode_op.getNumInputs() > 1:
                returned_value_vn = current_pcode_op.getInput(1)
                returned_value_hv = returned_value_vn.getHigh() if returned_value_vn else None
                if returned_value_hv and returned_value_hv in tainted_high_vars_in_current_func:
                    all_tainted_usages.append({
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                        "usage_type": "RETURN_TAINTED_VALUE", 
                        "tainted_component_repr": get_varnode_representation(returned_value_vn, high_func_to_analyze, current_program)
                    })
        
        # --- RECURSIVE CALL HANDLING --- 
        if mnemonic in ["CALL", "CALLIND"]:
            called_function_obj = None
            target_func_addr_vn = current_pcode_op.getInput(0) # This is the PCode varnode for the call target

            # Step 1: Direct CALL to a constant address via P-code
            if mnemonic == "CALL" and target_func_addr_vn.isConstant():
                try:
                    called_func_address = current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                    if called_func_address:
                        called_function_obj = func_manager_ref.getFunctionAt(called_func_address)
                        if called_function_obj:
                            println_func("DEBUG: [{} @ {}] Resolved CALL to constant PCode target {} -> function {}.".format(
                                func_name, current_op_address_str, called_func_address, called_function_obj.getName()))
                except Exception as e:
                    printerr_func("ERROR: [{} @ {}] Converting PCode constant target {} for CALL: {}".format(
                        func_name, current_op_address_str, target_func_addr_vn.getOffset(), e))

            # Step 2: For CALLIND, or CALL to non-constant P-code target (if not resolved above), try Ghidra's reference manager
            # This is often effective for well-analyzed indirect calls or PLT-like structures.
            if called_function_obj is None:
                # Only proceed if it's CALLIND, or if it's CALL and its PCode target wasn't a resolvable constant above.
                should_try_ref_man = False
                if mnemonic == "CALLIND":
                    should_try_ref_man = True
                    println_func("DEBUG: [{} @ {}] CALLIND target {}. Attempting resolution via reference manager.".format(
                        func_name, current_op_address_str, get_varnode_representation(target_func_addr_vn, high_func_to_analyze, current_program)))
                elif mnemonic == "CALL" and not target_func_addr_vn.isConstant(): # CALL to reg, ram, etc.
                    should_try_ref_man = True
                    println_func("DEBUG: [{} @ {}] CALL to non-constant PCode target {}. Attempting resolution via reference manager.".format(
                        func_name, current_op_address_str, get_varnode_representation(target_func_addr_vn, high_func_to_analyze, current_program)))
                
                if should_try_ref_man and func_manager_ref:
                    ref_iter = current_program.getReferenceManager().getReferencesFrom(current_op_address, 0) # Check reference from instruction for call op index 0
                    for ref in ref_iter:
                        if ref.getReferenceType().isCall():
                            ref_target_addr = ref.getToAddress()
                            called_func_obj_from_ref = func_manager_ref.getFunctionAt(ref_target_addr)
                            if called_func_obj_from_ref:
                                println_func("DEBUG: [{} @ {}] Resolved {} via reference manager to function {} at {}.".format(
                                    func_name, current_op_address_str, mnemonic, called_func_obj_from_ref.getName(), ref_target_addr))
                                called_function_obj = called_func_obj_from_ref
                                break # Take the first resolved call reference
            
            # Step 3: If function is resolved by any means above, proceed to analyze it
            if called_function_obj:
                high_called_func = None
                try:
                    decompile_res_callee = decompiler_ref.decompileFunction(called_function_obj, 60, monitor_ref)
                    if decompile_res_callee and decompile_res_callee.getHighFunction():
                        high_called_func = decompile_res_callee.getHighFunction()
                except Exception as de:
                    printerr_func("ERROR: Failed to decompile callee {}: {}".format(called_function_obj.getName(), de))

                if high_called_func:
                    # Get the ordered formal parameters of the callee function
                    ordered_callee_formal_params = called_function_obj.getParameters() # Returns Parameter[]

                    newly_tainted_callee_hvs = set()
                    # mapped_conceptual_callee_param_indices = set() # To track if a conceptual slot is already mapped

                    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()): # Iterate P-code args (0 is call target)
                        caller_arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                        caller_arg_hv_in_caller_context = caller_arg_vn.getHigh()

                        if caller_arg_hv_in_caller_context and caller_arg_hv_in_caller_context in tainted_high_vars_in_current_func:
                            # This P-code argument from the caller is tainted.
                            # Map it to the callee's conceptual parameter based on order.
                            conceptual_arg_index = pcode_arg_idx - 1 # 0-indexed

                            if conceptual_arg_index < len(ordered_callee_formal_params):
                                target_formal_param = ordered_callee_formal_params[conceptual_arg_index]
                                hv_to_taint_in_callee = None
                                try:
                                    # Get the HighVariable for this formal parameter from the callee's HighFunction.
                                    hv_to_taint_in_callee = target_formal_param.getHighVariable(high_called_func)
                                except Exception as e_hv:
                                    printerr_func("ERROR: [{} @ {}] Exception getting HighVariable for formal param '{}' in {}: {}".format(
                                        func_name, current_op_address_str, target_formal_param.getName(),
                                        high_called_func.getFunction().getName(), e_hv))

                                if hv_to_taint_in_callee:
                                    newly_tainted_callee_hvs.add(hv_to_taint_in_callee)
                                    # mapped_conceptual_callee_param_indices.add(conceptual_arg_index)
                                    
                                    println_func("INFO: [{} @ {}] Tainted PCode argument #{} (VN: {}) for {} to {}. Mapped to ordered callee param (concept_idx:{}, formal_name:'{}', HV:{}).".format(
                                        func_name, current_op_address_str,
                                        pcode_arg_idx - 1, 
                                        get_varnode_representation(caller_arg_vn, high_func_to_analyze, current_program),
                                        mnemonic, called_function_obj.getName(),
                                        conceptual_arg_index,
                                        target_formal_param.getName(),
                                        get_varnode_representation(hv_to_taint_in_callee, high_called_func, current_program)
                                    ))
                                else:
                                    println_func("WARN: [{} @ {}] Tainted PCode argument #{} for {} to {}. Could not retrieve HighVariable for callee's formal parameter #{} (name: '{}').".format(
                                        func_name, current_op_address_str, pcode_arg_idx - 1,
                                        mnemonic, called_function_obj.getName(),
                                        conceptual_arg_index, target_formal_param.getName()
                                    ))
                            else:
                                # Number of PCode arguments exceeds number of formal parameters in callee (e.g. varargs)
                                println_func("WARN: [{} @ {}] Tainted PCode argument #{} for {} to {}. Exceeds formal parameter count ({}) of callee. Cannot map (possibly varargs).".format(
                                    func_name, current_op_address_str, pcode_arg_idx - 1,
                                    mnemonic, called_function_obj.getName(),
                                    len(ordered_callee_formal_params)
                                ))
                    
                    if newly_tainted_callee_hvs:
                        all_tainted_usages.append({
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_RECURSION",
                            "details": "Recursive call to {} ({}) due to tainted args: {}.".format(
                                called_function_obj.getName(), mnemonic, 
                                ", ".join([get_varnode_representation(h, high_called_func, current_program) for h in newly_tainted_callee_hvs]))
                        })
                        trace_taint_in_function(
                            high_called_func, newly_tainted_callee_hvs, None, 
                            current_program, decompiler_ref, println_func, printerr_func, monitor_ref,
                            current_depth + 1, func_manager_ref,
                            sub_recursion_budget=sub_recursion_budget, 
                            current_sub_depth=current_sub_depth + 1 if sub_recursion_budget is not None else 0 
                        )
            
            # Step 4: If function still not resolved, try exploration with budget
            else: 
                potential_target_addr_to_explore = None
                exploration_context_msg = ""

                # Attempt 4a: If P-code target is a constant (even if getFunctionAt failed before, e.g., no function defined there yet)
                if target_func_addr_vn.isConstant():
                    try:
                        addr = current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                        if addr:
                            potential_target_addr_to_explore = addr
                            exploration_context_msg = "PCode target is constant address {}".format(addr)
                            println_func("DEBUG: [{} @ {}] {}'s PCode target is constant address {}, trying exploration.".format(
                                func_name, current_op_address_str, mnemonic, addr))
                    except Exception as addr_ex:
                         printerr_func("WARN: [{} @ {}] Could not convert {}'s PCode constant target offset {} to address for exploration: {}".format(
                             func_name, current_op_address_str, mnemonic, target_func_addr_vn.getOffset(), addr_ex))
                
                # Attempt 4b: If P-code target is a RAM location (for CALL or CALLIND)
                # e.g., `CALL (ram, pointer_loc, _)` or `CALLIND (ram, pointer_loc, _)`
                elif target_func_addr_vn.isAddress() and target_func_addr_vn.getAddress().isMemoryAddress() and \
                     not target_func_addr_vn.getAddress().isStackAddress(): # Exclude stack, focus on global/heap
                    pointer_location_addr = target_func_addr_vn.getAddress()
                    try:
                        mem = current_program.getMemory()
                        pointer_val = None
                        # Determine pointer size: PCode target varnode size is a good hint for the size of the data at pointer_location_addr.
                        # This varnode (target_func_addr_vn) represents the *address* being called, its size might be pointer size.
                        vn_size = target_func_addr_vn.getSize() 
                        # However, if the PCode is `CALL (ram, ADDR_OF_PTR, ...)` the ADDR_OF_PTR itself is a varnode.
                        # The actual pointer is read from memory. The size of that *read* should be default pointer size.
                        # Let's assume default pointer size for the data at pointer_location_addr
                        default_ptr_size_prog = current_program.getDefaultPointerSize()

                        if default_ptr_size_prog == 8: # 64-bit pointer
                            pointer_val = mem.getLong(pointer_location_addr)
                        elif default_ptr_size_prog == 4: # 32-bit pointer
                            pointer_val = mem.getInt(pointer_location_addr) & 0xFFFFFFFF # No 'L'
                        else:
                             println_func("WARN: [{} @ {}] {} to PCode target RAM loc {}: Unhandled default pointer size {} for reading target.".format(
                                 func_name, current_op_address_str, mnemonic, pointer_location_addr, default_ptr_size_prog))
                        
                        if pointer_val is not None:
                            addr = current_program.getAddressFactory().getAddress(hex(pointer_val))
                            if addr:
                                potential_target_addr_to_explore = addr
                                exploration_context_msg = "PCode target is RAM location {}, read pointer value {} -> target address {}".format(
                                    pointer_location_addr, hex(pointer_val), addr)
                                println_func("DEBUG: [{} @ {}] For {}, PCode target is RAM loc {}. Read pointer {} -> potential target address {} for exploration.".format(
                                    func_name, current_op_address_str, mnemonic, pointer_location_addr, hex(pointer_val), addr))
                        else:
                             if default_ptr_size_prog in [4,8]: # Only log if we expected to read
                                printerr_func("WARN: [{} @ {}] Could not read pointer from RAM location {} (PCode target for {}) using {} byte read.".format(
                                    func_name, current_op_address_str, pointer_location_addr, mnemonic, default_ptr_size_prog))
                    except Exception as e:
                        printerr_func("ERROR: [{} @ {}] Reading pointer from RAM location {} (PCode target for {}) failed: {}".format(
                            func_name, current_op_address_str, pointer_location_addr, mnemonic, e))
                
                # Proceed with exploration if a potential target address was found
                if potential_target_addr_to_explore and func_manager_ref and decompiler_ref and (current_depth < MAX_RECURSION_DEPTH):
                    println_func("INFO: [{} @ {}] Target of {} initially unresolved. Attempting to explicitly resolve and analyze {} ({}) with budget {}.".format(
                        func_name, current_op_address_str, mnemonic, potential_target_addr_to_explore, exploration_context_msg, UNRESOLVED_CALL_EXPLORE_BUDGET)) 
                    
                    attempted_func_obj = func_manager_ref.getFunctionAt(potential_target_addr_to_explore)
                    if attempted_func_obj:
                        high_attempted_func = None
                        try:
                            decompile_res_attempt = decompiler_ref.decompileFunction(attempted_func_obj, 60, monitor_ref)
                            if decompile_res_attempt and decompile_res_attempt.getHighFunction():
                                high_attempted_func = decompile_res_attempt.getHighFunction()
                        except Exception as de_attempt:
                            printerr_func("ERROR: Decompiling explicitly resolved function {} at {} failed: {}".format(
                                attempted_func_obj.getName(), potential_target_addr_to_explore, de_attempt))

                        if high_attempted_func:
                            println_func("INFO: Successfully decompiled initially unresolved target {} at {} for {}.".format(
                                attempted_func_obj.getName(), potential_target_addr_to_explore, mnemonic))
                            newly_tainted_callee_hvs_attempt = set()
                            callee_param_hvs_attempt = []
                            lsm_callee_attempt = high_attempted_func.getLocalSymbolMap()
                            if lsm_callee_attempt:
                                sym_iter_callee_attempt = lsm_callee_attempt.getSymbols()
                                while sym_iter_callee_attempt.hasNext():
                                    sym_c_att = sym_iter_callee_attempt.next()
                                    if sym_c_att.isParameter():
                                        hv_c_att = sym_c_att.getHighVariable()
                                        if hv_c_att: callee_param_hvs_attempt.append(hv_c_att)
                            
                            any_tainted_arg_for_attempt = False # Renamed from newly_tainted_params_for_attempt to avoid confusion
                            
                            # Similar mapping logic for exploration path
                            ordered_callee_formal_params_attempt = attempted_func_obj.getParameters()
                            newly_tainted_callee_hvs_attempt = set()

                            for arg_idx_pcode_attempt in range(1, current_pcode_op.getNumInputs()):
                                arg_vn_attempt = current_pcode_op.getInput(arg_idx_pcode_attempt)
                                arg_hv_attempt_in_caller = arg_vn_attempt.getHigh() if arg_vn_attempt else None
                                if arg_hv_attempt_in_caller and arg_hv_attempt_in_caller in tainted_high_vars_in_current_func:
                                    any_tainted_arg_for_attempt = True # Mark that at least one pcode arg was tainted
                                    conceptual_arg_index_attempt = arg_idx_pcode_attempt - 1

                                    if conceptual_arg_index_attempt < len(ordered_callee_formal_params_attempt):
                                        target_formal_param_attempt = ordered_callee_formal_params_attempt[conceptual_arg_index_attempt]
                                        hv_to_taint_in_callee_attempt = None
                                        try:
                                            hv_to_taint_in_callee_attempt = target_formal_param_attempt.getHighVariable(high_attempted_func)
                                        except Exception as e_hv_att:
                                            printerr_func("ERROR: [{} @ {}] Exception getting HighVariable for formal param '{}' in explored {}: {}".format(
                                                func_name, current_op_address_str, target_formal_param_attempt.getName(),
                                                high_attempted_func.getFunction().getName(), e_hv_att))

                                        if hv_to_taint_in_callee_attempt:
                                            newly_tainted_callee_hvs_attempt.add(hv_to_taint_in_callee_attempt)
                                            println_func("INFO: [{} @ {}] Tainted PCode argument #{} (VN: {}) for {} to explored {}. Mapped to ordered callee param (concept_idx:{}, formal_name:'{}', HV:{}).".format(
                                                func_name, current_op_address_str,
                                                arg_idx_pcode_attempt - 1,
                                                get_varnode_representation(arg_vn_attempt, high_func_to_analyze, current_program),
                                                mnemonic, attempted_func_obj.getName(),
                                                conceptual_arg_index_attempt,
                                                target_formal_param_attempt.getName(),
                                                get_varnode_representation(hv_to_taint_in_callee_attempt, high_attempted_func, current_program)
                                            ))
                                        else:
                                            println_func("WARN: [{} @ {}] Tainted PCode argument #{} for {} to explored {}. Could not retrieve HighVariable for callee's formal param #{} (name: '{}').".format(
                                                func_name, current_op_address_str, arg_idx_pcode_attempt - 1,
                                                mnemonic, attempted_func_obj.getName(),
                                                conceptual_arg_index_attempt, target_formal_param_attempt.getName()
                                            ))
                                    else:
                                        println_func("WARN: [{} @ {}] Tainted PCode argument #{} for {} to explored {}. Exceeds formal param count ({}) of callee. Cannot map (possibly varargs).".format(
                                            func_name, current_op_address_str, arg_idx_pcode_attempt - 1,
                                            mnemonic, attempted_func_obj.getName(),
                                            len(ordered_callee_formal_params_attempt)
                                        ))
                            
                            if newly_tainted_callee_hvs_attempt:
                                all_tainted_usages.append({
                                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                    "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                                    "usage_type": "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
                                    "details": "Exploring {} to now-resolved {} ({}) with tainted params: {}. Budget: {} levels.".format(
                                        mnemonic, attempted_func_obj.getName(), exploration_context_msg,
                                        ", ".join([get_varnode_representation(h, high_attempted_func, current_program) for h in newly_tainted_callee_hvs_attempt]),
                                        UNRESOLVED_CALL_EXPLORE_BUDGET)
                                })
                                trace_taint_in_function(
                                    high_attempted_func, newly_tainted_callee_hvs_attempt, None, 
                                    current_program, decompiler_ref, println_func, printerr_func, monitor_ref,
                                    current_depth + 1,  
                                    func_manager_ref,
                                    sub_recursion_budget=UNRESOLVED_CALL_EXPLORE_BUDGET, 
                                    current_sub_depth=0 
                                )
                            elif any_tainted_arg_for_attempt: 
                                all_tainted_usages.append({
                                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                    "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                                    "usage_type": "TAINTED_ARG_TO_RESOLVED_CALL_NO_PARAM_MAP",
                                    "details": "Tainted arg to {} to now-resolved {} ({}), but could not map to its parameters.".format(
                                        mnemonic, attempted_func_obj.getName(), exploration_context_msg)
                                })
                        else: 
                            log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, "(decompilation failed for resolved function at {} ({}) for {})".format(potential_target_addr_to_explore, exploration_context_msg, mnemonic))
                    else: 
                        log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, "(function object not found at derived target address {} ({}) for {})".format(potential_target_addr_to_explore, exploration_context_msg, mnemonic))
                
                else: # No potential_target_addr_to_explore or other conditions not met for exploration
                    reason_for_no_explore = ""
                    pcode_target_repr = get_varnode_representation(target_func_addr_vn, high_func_to_analyze, current_program)
                    if not potential_target_addr_to_explore : 
                        if target_func_addr_vn.isConstant(): reason_for_no_explore = "(PCode target is const {} but could not be converted to address)".format(pcode_target_repr)
                        elif target_func_addr_vn.isAddress() and target_func_addr_vn.getAddress().isMemoryAddress(): reason_for_no_explore = "(PCode target is RAM {} but failed to read/resolve pointer)".format(pcode_target_repr)
                        else: reason_for_no_explore = "(PCode target {} for {} is not a resolvable constant or RAM location)".format(pcode_target_repr, mnemonic)
                    elif not (func_manager_ref and decompiler_ref): reason_for_no_explore = "(managers not available for exploration)"
                    elif not (current_depth < MAX_RECURSION_DEPTH): reason_for_no_explore = "(main recursion depth limit reached for exploration)"
                    else: reason_for_no_explore = "(unknown reason for no exploration of {}, PCode target was {})".format(mnemonic, pcode_target_repr) 
                    
                    log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, reason_for_no_explore)

        # --- TAINT PROPAGATION ---
        if output_hv and output_hv not in tainted_high_vars_in_current_func:
            is_newly_tainted = False
            source_of_taint_repr = "N/A"
            
            unary_like_propagation_ops = ["COPY", "CAST", "INT_NEGATE", "INT_2COMP", "POPCOUNT", "INT_ZEXT", "INT_SEXT", "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND", "INT2FLOAT", "FLOAT2INT", "BOOL_NEGATE"]
            multi_input_propagation_ops = ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "MULTIEQUAL", "PIECE", "SUBPIECE"]
            load_op = "LOAD"

            inputs_to_check = []
            if mnemonic == load_op and current_pcode_op.getNumInputs() > 1:
                inputs_to_check.append(current_pcode_op.getInput(1)) # LOAD source is input 1 (pointer)
            elif mnemonic in unary_like_propagation_ops and current_pcode_op.getNumInputs() > 0:
                inputs_to_check.append(current_pcode_op.getInput(0))
            elif mnemonic in multi_input_propagation_ops:
                if mnemonic == "SUBPIECE" and current_pcode_op.getNumInputs() > 0: # SUBPIECE only taints from its first input
                    inputs_to_check.append(current_pcode_op.getInput(0))
                else:
                    for i in range(current_pcode_op.getNumInputs()):
                        inputs_to_check.append(current_pcode_op.getInput(i))
            
            for input_vn in inputs_to_check:
                if input_vn:
                    input_hv = input_vn.getHigh()
                    if input_hv and input_hv in tainted_high_vars_in_current_func:
                        is_newly_tainted = True
                        source_of_taint_repr = get_varnode_representation(input_hv, high_func_to_analyze, current_program)
                        tainted_high_vars_in_current_func.add(output_hv)
                        println_func("DEBUG: [{} @ {}] Taint propagated from {} ({}) to {} ({}) via {}.".format(
                            func_name, current_op_address_str,
                            source_of_taint_repr, get_varnode_representation(input_vn, high_func_to_analyze, current_program), # Show full input_vn repr
                            get_varnode_representation(output_hv, high_func_to_analyze, current_program), get_varnode_representation(output_vn, high_func_to_analyze, current_program), # Show full output_vn repr
                            mnemonic
                        ))
                        break 
            
            if is_newly_tainted:
                if output_hv in current_func_input_param_hvs and output_hv not in initial_tainted_hvs:
                    details_param_term = "Taint propagated to input parameter {} of function {}.".format(
                        get_varnode_representation(output_hv, high_func_to_analyze, current_program), func_name
                    )
                    calling_functions_info = []
                    function_being_analyzed = high_func_to_analyze.getFunction()
                    if func_manager_ref: 
                        references_to_function = current_program.getReferenceManager().getReferencesTo(function_being_analyzed.getEntryPoint())
                        for ref in references_to_function:
                            if ref.getReferenceType().isCall():
                                caller_func = func_manager_ref.getFunctionContaining(ref.getFromAddress())
                                if caller_func:
                                    calling_functions_info.append("{} at {}".format(caller_func.getName(), caller_func.getEntryPoint().toString()))
                    if calling_functions_info:
                        details_param_term += " Called by: [{}].".format(", ".join(calling_functions_info))
                    else:
                        details_param_term += " No direct callers found in program."

                    all_tainted_usages.append({
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                        "usage_type": "TAINT_REACHED_INPUT_PARAMETER_TERMINATION",
                        "tainted_component_repr": get_varnode_representation(output_hv, high_func_to_analyze, current_program),
                        "details": details_param_term
                    })
                    println_func("INFO: [{} @ {}] {}. Analysis path terminated.".format(
                        func_name, current_op_address_str, details_param_term
                    ))
                    return 

    println_func("<<< Finished analyzing function: {}. Final tainted HighVariables in this scope: {}".format(
        func_name, ", ".join([get_varnode_representation(hv, high_func_to_analyze, current_program) for hv in tainted_high_vars_in_current_func]) if tainted_high_vars_in_current_func else "None"
    ))

# Helper function to avoid code duplication for logging TAINTED_ARG_TO_UNRESOLVED_CALL
def log_unresolved_call_with_tainted_args(pcode_op, current_high_func, prog, tainted_hvs_from_caller, current_func_name, current_func_entry_addr_obj, op_addr_obj, println_func, context_msg=""):
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
                "function_name": current_func_name, 
                "function_entry": current_func_entry_addr_obj.toString(),
                "address": op_addr_obj.toString(), 
                "pcode_op_str": str(pcode_op),
                "usage_type": "TAINTED_ARG_TO_UNRESOLVED_CALL",
                "tainted_component_repr": get_varnode_representation(arg_vn, current_high_func, prog),
                "details": details_str.strip()
            })
            println_func("WARN: [{} @ {}] {}. Cannot recurse or explore further on this specific path for this argument.".format(
                current_func_name, 
                op_addr_obj.toString(), 
                details_str.strip()
            ))
            break

# -------------------
# Main script logic
# -------------------
println("DEBUG: Interprocedural Value Taint Tracking Script Starting...")

decompiler = None
# Ensure Ghidra globals are available (moved outside try-finally for decompiler for clarity)
try:
    # These are Ghidra's built-in functions/globals when run in Script Manager
    if 'currentProgram' not in globals() or currentProgram is None:
        try:
            from __main__ import currentProgram, askAddress, println, printerr, monitor, askString
        except ImportError:
             print("Error: Essential Ghidra variables (currentProgram, etc.) not defined. Please run from Ghidra Script Manager.")
             raise SystemExit() # Exit if essential Ghidra context is missing

except NameError: # Fallback for environments where these might not be pre-defined as globals and __main__ trick is needed
    try:
        from __main__ import currentProgram, askAddress, println, printerr, monitor, askString, getFunctionManager
        if currentProgram is None: raise ImportError("currentProgram is None after import")
    except ImportError:
        print("FATAL: Essential Ghidra variables (currentProgram, etc.) not defined via __main__. Please run from Ghidra Script Manager.")
        raise SystemExit()

try:
    # Reset global state for each run
    all_tainted_usages = []
    visited_function_states = set()

    parent_func_addr_input = askAddress("Initial Function Start", "Enter address of the function where analysis begins:")
    call_site_addr_input = askAddress("Initial Call Site (Optional)", 
                                      "Enter address of a CALL instruction. The script will attempt to taint the variable associated with its last P-code input (often the output or a modified reference). Leave blank if tainting a parameter/other local directly by name.")

    if parent_func_addr_input is None:
        printerr("User cancelled or provided invalid initial function address. Script terminated.")
        # Consider raising SystemExit here if appropriate in Ghidra scripting
    else:
        output_slot_local_var_name_hint = None # Initialize to None

        if call_site_addr_input:
            # Call site is provided. We will try to auto-detect the taint source.
            # output_slot_local_var_name_hint remains None for auto-detection.
            println("DEBUG: Call site {} provided. Will attempt to auto-detect taint source from its last P-code input/output slot.".format(call_site_addr_input))
        else:
            # No call site provided, so we MUST ask for a variable name hint.
            output_slot_local_var_name_hint_str = askString("Tainted Variable Name Hint", 
                                                        "Enter name of the variable (e.g., local_68, or a parameter name) that is initially tainted.")
            if output_slot_local_var_name_hint_str: # User provided a name
                output_slot_local_var_name_hint = output_slot_local_var_name_hint_str.strip()
                if not output_slot_local_var_name_hint: # If it was just whitespace
                     output_slot_local_var_name_hint = None # Treat as not provided
            # If user provided nothing or cancelled, output_slot_local_var_name_hint remains None

        func_manager = currentProgram.getFunctionManager()

        decompiler = DecompInterface()
        options = DecompileOptions()
        # Configure options as needed, e.g., for better analysis or specific processor
        # options.setรอบDeclaredData(True) # Example option
        decompiler.setOptions(options)

        if not decompiler.openProgram(currentProgram):
            printerr("Failed to open program with decompiler. Script terminated.")
            decompiler = None # Ensure it's None if failed
            raise SystemExit()

        initial_function_obj = func_manager.getFunctionContaining(parent_func_addr_input)
        if initial_function_obj is None or not initial_function_obj.getEntryPoint().equals(parent_func_addr_input):
            initial_function_obj = func_manager.getFunctionAt(parent_func_addr_input)

        if initial_function_obj is None:
            printerr("Initial function not found at address: {}.".format(parent_func_addr_input))
        else:
            println("DEBUG: Initial Function to analyze: {} at {}".format(initial_function_obj.getName(), initial_function_obj.getEntryPoint()))
            
            decompile_results_initial = decompiler.decompileFunction(initial_function_obj, 60, monitor)
            if not decompile_results_initial or decompile_results_initial.getHighFunction() is None:
                printerr("Failed to decompile initial function: {}. Script terminated.".format(initial_function_obj.getName()))
            else:
                high_initial_function = decompile_results_initial.getHighFunction()
                initial_taint_source_hv_set = set()
                start_pcode_op_for_trace = None 

                if call_site_addr_input:
                    # output_slot_local_var_name_hint is None, find_highlocal_for_output_slot will try to work without a name.
                    println("DEBUG: Initial taint source is related to call at {} (attempting auto-detection from last P-code input/output slot).".format(call_site_addr_input))
                    V_addr_of_output_ptr_var, call_site_pcode_op_initial = get_initial_taint_source(
                        high_initial_function, call_site_addr_input, printerr, println
                    )
                    if V_addr_of_output_ptr_var and call_site_pcode_op_initial:
                        # Pass the None hint to find_highlocal_for_output_slot
                        H_output_var = find_highlocal_for_output_slot(high_initial_function, V_addr_of_output_ptr_var, output_slot_local_var_name_hint, println, currentProgram)
                        if H_output_var:
                            initial_taint_source_hv_set.add(H_output_var)
                            start_pcode_op_for_trace = call_site_pcode_op_initial 
                            println("DEBUG: Initial taint source (from call site, auto-detected): {}. Analysis will start after PCodeOp {} @ {}.".format(
                                get_varnode_representation(H_output_var, high_initial_function, currentProgram),
                                start_pcode_op_for_trace, start_pcode_op_for_trace.getSeqnum().getTarget()
                                ))
                        else:
                            printerr("ERROR: Could not automatically determine HighLocal from call site {} (V_ref was {}). Cannot set initial taint.".format(
                                call_site_addr_input,
                                get_varnode_representation(V_addr_of_output_ptr_var, high_initial_function, currentProgram) if V_addr_of_output_ptr_var else "None"
                            ))
                    else:
                        printerr("ERROR: Could not identify reference parameter or PCodeOp for call site {}. Cannot set initial taint.".format(call_site_addr_input))
                
                elif output_slot_local_var_name_hint: # No call site, but a name hint was provided
                    println("DEBUG: Initial taint source is named variable/parameter '{}' in {}.".format(output_slot_local_var_name_hint, initial_function_obj.getName()))
                    found_var_hv = None
                    lsm = high_initial_function.getLocalSymbolMap()
                    if lsm: 
                        symbols_iter = lsm.getSymbols()
                        while symbols_iter.hasNext():
                            symbol = symbols_iter.next()
                            if symbol and symbol.getName() == output_slot_local_var_name_hint:
                                hv = symbol.getHighVariable()
                                if hv: # Could be HighLocal or HighParam
                                    found_var_hv = hv
                                    break
                    if found_var_hv:
                        initial_taint_source_hv_set.add(found_var_hv)
                        # start_pcode_op_for_trace remains None, so analysis starts from function beginning
                        println("DEBUG: Initial taint source (direct variable): {}. Analysis will start from beginning of function.".format(
                            get_varnode_representation(found_var_hv, high_initial_function, currentProgram)))
                    else:
                        printerr("ERROR: Could not find variable/parameter named '{}' in function {} to set as initial taint source.".format(output_slot_local_var_name_hint, initial_function_obj.getName()))
                else: # Neither call site, nor a name hint if call site wasn't given
                    printerr("ERROR: No valid initial taint source specified. Please provide a call site for auto-detection or a direct variable name. Analysis cannot start.")

                if initial_taint_source_hv_set:
                    println("\n--- Initiating Taint Analysis ---")
                    trace_taint_in_function(
                        high_initial_function,
                        initial_taint_source_hv_set,
                        start_pcode_op_for_trace, # Can be None
                        currentProgram,
                        decompiler, 
                        println, printerr, monitor, # Pass monitor here
                        current_depth=0,
                        func_manager_ref=func_manager
                    )
                    
                    println("\n--- Taint Analysis Complete ---")
                    if all_tainted_usages:
                        print_tainted_value_usage_results(all_tainted_usages, println, is_global_print=True)
                    else:
                        println("No tainted value usages detected across the analyzed functions.")
                else:
                    println("No initial taint source could be established. Analysis not started.")

except Exception as e:
    import traceback
    import sys
    # Using os might not be necessary if we rely on Ghidra's println/printerr for output.
    # import os 

    # Define default print functions for safety if Ghidra's are not available
    # (though the checks at the start should ideally handle this)
    def _safe_printerr(msg):
        sys.stderr.write(str(msg) + "\n")
    def _safe_println(msg):
        sys.stdout.write(str(msg) + "\n")

    # Use Ghidra's printerr/println if available, otherwise fall back to safe versions
    # This is somewhat redundant due to earlier checks but provides a last-resort fallback.
    _effective_printerr = globals().get('printerr', _safe_printerr)
    _effective_println = globals().get('println', _safe_println)

    _effective_printerr("An unhandled error occurred during script execution:")
    _effective_printerr(str(e))

    try:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        # traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr) 
        # Instead of printing directly to sys.stderr, use Ghidra's printerr if possible
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for line in tb_lines:
            _effective_printerr(line.rstrip()) # rstrip to remove double newlines
        _effective_println("Detailed traceback printed to error log.")

    except Exception as te_print:
        _effective_printerr("Error trying to print traceback: {}".format(str(te_print)))

finally:
    if 'decompiler' in locals() and decompiler is not None:
        decompiler.dispose()
        # Check for println availability before using it in finally block
        if 'println' in globals(): 
            println("DEBUG: Decompiler disposed.")
        else:
            print("DEBUG: Decompiler disposed. (println not available)")

# Final script finished message
if 'println' in globals():
    println("DEBUG: Interprocedural Value Taint Tracking Script Finished.")
else:
    print("DEBUG: Interprocedural Value Taint Tracking Script Finished (println not available).") 