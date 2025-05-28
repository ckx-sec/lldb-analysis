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
    println("DEBUG: Locating HighLocal for output variable (e.g., 'local_68'), reference param is V_ref_to_output_slot (e.g., '&local_var'): {}".format(get_varnode_representation(V_ref_to_output_slot, high_func, current_program)))

    if local_var_name_hint:
        lsm = high_func.getLocalSymbolMap()
        # getSymbols() returns an Iterator in Java, not a list.
        symbols_iter = lsm.getSymbols()
        while symbols_iter.hasNext():
            symbol = symbols_iter.next()
            if symbol and symbol.getName() == local_var_name_hint:
                hv = symbol.getHighVariable()
                if hv and isinstance(hv, ghidra.program.model.pcode.HighLocal):
                    println("DEBUG: Found HighLocal '{}' by provided name for output variable.".format(local_var_name_hint))
                    return hv
        println("DEBUG: Could not find HighLocal by name '{}'. Will attempt to find via V_ref_to_output_slot's HighVariable.".format(local_var_name_hint))

    v_ref_high = V_ref_to_output_slot.getHigh()
    if v_ref_high and isinstance(v_ref_high, ghidra.program.model.pcode.HighLocal):
        println("DEBUG: Directly found HighLocal for V_ref_to_output_slot: {}".format(get_varnode_representation(v_ref_high, high_func, current_program)))
        return v_ref_high

    def_op = V_ref_to_output_slot.getDef()
    if def_op:
        if (def_op.getMnemonic() == "PTRADD" or def_op.getMnemonic() == "PTRSUB" or def_op.getMnemonic() == "INT_ADD" or def_op.getMnemonic() == "INT_SUB"):
            base_reg_vn = def_op.getInput(0)
            offset_vn = def_op.getInput(1)
            sp_reg = current_program.getRegister("SP")
            if base_reg_vn.isRegister() and sp_reg and base_reg_vn.getAddress().equals(sp_reg.getAddress()) and offset_vn.isConstant():
                println("DEBUG: V_ref_to_output_slot {} is SP-relative: {} {} {}. Mapping this to a specific HighLocal for tainting typically relies on the name hint or subsequent LOAD/STORE analysis on this address.".format(
                    get_varnode_representation(V_ref_to_output_slot, high_func, current_program),
                    get_varnode_representation(base_reg_vn, high_func, current_program),
                    def_op.getMnemonic(),
                    get_varnode_representation(offset_vn, high_func, current_program)
                ))

    println("DEBUG: Could not automatically determine target HighLocal for output variable for {}. Relies heavily on accurate name hint or direct HighVariable mapping of V_ref_to_output_slot.".format(get_varnode_representation(V_ref_to_output_slot,high_func,current_program)))
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
            # Resolve called function
            called_function_obj = None
            target_func_addr_vn = current_pcode_op.getInput(0)
            if mnemonic == "CALL" and target_func_addr_vn.isConstant():
                called_func_address = current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                if called_func_address:
                    called_function_obj = func_manager_ref.getFunctionAt(called_func_address)
            elif mnemonic == "CALLIND": # More complex, could be dynamic
                # Try to get the function if Ghidra resolved it (e.g., from a register that was set)
                # This is a simplification; robust CALLIND resolution is hard.
                ref_iter = current_program.getReferenceManager().getReferencesFrom(current_op_address, 0) # Check reference from instruction for call op index 0
                for ref in ref_iter:
                    if ref.getReferenceType().isCall():
                        called_function_obj = func_manager_ref.getFunctionAt(ref.getToAddress())
                        if called_function_obj: break
            
            if called_function_obj:
                high_called_func = None
                try:
                    decompile_res_callee = decompiler_ref.decompileFunction(called_function_obj, 60, monitor_ref)
                    if decompile_res_callee and decompile_res_callee.getHighFunction():
                        high_called_func = decompile_res_callee.getHighFunction()
                except Exception as de:
                    printerr_func("ERROR: Failed to decompile callee {}: {}".format(called_function_obj.getName(), de))

                if high_called_func:
                    newly_tainted_params_for_callee = set()
                    callee_param_hvs = []
                    lsm_callee = high_called_func.getLocalSymbolMap()
                    if lsm_callee:
                        sym_iter_callee = lsm_callee.getSymbols()
                        while sym_iter_callee.hasNext():
                            sym_c = sym_iter_callee.next()
                            if sym_c.isParameter():
                                hv_c = sym_c.getHighVariable()
                                if hv_c: callee_param_hvs.append(hv_c)

                    # Match arguments to parameters (simplified)
                    # PCode arguments (inputs 1 onwards) need to be mapped to function parameters.
                    # This mapping can be complex due to calling conventions.
                    # Here, we try a positional mapping, which is often incorrect but a starting point.
                    num_pcode_args = current_pcode_op.getNumInputs() - 1
                    
                    for arg_idx_pcode in range(1, current_pcode_op.getNumInputs()): # PCode input index (1-based for args)
                        arg_vn = current_pcode_op.getInput(arg_idx_pcode)
                        arg_hv = arg_vn.getHigh() if arg_vn else None
                        if arg_hv and arg_hv in tainted_high_vars_in_current_func:
                            # Try to map this arg_idx_pcode to a callee_param_hv
                            # This is where robust mapping is needed. For now, assume param_idx = arg_idx_pcode - 1
                            param_idx_conceptual = arg_idx_pcode - 1 
                            if 0 <= param_idx_conceptual < len(callee_param_hvs):
                                callee_param_to_taint = callee_param_hvs[param_idx_conceptual]
                                newly_tainted_params_for_callee.add(callee_param_to_taint)
                                println_func("INFO: [{} @ {}] Tainted argument {} (value: {}) for CALL to {}. Mapped to callee param {}.".format(
                                    func_name, current_op_address_str,
                                    arg_idx_pcode -1, # 0-indexed argument
                                    get_varnode_representation(arg_vn, high_func_to_analyze, current_program),
                                    called_function_obj.getName(),
                                    get_varnode_representation(callee_param_to_taint, high_called_func, current_program)
                                ))
                            else:
                                println_func("WARN: [{} @ {}] Tainted argument {} (PCode input #{}) for CALL to {} could not be mapped to a callee parameter by simple index.".format(
                                     func_name, current_op_address_str, arg_idx_pcode -1, arg_idx_pcode, called_function_obj.getName()
                                ))
                    
                    if newly_tainted_params_for_callee:
                        all_tainted_usages.append({
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_RECURSION",
                            "details": "Recursive call to {} due to tainted args: {}.".format(
                                called_function_obj.getName(), ", ".join([get_varnode_representation(h, high_called_func, current_program) for h in newly_tainted_params_for_callee]))
                        })
                        trace_taint_in_function(
                            high_called_func, newly_tainted_params_for_callee, None, 
                            current_program, decompiler_ref, println_func, printerr_func, monitor_ref,
                            current_depth + 1, func_manager_ref,
                            sub_recursion_budget=sub_recursion_budget, # Pass along current budget
                            current_sub_depth=current_sub_depth + 1 if sub_recursion_budget is not None else 0 # Increment if budget active
                        )
            else: # Could not resolve called function object initially (called_function_obj is None)
                target_is_constant_address = False
                actual_target_address = None
                if target_func_addr_vn.isConstant():
                    try:
                        actual_target_address = current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                        target_is_constant_address = True if actual_target_address else False
                    except Exception as addr_ex:
                        printerr_func("WARN: Could not convert target_func_addr_vn offset {} to address: {}".format(target_func_addr_vn.getOffset(), addr_ex))
                        target_is_constant_address = False

                if target_is_constant_address and func_manager_ref and decompiler_ref and (current_depth < MAX_RECURSION_DEPTH): # Check main depth before attempting explore
                    println_func("INFO: [{} @ {}] Target {} initially unresolved. Attempting to explicitly resolve and analyze with budget {}.".format(
                        func_name, current_op_address_str, actual_target_address, UNRESOLVED_CALL_EXPLORE_BUDGET)) 
                    
                    attempted_func_obj = func_manager_ref.getFunctionAt(actual_target_address)
                    if attempted_func_obj:
                        high_attempted_func = None
                        try:
                            decompile_res_attempt = decompiler_ref.decompileFunction(attempted_func_obj, 60, monitor_ref)
                            if decompile_res_attempt and decompile_res_attempt.getHighFunction():
                                high_attempted_func = decompile_res_attempt.getHighFunction()
                        except Exception as de_attempt:
                            printerr_func("ERROR: Decompiling explicitly resolved function {} failed: {}".format(attempted_func_obj.getName(), de_attempt))

                        if high_attempted_func:
                            println_func("INFO: Successfully decompiled initially unresolved target {} at {}.".format(attempted_func_obj.getName(), actual_target_address))
                            newly_tainted_params_for_attempt = set()
                            callee_param_hvs_attempt = []
                            lsm_callee_attempt = high_attempted_func.getLocalSymbolMap()
                            if lsm_callee_attempt:
                                sym_iter_callee_attempt = lsm_callee_attempt.getSymbols()
                                while sym_iter_callee_attempt.hasNext():
                                    sym_c_att = sym_iter_callee_attempt.next()
                                    if sym_c_att.isParameter():
                                        hv_c_att = sym_c_att.getHighVariable()
                                        if hv_c_att: callee_param_hvs_attempt.append(hv_c_att)
                            
                            any_tainted_arg_for_attempt = False
                            for arg_idx_pcode_attempt in range(1, current_pcode_op.getNumInputs()):
                                arg_vn_attempt = current_pcode_op.getInput(arg_idx_pcode_attempt)
                                arg_hv_attempt = arg_vn_attempt.getHigh() if arg_vn_attempt else None
                                if arg_hv_attempt and arg_hv_attempt in tainted_high_vars_in_current_func:
                                    any_tainted_arg_for_attempt = True
                                    param_idx_conceptual_attempt = arg_idx_pcode_attempt - 1
                                    if 0 <= param_idx_conceptual_attempt < len(callee_param_hvs_attempt):
                                        callee_param_to_taint_attempt = callee_param_hvs_attempt[param_idx_conceptual_attempt]
                                        newly_tainted_params_for_attempt.add(callee_param_to_taint_attempt)
                                        println_func("INFO: Mapping tainted arg #{} to param {} of {}".format(
                                            param_idx_conceptual_attempt, 
                                            get_varnode_representation(callee_param_to_taint_attempt, high_attempted_func, current_program),
                                            attempted_func_obj.getName()))
                                    else:
                                        println_func("WARN: Could not map tainted arg #{} to a param in {}".format(param_idx_conceptual_attempt, attempted_func_obj.getName()))
                            
                            if newly_tainted_params_for_attempt:
                                all_tainted_usages.append({
                                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                    "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                                    "usage_type": "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
                                    "details": "Exploring call to now-resolved {} with tainted params: {}. Budget: {} levels.".format(
                                        attempted_func_obj.getName(), 
                                        ", ".join([get_varnode_representation(h, high_attempted_func, current_program) for h in newly_tainted_params_for_attempt]),
                                        UNRESOLVED_CALL_EXPLORE_BUDGET)
                                })
                                trace_taint_in_function(
                                    high_attempted_func, newly_tainted_params_for_attempt, None, 
                                    current_program, decompiler_ref, println_func, printerr_func, monitor_ref,
                                    current_depth + 1,  # Main depth still increments
                                    func_manager_ref,
                                    sub_recursion_budget=UNRESOLVED_CALL_EXPLORE_BUDGET, # Start new budget
                                    current_sub_depth=0 # Reset sub-depth for this new budgeted path
                                )
                            elif any_tainted_arg_for_attempt:
                                all_tainted_usages.append({
                                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                    "address": current_op_address.toString(), "pcode_op_str": str(current_pcode_op),
                                    "usage_type": "TAINTED_ARG_TO_RESOLVED_CALL_NO_PARAM_MAP",
                                    "details": "Tainted arg to call to now-resolved {}, but could not map to its parameters.".format(attempted_func_obj.getName())
                                })
                        else: # Decompilation of attempted_func_obj failed
                            log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, "(decompilation failed for resolved function)")
                    else: # func_manager_ref.getFunctionAt(actual_target_address) returned None
                        log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, current_program, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, println_func, "(function object not found at target address)")
                else: # Target not constant or managers not available, or main depth already too high for exploration
                    reason_for_no_explore = ""
                    if not target_is_constant_address : reason_for_no_explore = "(target address not constant)"
                    elif not (func_manager_ref and decompiler_ref): reason_for_no_explore = "(managers not available)"
                    elif not (current_depth < MAX_RECURSION_DEPTH): reason_for_no_explore = "(main recursion depth limit reached)"
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
                inputs_to_check.append(current_pcode_op.getInput(1))
            elif mnemonic in unary_like_propagation_ops and current_pcode_op.getNumInputs() > 0:
                inputs_to_check.append(current_pcode_op.getInput(0))
            elif mnemonic in multi_input_propagation_ops:
                if mnemonic == "SUBPIECE" and current_pcode_op.getNumInputs() > 0:
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
                            source_of_taint_repr, input_vn, 
                            get_varnode_representation(output_hv, high_func_to_analyze, current_program), output_vn,
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
    call_site_addr_input = askAddress("Initial Call Site (Optional)", "Enter address of a CALL instruction whose output is the initial taint source (or leave blank if tainting a parameter/other local):")
    output_slot_local_var_name_hint = askString("Tainted Variable Name Hint", "Enter name of the variable (e.g., local_68, or a parameter name) that is initially tainted. If call site provided, this is the output var.")

    if parent_func_addr_input is None:
        printerr("User cancelled or provided invalid initial function address. Script terminated.")
    else:
        output_slot_local_var_name_hint = output_slot_local_var_name_hint.strip() if output_slot_local_var_name_hint else None

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
                start_pcode_op_for_trace = None # PCodeOp from which to start tracing in the initial function

                if call_site_addr_input and output_slot_local_var_name_hint:
                    println("DEBUG: Initial taint source is output of call at {} (variable hint: '{}').".format(call_site_addr_input, output_slot_local_var_name_hint))
                    V_addr_of_output_ptr_var, call_site_pcode_op_initial = get_initial_taint_source(
                        high_initial_function, call_site_addr_input, printerr, println
                    )
                    if V_addr_of_output_ptr_var and call_site_pcode_op_initial:
                        H_output_var = find_highlocal_for_output_slot(high_initial_function, V_addr_of_output_ptr_var, output_slot_local_var_name_hint, println, currentProgram)
                        if H_output_var:
                            initial_taint_source_hv_set.add(H_output_var)
                            start_pcode_op_for_trace = call_site_pcode_op_initial # Start tracing after this call
                            println("DEBUG: Initial taint source (from call output): {}. Analysis will start after PCodeOp {} @ {}.".format(
                                get_varnode_representation(H_output_var, high_initial_function, currentProgram),
                                start_pcode_op_for_trace, start_pcode_op_for_trace.getSeqnum().getTarget()
                                ))
                        else:
                            printerr("ERROR: Could not determine HighLocal for output variable '{}' from call site. Cannot set initial taint.".format(output_slot_local_var_name_hint))
                    else:
                        printerr("ERROR: Could not identify reference parameter or PCodeOp for call site {}. Cannot set initial taint.".format(call_site_addr_input))
                
                elif output_slot_local_var_name_hint: # Tainting a named variable (local or parameter) directly
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
                else:
                    printerr("ERROR: No valid initial taint source specified (neither call site output nor direct variable name). Analysis cannot start.")

                if initial_taint_source_hv_set:
                    println("\\n--- Initiating Taint Analysis ---")
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