# ARMv8TaintTracer_Combined_Sourcing_V2.py
# MODIFIED FOR VALUE TAINT TRACKING
# VERSION: Combined Taint Sourcing with Corrected P-code Mnemonics

# Import necessary Ghidra modules
from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable
from ghidra.program.model.listing import Function, Instruction, VariableStorage
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions

# -------------------
# Global Helper Functions (get_varnode_representation, print_results_func, find_highlocal remain same)
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
        if isinstance(varnode_obj, HighVariable):
            actual_high_var_target = varnode_obj
        else:
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
        return "unique_vn:{} (size {})".format(varnode_obj.getOffset(), varnode_obj.getSize())
    return varnode_obj.toString()


def print_tainted_value_usage_results(results_list, println_func):
    if not results_list:
        println_func("\nNo specific usages (CALL args, STOREs, CBRANCH conditions, RETURNs) of the tainted value found within the function.")
        return
    println_func("\n--- Detected Tainted Value Usages ---")
    for i, res in enumerate(results_list):
        println_func("Usage #{}:".format(i + 1))
        println_func("  Instruction Address: {}".format(res["address"]))
        println_func("    PCode Op:            {}".format(res["pcode_op_str"]))
        println_func("    Usage Type:          {}".format(res["usage_type"]))
        if "tainted_component_repr" in res:
             println_func("    Tainted Component:   {}".format(res["tainted_component_repr"]))
        if "destination_repr" in res:
             println_func("    Destination Address: {}".format(res["destination_repr"]))
        if "details" in res:
             println_func("    Details:             {}".format(res["details"]))
        println_func("-" * 40)

def find_highlocal_for_output_slot(high_func, V_ref_to_output_slot, local_var_name_hint, println, current_program):
    println("DEBUG: Locating HighLocal for output variable (e.g., 'local_68' or 'local_74'), reference param is V_ref_to_output_slot (e.g., '&local_var'): {}".format(get_varnode_representation(V_ref_to_output_slot, high_func, current_program)))

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
        println("DEBUG: Could not find HighLocal by name '{}'. Further P-code analysis for SP-relativity might be needed but is complex.".format(local_var_name_hint))

    vn_to_trace = V_ref_to_output_slot
    def_op = vn_to_trace.getDef()

    if def_op and (def_op.getMnemonic() == "PTRADD" or def_op.getMnemonic() == "PTRSUB" or def_op.getMnemonic() == "INT_ADD" or def_op.getMnemonic() == "INT_SUB"):
        base_reg_vn = def_op.getInput(0)
        offset_vn = def_op.getInput(1)
        sp_reg = current_program.getRegister("SP")
        if base_reg_vn.isRegister() and sp_reg and base_reg_vn.getAddress().equals(sp_reg.getAddress()) and offset_vn.isConstant():
            println("DEBUG: V_ref_to_output_slot {} is SP-relative: {} {} {}. Mapping this to a specific HighLocal requires deeper analysis of stack frame layout.".format(
                get_varnode_representation(vn_to_trace, high_func, current_program),
                get_varnode_representation(base_reg_vn, high_func, current_program),
                def_op.getMnemonic(),
                get_varnode_representation(offset_vn, high_func, current_program)
            ))

    println("DEBUG: Could not automatically determine target HighLocal for output variable for {}. Relies heavily on accurate name hint.".format(get_varnode_representation(V_ref_to_output_slot,high_func,current_program)))
    return None
# -------------------
# Main script logic
# -------------------
println("DEBUG: Value Taint Tracking Script Starting (Combined Sourcing, Corrected Mnemonics)...")
decompiler = None

try:
    if 'currentProgram' not in globals() or currentProgram is None:
        print("Error: currentProgram is not defined. Please open a program.")
    elif 'askAddress' not in globals() or 'println' not in globals() or 'printerr' not in globals() or 'monitor' not in globals():
        print("Error: Ghidra global functions not defined. Run in Ghidra's script manager.")
    else:
        parent_func_addr_input = askAddress("Parent Function Start", "Enter address of the function containing the call:")
        call_site_addr_input = askAddress("Call Site Address", "Enter address of the CALL instruction (e.g., to ANC_LIVE_fmp_classify):")
        output_slot_local_var_name = askString("Output Variable Name", "Enter name of the variable (e.g., local_68 or local_74):")

        if parent_func_addr_input is None or call_site_addr_input is None or not output_slot_local_var_name or output_slot_local_var_name.strip() == "":
            printerr("User cancelled or provided invalid input. 'Output Variable Name' is mandatory. Script terminated.")
        else:
            output_slot_local_var_name = output_slot_local_var_name.strip()
            println("DEBUG: Output Variable Name to track: '{}'".format(output_slot_local_var_name))

            func_manager = currentProgram.getFunctionManager()
            listing = currentProgram.getListing()

            decompiler = DecompInterface()
            options = DecompileOptions()
            decompiler.setOptions(options)
            if not decompiler.openProgram(currentProgram):
                printerr("Failed to open program with decompiler. Script terminated.")
                decompiler = None
            else:
                parent_function = func_manager.getFunctionContaining(parent_func_addr_input)
                if parent_function is None or not parent_function.getEntryPoint().equals(parent_func_addr_input):
                    parent_function = func_manager.getFunctionAt(parent_func_addr_input)

                if parent_function is None:
                    printerr("Parent function not found at address: {}.".format(parent_func_addr_input))
                else:
                    decompile_results_for_script = decompiler.decompileFunction(parent_function, 60, monitor)
                    if not decompile_results_for_script or decompile_results_for_script.getHighFunction() is None:
                        printerr("Failed to decompile parent function: {}. Script terminated.".format(parent_function.getName()))
                    else:
                        high_function_for_script = decompile_results_for_script.getHighFunction()

                        println("Parent Function: {} at {}".format(parent_function.getName(), parent_function.getEntryPoint()))
                        println("Call Site Address: {}".format(call_site_addr_input))

                        V_addr_of_output_ptr_var, call_site_pcode_op = get_initial_taint_source(
                            high_function_for_script, call_site_addr_input,
                            printerr, println
                        )

                        if V_addr_of_output_ptr_var is None or call_site_pcode_op is None:
                            printerr("Could not identify the initial reference parameter Varnode (&OutputVar) or call PcodeOp.")
                        else:
                            println("Initial Reference PcodeVarnode (address of/for OutputVar, e.g., &local_var): {}".format(get_varnode_representation(V_addr_of_output_ptr_var, high_function_for_script, currentProgram)))

                            H_output_var = find_highlocal_for_output_slot(high_function_for_script, V_addr_of_output_ptr_var, output_slot_local_var_name, println, currentProgram)

                            if H_output_var is None:
                                printerr("ERROR: Could not find the HighLocal for the output variable '{}'. Taint analysis cannot proceed.".format(output_slot_local_var_name))
                            else:
                                println("DEBUG: Identified HighLocal for Output Variable (named '{}'): {}".format(
                                    output_slot_local_var_name,
                                    get_varnode_representation(H_output_var, high_function_for_script, currentProgram)
                                ))

                                tainted_high_vars = set()
                                an_instance_of_source_value_has_been_loaded = False
                                tainted_value_usages = []

                                op_iter_for_analysis = high_function_for_script.getPcodeOps()
                                encountered_call_site = False

                                for current_pcode_op in op_iter_for_analysis:
                                    current_op_address_str = current_pcode_op.getSeqnum().getTarget().toString()

                                    if not encountered_call_site:
                                        if call_site_pcode_op is not None and current_pcode_op.getSeqnum().equals(call_site_pcode_op.getSeqnum()):
                                            encountered_call_site = True
                                            println("\nDEBUG: Reached call site PcodeOp {} at {}, subsequent ops will be processed for taint.".format(
                                                current_pcode_op, current_op_address_str
                                            ))

                                            if H_output_var:
                                                if H_output_var not in tainted_high_vars:
                                                    tainted_high_vars.add(H_output_var)
                                                    println("DEBUG: <<< INITIAL TAINT SOURCE >>> HighVar {} (named '{}') directly tainted as it is the output variable modified by call at {}.".format(
                                                        get_varnode_representation(H_output_var, high_function_for_script, currentProgram),
                                                        output_slot_local_var_name,
                                                        current_op_address_str
                                                    ))
                                                if not an_instance_of_source_value_has_been_loaded:
                                                    an_instance_of_source_value_has_been_loaded = True
                                                    println("DEBUG: Initial source value (named '{}') is now considered tainted.".format(output_slot_local_var_name))
                                            else:
                                                printerr("ERROR: H_output_var was None at call site, cannot apply initial taint.")
                                        continue

                                    output_vn = current_pcode_op.getOutput()
                                    output_hv = output_vn.getHigh() if output_vn else None
                                    mnemonic = current_pcode_op.getMnemonic()
                                    instr_addr = current_pcode_op.getSeqnum().getTarget()

                                    #println("\n--- Analyzing PCODE OP at {}: {} (Seq: {}) ---".format(instr_addr, mnemonic, current_pcode_op.getSeqnum()))
                                    for i_idx in range(current_pcode_op.getNumInputs()):
                                        i_vn = current_pcode_op.getInput(i_idx)
                                        i_hv = i_vn.getHigh() if i_vn else None
                                        is_i_hv_tainted = (i_hv in tainted_high_vars) if i_hv else False
                                        # println("  Input [{}]: {} (HV: {}) (is_tainted: {})".format(
                                        #     i_idx,
                                        #     get_varnode_representation(i_vn, high_function_for_script, currentProgram),
                                        #     get_varnode_representation(i_hv, high_function_for_script, currentProgram) if i_hv else "None",
                                        #     is_i_hv_tainted
                                        # ))
                                    if output_vn:
                                        o_hv_current_op = output_hv
                                        is_o_hv_tainted = (o_hv_current_op in tainted_high_vars) if o_hv_current_op else False
                                        # println("  Output:    {} (HV: {}) (is_currently_in_taint_set: {})".format(
                                        #     get_varnode_representation(output_vn, high_function_for_script, currentProgram),
                                        #     get_varnode_representation(o_hv_current_op, high_function_for_script, currentProgram) if o_hv_current_op else "None",
                                        #     is_o_hv_tainted
                                        # ))
                                    # else:
                                    #     println("  Output:    None")

                                    if an_instance_of_source_value_has_been_loaded:
                                        if mnemonic in ["CALL", "CALLIND"]:
                                            for i in range(1, current_pcode_op.getNumInputs()):
                                                arg_vn = current_pcode_op.getInput(i)
                                                arg_hv = arg_vn.getHigh() if arg_vn else None
                                                if arg_hv and arg_hv in tainted_high_vars:
                                                    tainted_value_usages.append({
                                                        "address": instr_addr, "pcode_op_str": str(current_pcode_op), "usage_type": "CALL_ARGUMENT",
                                                        "tainted_component_repr": get_varnode_representation(arg_vn, high_function_for_script, currentProgram),
                                                        "details": "Argument #{} to target {}".format(i-1, current_pcode_op.getInput(0).getAddress())
                                                    })
                                        elif mnemonic == "STORE":
                                            stored_value_vn = current_pcode_op.getInput(2)
                                            stored_value_hv = stored_value_vn.getHigh() if stored_value_vn else None
                                            if stored_value_hv and stored_value_hv in tainted_high_vars:
                                                dest_addr_vn = current_pcode_op.getInput(1)
                                                tainted_value_usages.append({
                                                    "address": instr_addr, "pcode_op_str": str(current_pcode_op), "usage_type": "STORE_VALUE",
                                                    "tainted_component_repr": get_varnode_representation(stored_value_vn, high_function_for_script, currentProgram),
                                                    "destination_repr": get_varnode_representation(dest_addr_vn, high_function_for_script, currentProgram)
                                                })
                                        elif mnemonic == "CBRANCH":
                                            condition_vn = current_pcode_op.getInput(1)
                                            condition_hv = condition_vn.getHigh() if condition_vn else None
                                            if condition_hv and condition_hv in tainted_high_vars:
                                                tainted_value_usages.append({
                                                    "address": instr_addr, "pcode_op_str": str(current_pcode_op), "usage_type": "BRANCH_CONDITION",
                                                    "tainted_component_repr": get_varnode_representation(condition_vn, high_function_for_script, currentProgram)
                                                })
                                        elif mnemonic == "RETURN":
                                            if current_pcode_op.getNumInputs() > 1:
                                                returned_value_vn = current_pcode_op.getInput(1)
                                                returned_value_hv = returned_value_vn.getHigh() if returned_value_vn else None
                                                if returned_value_hv and returned_value_hv in tainted_high_vars:
                                                    tainted_value_usages.append({
                                                        "address": instr_addr, "pcode_op_str": str(current_pcode_op), "usage_type": "RETURN_VALUE",
                                                        "tainted_component_repr": get_varnode_representation(returned_value_vn, high_function_for_script, currentProgram)
                                                    })

                                        if output_hv and output_hv not in tainted_high_vars:
                                            is_newly_tainted_by_propagation = False
                                            propagated_by_load = False

                                            if mnemonic == "LOAD":
                                                if current_pcode_op.getNumInputs() > 1:
                                                    address_vn = current_pcode_op.getInput(1)
                                                    address_hv = address_vn.getHigh() if address_vn else None
                                                    if address_hv and address_hv in tainted_high_vars:
                                                        is_newly_tainted_by_propagation = True
                                                        propagated_by_load = True # Mark that LOAD caused this
                                                        println("DEBUG: >>> Propagated taint via LOAD from tainted address {} to output {}.".format(
                                                            get_varnode_representation(address_vn, high_function_for_script, currentProgram),
                                                            get_varnode_representation(output_vn, high_function_for_script, currentProgram)
                                                        ))
                                            # IMPORTANT: Corrected P-code mnemonics for unary float ops based on common Ghidra getMnemonic() outputs
                                            unary_like_propagation_ops = [
                                                "COPY", "CAST", "INT_NEGATE", "INT_2COMP", "POPCOUNT",
                                                "INT_ZEXT", "INT_SEXT",
                                                "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", # These often keep FLOAT_ prefix
                                                "FLOAT2FLOAT",  # Corrected
                                                "TRUNC",        # Corrected
                                                "CEIL",         # Corrected
                                                "FLOOR",        # Corrected
                                                "ROUND",        # Corrected
                                                "INT2FLOAT",    # Corrected
                                                "FLOAT2INT"     # Corrected
                                            ]
                                            binary_like_propagation_ops = [
                                                "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
                                                "INT_AND", "INT_OR", "INT_XOR",
                                                "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
                                                "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
                                                "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
                                                "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", # Arithmetic ops often keep FLOAT_ prefix
                                                "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
                                                "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR",
                                                "MULTIEQUAL"
                                            ]

                                            if not propagated_by_load: # Only check other rules if not already handled by LOAD
                                                if mnemonic in unary_like_propagation_ops:
                                                    if current_pcode_op.getNumInputs() > 0 :
                                                        input_vn_check = current_pcode_op.getInput(0)
                                                        input_hv_check = input_vn_check.getHigh() if input_vn_check else None
                                                        if input_hv_check and input_hv_check in tainted_high_vars:
                                                            is_newly_tainted_by_propagation = True
                                                elif mnemonic == "PIECE":
                                                    for i in range(current_pcode_op.getNumInputs()):
                                                        input_vn_check = current_pcode_op.getInput(i)
                                                        input_hv_check = input_vn_check.getHigh() if input_vn_check else None
                                                        if input_hv_check and input_hv_check in tainted_high_vars:
                                                            is_newly_tainted_by_propagation = True
                                                            break
                                                elif mnemonic == "SUBPIECE":
                                                    input_vn_check = current_pcode_op.getInput(0)
                                                    input_hv_check = input_vn_check.getHigh() if input_vn_check else None
                                                    if input_hv_check and input_hv_check in tainted_high_vars:
                                                        is_newly_tainted_by_propagation = True
                                                elif mnemonic in binary_like_propagation_ops:
                                                    max_inputs_to_check = current_pcode_op.getNumInputs()
                                                    if mnemonic == "BOOL_NEGATE" and max_inputs_to_check > 0:
                                                        max_inputs_to_check = 1
                                                    for i in range(max_inputs_to_check):
                                                        input_vn_check = current_pcode_op.getInput(i)
                                                        input_hv_check = input_vn_check.getHigh() if input_vn_check else None
                                                        if input_hv_check and input_hv_check in tainted_high_vars:
                                                            is_newly_tainted_by_propagation = True
                                                            break
                                            
                                            if is_newly_tainted_by_propagation and not propagated_by_load:
                                                println("DEBUG: >>> Propagated value taint via {} from input(s) to output {}".format(
                                                    mnemonic,
                                                    get_varnode_representation(output_vn, high_function_for_script, currentProgram)
                                                ))

                                            if is_newly_tainted_by_propagation:
                                                 tainted_high_vars.add(output_hv)

                                print_tainted_value_usage_results(tainted_value_usages, println)
                                println("\n--- Final Tainted Value HighVariables ---")
                                if tainted_high_vars:
                                    for thv_idx, thv in enumerate(tainted_high_vars):
                                        println("  Tainted HV #{}: {}".format(thv_idx, get_varnode_representation(thv, high_function_for_script, currentProgram)))
                                else:
                                    println("  No HighVariables ended up holding propagated tainted values.")

except Exception as e:
    import traceback
    if 'printerr' in globals():
        printerr("An unhandled error occurred during script execution:")
        printerr(str(e))
    else:
        print("An unhandled error occurred (printerr not available):")
        print(str(e))

    try:
        import sys
        output_stream = sys.stdout if 'println' in globals() else sys.stderr
        traceback.print_exc(file=output_stream)
        if 'println' in globals() and output_stream == sys.stderr:
            println("Detailed traceback printed to stderr (see console if Ghidra captures it).")
        elif 'println' not in globals():
             print("Detailed traceback printed to stderr.")
    except Exception as te:
        error_message = "Error trying to print traceback: {}".format(str(te))
        if 'println' in globals():
            println(error_message)
        else:
            print(error_message)

finally:
    if 'decompiler' in locals() and decompiler is not None:
        decompiler.dispose()
        if 'println' in globals():
            println("DEBUG: Decompiler disposed.")

if 'println' in globals():
    println("DEBUG: Value Taint Tracking Script Finished (Combined Sourcing, Corrected Mnemonics).")
else:
    print("DEBUG: Value Taint Tracking Script Finished (Combined Sourcing, Corrected Mnemonics, println not available).")