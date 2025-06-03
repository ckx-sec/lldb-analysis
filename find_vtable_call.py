# Ghidra Python Script - Combined VTable Analyzer
# This script combines functionalities from vcall_offset_find.py and backword_vtable_call.py.
# 1. It first analyzes a user-specified function to find potential "offset1" values
#    from indirect call patterns like *(*(*(BaseRegister + Offset1)) + Offset2)).
# 2. Then, for each unique "offset1" found, it uses it as TARGET_OFFSET_FOR_STR_SEARCH
#    to globally find STR/STUR instructions storing a potential vtable pointer at that offset.
# 3. Finally, it performs inter-procedural backward taint tracing on the stored value (xi)
#    to identify object allocation sites and subsequently scans forward for vtable assignments
#    to report the actual vtable addresses.
# 4. For each indirect call site (CALLIND) identified in step 1, it combines the 'offset2' from that site
#    with the vtable addresses (resolved in step 3 for the corresponding 'offset1')
#    to calculate the address of the concrete function being called.
# 5. Results, including call site, offset1, offset2, vtable base, and target function, are output as JSON.
# @author CombinedScriptUser
# @category Analysis

from ghidra.program.model.listing import Instruction, Function, Parameter, VariableStorage
from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable, PcodeOpAST
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import Reference, ReferenceIterator

import java.lang.Long # For toHexString
import json # For JSON output
# import os # Not strictly needed if askFile provides absolute path

# --- Configuration ---
# TARGET_OFFSET_FOR_STR_SEARCH will be set dynamically from offset1 values
MAX_BACKWARD_TRACE_DEPTH_INTRA = 15
MAX_BACKWARD_TRACE_DEPTH_INTER = 5
ENABLE_DEBUG_PRINTS = True
KNOWN_ALLOCATOR_FUNCTIONS = ["operator.new", "malloc", "_Znwm", "_Znam", "_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t"]
# --- End Configuration ---

# Global store for decompiler interfaces
decompiler_interfaces = {}
# program = getCurrentProgram() # Ghidra global
# monitor = ConsoleTaskMonitor() # Ghidra global, but can be passed

def dprint(s):
    if ENABLE_DEBUG_PRINTS:
        s_str = str(s)
        if not s_str.endswith("\\n"):
             print("[DEBUG] " + s_str)
        else:
             print("[DEBUG] " + s_str.rstrip("\\n"))

# --- Functions from backword_vtable_call.py (START) ---

def get_decompiler(current_prog_ref):
    prog_id = current_prog_ref.getUniqueProgramID()
    if prog_id not in decompiler_interfaces:
        dprint("Initializing decompiler interface for program: %s" % current_prog_ref.getName())
        ifc = DecompInterface()
        options = DecompileOptions()
        # options.grabFromProgram(current_prog_ref) # Ensure options are set
        ifc.setOptions(options)
        ifc.openProgram(current_prog_ref)
        decompiler_interfaces[prog_id] = ifc
    return decompiler_interfaces[prog_id]

def dispose_decompilers():
    global decompiler_interfaces
    for ifc in decompiler_interfaces.values():
        ifc.dispose()
    decompiler_interfaces = {}
    dprint("All decompiler interfaces disposed.")

def get_high_function(func_obj, current_program_ref): # Takes monitor as global
    if func_obj is None: return None
    ifc = get_decompiler(current_program_ref)

    if func_obj.isExternal():
        thunked_func_for_external = func_obj.getThunkedFunction(True)
        if thunked_func_for_external is not None and not thunked_func_for_external.equals(func_obj) and not thunked_func_for_external.isExternal():
            dprint("External function %s in %s is thunk to internal %s in %s. Using thunked." % (
                func_obj.getName(), current_program_ref.getName(),
                thunked_func_for_external.getName(), thunked_func_for_external.getProgram().getName()
            ))
            return get_high_function(thunked_func_for_external, thunked_func_for_external.getProgram())
        if func_obj.getName() in KNOWN_ALLOCATOR_FUNCTIONS:
            dprint("Function %s in program %s is an external allocator. P-code for CALLs to it will be analyzed." % (func_obj.getName(), current_program_ref.getName()))
            return None
        dprint("Function %s in program %s is external and not a thunk to internal or known allocator. No P-code to analyze." % (func_obj.getName(), current_program_ref.getName()))
        return None
        
    if func_obj.isThunk():
        dprint("Function %s in program %s is a thunk. Attempting to get thunked function." % (func_obj.getName(), current_program_ref.getName()))
        thunked_func = func_obj.getThunkedFunction(True) 
        if thunked_func is not None and not thunked_func.equals(func_obj):
            dprint("  Thunk resolves to: %s in program %s" % (thunked_func.getName(), thunked_func.getProgram().getName()))
            return get_high_function(thunked_func, thunked_func.getProgram())
        else:
            dprint("  Could not resolve thunk or thunk to self for %s. Skipping." % func_obj.getName())
            return None
    try:
        timeout_seconds = 60
        decompile_options_from_ifc = ifc.getOptions()
        if decompile_options_from_ifc is not None: # getOptions() might return None if not set
             timeout_seconds = decompile_options_from_ifc.getDefaultTimeout()
        else: # Fallback if getOptions() is None
            temp_options = DecompileOptions()
            # temp_options.grabFromProgram(current_program_ref) # Initialize with program defaults
            timeout_seconds = temp_options.getDefaultTimeout()
            dprint("Warning: Decompiler options (ifc.getOptions()) for %s returned None. Using hardcoded/default timeout of %s seconds." % (current_program_ref.getName(), timeout_seconds))

        results = ifc.decompileFunction(func_obj, timeout_seconds, monitor) # monitor is Ghidra global
        if results is not None and results.getHighFunction() is not None:
            return results.getHighFunction()
        else:
            err_msg = results.getErrorMessage() if results and results.getErrorMessage() else "Decompilation returned no HighFunction."
            print("Warning: Could not decompile function %s in program %s. Reason: %s" % (func_obj.getName(), current_program_ref.getName(), err_msg))
            return None
    except Exception as e:
        print("Exception during decompilation of %s in program %s: %s" % (func_obj.getName(), current_program_ref.getName(), str(e)))
        return None

def get_varnode_representation(varnode_obj, high_function_context, current_program_ref):
    if varnode_obj is None: return "None"
    if high_function_context:
        actual_high_var_target = varnode_obj
        if not isinstance(varnode_obj, HighVariable):
            high_equiv = varnode_obj.getHigh()
            if high_equiv is not None:
                 actual_high_var_target = high_equiv

        if isinstance(actual_high_var_target, HighVariable):
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
                        storage_info_str = reg.getName() if reg else "Register @ %s" % rep_vn.getAddress()
                    elif rep_vn.getAddress() is not None and rep_vn.getAddress().isStackAddress():
                        storage_info_str = "Stack[%#x]" % actual_high_var_target.getStackOffset() if hasattr(actual_high_var_target, 'getStackOffset') else "StackDirect[%s]" % rep_vn.getAddress().toString(True)
                    elif rep_vn.isUnique():
                        storage_info_str = "UniquePcodeStorage"
                    elif rep_vn.isConstant():
                        storage_info_str = "ConstantStorage(%#x)" % rep_vn.getOffset()
                    elif rep_vn.getAddress() is not None and rep_vn.getAddress().isMemoryAddress() and not rep_vn.getAddress().isStackAddress():
                         storage_info_str = "GlobalMem[%s]" % rep_vn.getAddress().toString(True)
                elif str(type(actual_high_var_target)) == "<type \'ghidra.program.model.pcode.HighOther\'>": 
                     storage_info_str = "HighOther"
            if display_name is None : display_name = "UnnamedHighVar"
            if storage_info_str:
                return "%s(%s)" % (display_name, storage_info_str)
            else:
                return "%s (HighVar Repr)" % display_name

    if varnode_obj.isRegister():
        reg = current_program_ref.getLanguage().getRegister(varnode_obj.getAddress(), varnode_obj.getSize())
        return reg.getName() if reg else "reg_vn:%s" % varnode_obj.getAddress()
    if varnode_obj.isConstant():
        return "const_vn:0x%x" % varnode_obj.getOffset()
    if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isStackAddress():
        return "stack_vn_direct:%s" % varnode_obj.getAddress().toString(True)
    if varnode_obj.isUnique():
        def_op = varnode_obj.getDef()
        if def_op:
            return "unique_vn:0x%x(def:%s) (size %s)" % (varnode_obj.getOffset(), def_op.getMnemonic(), varnode_obj.getSize())
        return "unique_vn:0x%x (size %s)" % (varnode_obj.getOffset(), varnode_obj.getSize())
    if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isMemoryAddress():
        return "mem_vn:%s" % varnode_obj.getAddress().toString(True)
    return varnode_obj.toString()

def find_prior_stores_to_stack_location(high_func, target_stack_addr_hv, load_op,
                                        current_intra_depth, max_intra_depth,     
                                        current_inter_depth, max_inter_depth,     
                                        global_visited_interproc_states, 
                                        println_func, current_program_ref):
    store_value_origins = []
    if not (target_stack_addr_hv and target_stack_addr_hv.isStackVariable()):
        return store_value_origins
    target_stack_offset = target_stack_addr_hv.getStackOffset()
    println_func("      Looking for prior STOREs to HighStackVar %s (offset %#x) before LOAD op at %s" % (
        target_stack_addr_hv.getName(), target_stack_offset, load_op.getSeqnum().getTarget()
    ))
    pcode_ops_iterator = high_func.getPcodeOps()
    latest_store_op_to_target = None
    while pcode_ops_iterator.hasNext():
        pcode_op = pcode_ops_iterator.next()
        if pcode_op.getSeqnum().getOrder() >= load_op.getSeqnum().getOrder():
            break
        if pcode_op.getMnemonic() == "STORE":
            store_addr_vn = pcode_op.getInput(1)
            store_addr_hv = store_addr_vn.getHigh()
            if store_addr_hv and store_addr_hv.isStackVariable():
                if store_addr_hv.getStackOffset() == target_stack_offset:
                    is_same_symbol = False
                    if target_stack_addr_hv.getSymbol() and store_addr_hv.getSymbol() and \
                       target_stack_addr_hv.getSymbol().getID() == store_addr_hv.getSymbol().getID():
                        is_same_symbol = True
                    elif target_stack_addr_hv.getName() == store_addr_hv.getName():
                        is_same_symbol = True
                    if is_same_symbol:
                        latest_store_op_to_target = pcode_op
    if latest_store_op_to_target:
        pcode_op = latest_store_op_to_target
        println_func("        Found latest prior STORE to stack location: %s (Seq: %s)" % (pcode_op, pcode_op.getSeqnum().getOrder()))
        value_stored_vn = pcode_op.getInput(2)
        value_stored_repr = get_varnode_representation(value_stored_vn, high_func, current_program_ref)
        println_func("          Value previously STOREd: %s" % value_stored_repr)
        sub_trace_visited_intra = {}
        origins = trace_variable_origin_backward_recursive(
            high_func, value_stored_vn,
            0, max_intra_depth, 
            sub_trace_visited_intra, 
            current_inter_depth, max_inter_depth, global_visited_interproc_states, 
            println_func, current_program_ref, None 
        )
        for origin_item in origins:
            origin_item["details"] = "Value from prior stack STORE of %s. %s" % (value_stored_repr, origin_item.get("details", ""))
            origin_item["source_type"] = origin_item.get("source_type", "UNKNOWN") + "_VIA_STACK_STORE"
        store_value_origins.extend(origins)
    else:
        println_func("        No definitive prior STORE found to HighStackVar %s (offset %#x) before this LOAD." % (
            target_stack_addr_hv.getName(), target_stack_offset
        ))
    return store_value_origins

def trace_variable_origin_backward_recursive(
    high_func, current_vn,
    current_intra_depth, max_intra_depth,
    visited_intra_vns, 
    current_inter_depth, max_inter_depth, 
    global_visited_interproc_states, 
    println_func, current_program_ref,
    original_target_info
    ):
    origins = []
    current_vn_repr = get_varnode_representation(current_vn, high_func, current_program_ref)
    trace_prefix = "  " * (current_inter_depth * 2) + "  " * current_intra_depth + "|- "
    println_func(trace_prefix + "Tracing Varnode (intra): %s (InterDepth: %s, IntraDepth: %s)" % (current_vn_repr, current_inter_depth, current_intra_depth))

    if current_vn in visited_intra_vns and visited_intra_vns[current_vn] <= current_intra_depth:
        println_func(trace_prefix + "Skipping already visited Varnode (intra): %s at same/shallower intra-depth for this leg" % current_vn_repr)
        return origins
    visited_intra_vns[current_vn] = current_intra_depth

    if current_intra_depth >= max_intra_depth:
        println_func(trace_prefix + "Max intra-depth reached for %s" % current_vn_repr)
        def_op_at_max_depth = current_vn.getDef()
        origins.append({
            "address": def_op_at_max_depth.getSeqnum().getTarget().toString() if def_op_at_max_depth else "N/A",
            "pcode_op_str": str(def_op_at_max_depth) if def_op_at_max_depth else "N/A",
            "source_type": "MAX_INTRA_DEPTH_REACHED", "source_value_repr": current_vn_repr,
            "details": "Intra-procedural trace stopped at max depth.", "function_name": high_func.getFunction().getName(),
            "original_target_info": original_target_info
        })
        return origins

    if current_vn.isConstant():
        println_func(trace_prefix + "Source Found: Constant %s" % current_vn_repr)
        origins.append({"address": "N/A", "pcode_op_str": "Constant", "source_type": "CONSTANT",
                       "source_value_repr": current_vn_repr, "function_name": high_func.getFunction().getName(),
                       "original_target_info": original_target_info})
        return origins

    hv = current_vn.getHigh()
    if hv:
        symbol = hv.getSymbol()
        if symbol and symbol.isParameter():
            param_name = symbol.getName()
            param_index = -1
            try:
                func_params = high_func.getFunction().getParameters()
                for i, p_obj in enumerate(func_params):
                    if p_obj.getSymbol() and p_obj.getSymbol().equals(symbol):
                         param_index = p_obj.getOrdinal(); break
                    if param_index == -1 and p_obj.getVariableStorage().contains(current_vn):
                         param_index = p_obj.getOrdinal(); break
                if param_index == -1 and hasattr(symbol, 'getCategoryIndex') and symbol.getCategoryIndex() >=0:
                    param_index = symbol.getCategoryIndex()
            except Exception as e_param:
                println_func(trace_prefix + "  Warning: Error getting parameter ordinal for %s: %s" % (param_name, e_param))
            println_func(trace_prefix + "Source is Function Input Parameter \'%s\' (Ordinal: %s). Signaling for inter-procedural analysis." % (param_name, param_index if param_index != -1 else "Unknown"))
            origins.append({
                "source_type": "_INTERPROC_FUNCTION_INPUT_", 
                "function_object": high_func.getFunction(),
                "param_high_var": hv, 
                "param_varnode_repr": current_vn_repr,
                "param_name": param_name, "param_index": param_index,
                "details": "Parameter \'%s\' of function %s." % (param_name, high_func.getFunction().getName()),
                "function_name": high_func.getFunction().getName(),
                "original_target_info": original_target_info
            })
            return origins

    defining_op = current_vn.getDef()
    if defining_op is None:
        source_type = "INPUT_VARNODE_OR_UNRESOLVED"
        details = "Varnode has no defining P-code op in this function\'s P-code."
        if current_vn.isInput() and not (hv and hv.getSymbol() and hv.getSymbol().isParameter()):
            println_func(trace_prefix + "Hit Direct HighFunction Input Varnode (not a formal parameter symbol). Signaling for inter-procedural analysis.")
            origins.append({
                "source_type": "_INTERPROC_HF_INPUT_", 
                "function_object": high_func.getFunction(),
                "input_varnode": current_vn, "input_varnode_repr": current_vn_repr,
                "details": "Direct HighFunction input in %s." % high_func.getFunction().getName(),
                "function_name": high_func.getFunction().getName(),
                "original_target_info": original_target_info
            })
            return origins
        elif current_vn.isPersistant() or current_vn.isAddrTied():
            source_type = "GLOBAL_OR_PERSISTENT_VAR"
            details = "Varnode may represent a global variable or persistent storage."
        println_func(trace_prefix + "Source Found: %s (%s)" % (source_type, current_vn_repr))
        origins.append({"address": "N/A", "pcode_op_str": "No Defining PCodeOp", "source_type": source_type,
                       "source_value_repr": current_vn_repr, "details": details, "function_name": high_func.getFunction().getName(),
                       "original_target_info": original_target_info})
        return origins

    op_mnemonic = defining_op.getMnemonic()
    op_address_str = defining_op.getSeqnum().getTarget().toString()
    println_func(trace_prefix + "Defined by PCodeOp: %s (%s) at %s" % (op_mnemonic, defining_op, op_address_str))
    source_op_details_base = {"address": op_address_str, "pcode_op_str": str(defining_op), 
                              "source_value_repr": current_vn_repr, "function_name": high_func.getFunction().getName(),
                              "original_target_info": original_target_info}
    next_intra_depth = current_intra_depth + 1

    if op_mnemonic == "LOAD":
        addr_vn = defining_op.getInput(1)
        addr_vn_repr = get_varnode_representation(addr_vn, high_func, current_program_ref)
        println_func(trace_prefix + "  -> Value from LOAD. Tracing address: %s" % addr_vn_repr)
        load_event_origin = dict(source_op_details_base, **{
            "source_type": "LOAD_FROM_MEMORY",
            "details": "Value loaded from address specified by: %s." % addr_vn_repr
        })
        origins.append(load_event_origin)
        origins.extend(trace_variable_origin_backward_recursive(high_func, addr_vn, next_intra_depth, max_intra_depth, 
                                                               visited_intra_vns, current_inter_depth, max_inter_depth, 
                                                               global_visited_interproc_states, println_func, current_program_ref,
                                                               original_target_info))
        addr_hv_for_stack_check = addr_vn.getHigh()
        if addr_hv_for_stack_check and addr_hv_for_stack_check.isStackVariable():
            println_func(trace_prefix + "    LOAD is from HighStackVariable: %s. Attempting to find prior STOREs." % addr_hv_for_stack_check.getName())
            prior_store_value_origins = find_prior_stores_to_stack_location(
                high_func, addr_hv_for_stack_check, defining_op,
                next_intra_depth, max_intra_depth, 
                current_inter_depth, max_inter_depth, global_visited_interproc_states, 
                println_func, current_program_ref)
            if prior_store_value_origins:
                origins.extend(prior_store_value_origins)
                load_event_origin["details"] += " Additionally, specific prior stack STORE(s) found and traced."
    
    elif op_mnemonic == "INDIRECT":
        effect_op_ref_vn = defining_op.getInput(1)
        actual_effect_op = None
        if effect_op_ref_vn.isConstant():
            target_time_or_order = effect_op_ref_vn.getOffset()
            instr_address_of_indirect = defining_op.getSeqnum().getTarget()
            ops_at_instr_addr_iter = high_func.getPcodeOps(instr_address_of_indirect)
            while ops_at_instr_addr_iter.hasNext():
                candidate_op = ops_at_instr_addr_iter.next()
                if candidate_op.getSeqnum().getTime() == target_time_or_order:
                    actual_effect_op = candidate_op; break
        if actual_effect_op:
            actual_effect_op_mnemonic = actual_effect_op.getMnemonic()
            details_indirect = "Value from indirect effect of PCodeOp: %s (%s)" % (actual_effect_op_mnemonic, actual_effect_op)
            if actual_effect_op_mnemonic in ["CALL", "CALLIND"]:
                call_target_vn_repr = get_varnode_representation(actual_effect_op.getInput(0), high_func, current_program_ref)
                modified_vn_stack_info = None
                if current_vn.getAddress() and current_vn.getAddress().isStackAddress():
                    modified_vn_stack_info = {"is_stack": True, "offset": current_vn.getAddress().getOffset(),
                                              "space_name": current_vn.getAddress().getAddressSpace().getName(), "size": current_vn.getSize()}
                elif hv and hv.isStackVariable():
                     modified_vn_stack_info = {"is_stack": True, "offset": hv.getStackOffset(),
                                               "space_name": "stack", "size": hv.getSize()}
                origins.append(dict(source_op_details_base, **{
                    "pcode_op_str": str(actual_effect_op), "address": actual_effect_op.getSeqnum().getTarget().toString(),
                    "source_type": "_INTERPROC_MODIFIED_BY_CALL_EFFECT_", 
                    "call_op_seqnum_str": str(actual_effect_op.getSeqnum()), "modified_vn_info": modified_vn_stack_info,
                    "details": "Modified by indirect effect of call to: %s. (Original var: %s)." % (call_target_vn_repr, current_vn_repr),
                    "original_target_info": original_target_info
                }))
                return origins
            else:
                origins.append(dict(source_op_details_base, **{
                    "pcode_op_str": str(actual_effect_op), "address": actual_effect_op.getSeqnum().getTarget().toString(),
                    "source_type": "COMPLEX_INDIRECT_EFFECT_FROM_%s" % actual_effect_op_mnemonic, "details": details_indirect,
                    "original_target_info": original_target_info
                }))
        else:
            origins.append(dict(source_op_details_base, **{
                "source_type": "UNHANDLED_INDIRECT_EFFECT_RESOLUTION_FAILURE", 
                "details": "Could not resolve PCodeOp for indirect effect (ref_key: %#x at %s)." % (
                    effect_op_ref_vn.getOffset() if effect_op_ref_vn.isConstant() else -1, 
                    defining_op.getSeqnum().getTarget().toString()),
                "original_target_info": original_target_info
            }))

    elif op_mnemonic in ["CALL", "CALLIND"]:
        call_target_vn = defining_op.getInput(0)
        origins.append(dict(source_op_details_base, **{
            "source_type": "FUNCTION_CALL_OUTPUT",
            "details": "Output of call to target: %s" % get_varnode_representation(call_target_vn, high_func, current_program_ref),
            "original_target_info": original_target_info
        }))

    elif op_mnemonic in ["COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT_NEGATE", "INT_2COMP", "BOOL_NEGATE", "POPCOUNT",
                         "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND",
                         "INT2FLOAT", "FLOAT2INT", "SUBPIECE"]:
        input_vn = defining_op.getInput(0)
        if input_vn:
            origins.extend(trace_variable_origin_backward_recursive(high_func, input_vn, next_intra_depth, max_intra_depth,
                                                                   visited_intra_vns, current_inter_depth, max_inter_depth,
                                                                   global_visited_interproc_states, println_func, current_program_ref,
                                                                   original_target_info))
    elif op_mnemonic in ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
                         "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
                         "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
                         "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV",
                         "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_XOR", "BOOL_AND", "BOOL_OR",
                         "MULTIEQUAL", "PIECE", "PTRADD", "PTRSUB"]:
        for i in range(defining_op.getNumInputs()):
            input_vn = defining_op.getInput(i)
            if input_vn:
                 origins.extend(trace_variable_origin_backward_recursive(high_func, input_vn, next_intra_depth, max_intra_depth,
                                                                        visited_intra_vns, current_inter_depth, max_inter_depth,
                                                                        global_visited_interproc_states, println_func, current_program_ref,
                                                                        original_target_info))
    else:
        inputs_repr = [get_varnode_representation(defining_op.getInput(j), high_func, current_program_ref) for j in range(defining_op.getNumInputs())]
        origins.append(dict(source_op_details_base, **{
            "source_type": "UNHANDLED_PCODE_OP",
            "details": "PCodeOp %s is not specifically handled. Inputs: %s" % (op_mnemonic, inputs_repr),
            "original_target_info": original_target_info
        }))

    if op_mnemonic == "CALL" or op_mnemonic == "CALLIND":
        call_target_vn = defining_op.getInput(0)
        called_function_name = None; called_function_obj = None; is_known_allocator = False
        func_addr = call_target_vn.getAddress()
        if func_addr and func_addr.isMemoryAddress():
            func_at_addr = current_program_ref.getFunctionManager().getFunctionAt(func_addr)
            if func_at_addr:
                called_function_name = func_at_addr.getName(); called_function_obj = func_at_addr
        elif call_target_vn.isConstant(): 
            const_addr = call_target_vn.getAddress()
            if const_addr:
                func_at_addr = current_program_ref.getFunctionManager().getFunctionAt(const_addr)
                if func_at_addr:
                    called_function_name = func_at_addr.getName(); called_function_obj = func_at_addr
        dprint(trace_prefix + "  Evaluating CALL to: %s (Name: %s, AddrFromVN: %s, VN: %s)" % (
            op_mnemonic, called_function_name if called_function_name else "<UnknownName>",
            func_addr.toString() if func_addr else (call_target_vn.getAddress().toString() if call_target_vn.getAddress() else "<NoAddressFromVN>"),
            call_target_vn ))
        if called_function_name:
            if called_function_name in KNOWN_ALLOCATOR_FUNCTIONS or \
               any(mangled_name == called_function_name for mangled_name in KNOWN_ALLOCATOR_FUNCTIONS if called_function_name.startswith("_Z")):
                is_known_allocator = True
        if is_known_allocator:
            println_func(trace_prefix + "Allocator Call Found: %s to %s" % (op_mnemonic, called_function_name))
            origins.append(dict(source_op_details_base, **{
                "source_type": "_OBJECT_ALLOCATION_SITE_",
                "details": "Call to known allocator function %s" % called_function_name,
                "object_ptr_hv": current_vn.getHigh(), "allocator_call_op": defining_op,
                "function_where_allocated": high_func, "original_target_info": original_target_info
            }))
    return origins

def start_interprocedural_backward_trace(initial_hf, initial_vn_to_trace, println_func, current_program_ref_of_initial_trace, initial_target_details_for_report):
    master_origins_list = []
    global_visited_interproc_states = set()
    initial_original_target_info = {"str_address": initial_target_details_for_report.get("str_address", "N/A"),
                                    "str_instr": initial_target_details_for_report.get("str_instr", "N/A"),
                                    "initial_xi_repr": get_varnode_representation(initial_vn_to_trace, initial_hf, current_program_ref_of_initial_trace)
                                   }
    worklist = [(initial_hf, initial_vn_to_trace, 0, None, None, initial_original_target_info)] 
    processed_count = 0
    while worklist:
        processed_count += 1
        if monitor.isCancelled(): dprint("Inter-procedural trace cancelled.") # monitor is Ghidra global
        
        current_hf, current_vn, current_inter_depth, special_task, task_info, original_target_info_for_current_item = worklist.pop(0)
        current_prog_ref = current_hf.getFunction().getProgram() 
        func_entry_str = str(current_hf.getFunction().getEntryPoint())
        prog_id_str = str(current_prog_ref.getUniqueProgramID())
        vn_key_part = None
        if isinstance(current_vn, Varnode): 
            if current_vn.isUnique():
                def_op = current_vn.getDef()
                vn_key_part = ("unique", str(def_op.getSeqnum().getTarget()) if def_op else "nodef", 
                               def_op.getSeqnum().getOrder() if def_op else -1, 
                               def_op.getSeqnum().getTime() if def_op else -1, current_vn.getOffset())
            else: 
                vn_key_part = ("addr_vn", str(current_vn.getAddress()), current_vn.getOffset(), current_vn.getSize())
        elif special_task == "_TRACE_WRITES_TO_PARAM_": 
            if isinstance(task_info, dict):
                param_ordinal_val = task_info.get("param_ordinal", -99) 
                original_var_repr_val = task_info.get("original_caller_var_repr", "_UnknownOrigVar_") 
                vn_key_part = ("_SPECIAL_TASK_WRITES_TO_PARAM_", param_ordinal_val, original_var_repr_val,
                               original_target_info_for_current_item.get("initial_xi_repr", "N/A_XI"))
            else:
                vn_key_part = ("_SPECIAL_TASK_WRITES_TO_PARAM_FALLBACK_", str(task_info),
                               original_target_info_for_current_item.get("initial_xi_repr", "N/A_XI"))
        else: 
            println_func("Error: Unknown item type or special_task for vn_key_part generation. VN: %s, SpecialTask: %s" % (current_vn, special_task))
            continue
        current_processing_key = (prog_id_str, func_entry_str, vn_key_part)
        if current_processing_key in global_visited_interproc_states:
            println_func("  " * (current_inter_depth * 2) + "[INTER] Globally skipping already processed state: %s" % str(current_processing_key))
            continue
        global_visited_interproc_states.add(current_processing_key)
        
        if special_task == "_TRACE_WRITES_TO_PARAM_":
            param_ordinal_to_check = task_info["param_ordinal"] if isinstance(task_info, dict) else task_info
            original_caller_var_repr = task_info.get("original_caller_var_repr", "UnknownOriginalVar") if isinstance(task_info, dict) else "UnknownOriginalVar"
            println_func("  " * (current_inter_depth * 2) + "[INTER] Special Task: Tracing writes to param #%s in %s (orig_var: %s, initial_target: %s)" % (
                param_ordinal_to_check, current_hf.getFunction().getName(), original_caller_var_repr, original_target_info_for_current_item.get("initial_xi_repr")))
            param_symbol = current_hf.getLocalSymbolMap().getParamSymbol(param_ordinal_to_check)
            if not param_symbol or not param_symbol.getHighVariable():
                master_origins_list.append({"source_type": "ERROR_NO_PARAM_SYMBOL_FOR_WRITE_TRACE", "function_name": current_hf.getFunction().getName(), "details": "Param ordinal %s invalid or no HV." % param_ordinal_to_check, "original_target_info": original_target_info_for_current_item}); continue
            param_vn_rep_in_callee = param_symbol.getHighVariable().getRepresentative() 
            found_writes = False
            for op_in_callee in current_hf.getPcodeOps():
                if op_in_callee.getMnemonic() == "STORE":
                    store_dest_addr_vn = op_in_callee.getInput(1); is_match = False
                    if store_dest_addr_vn.equals(param_vn_rep_in_callee): is_match = True
                    else:
                        def_of_store_addr = store_dest_addr_vn.getDef()
                        if def_of_store_addr and def_of_store_addr.getMnemonic() == "COPY" and def_of_store_addr.getInput(0).equals(param_vn_rep_in_callee): is_match = True
                    if is_match:
                        found_writes = True; value_stored_vn = op_in_callee.getInput(2)
                        println_func("    Found STORE to by-ref param #%s: %s (value: %s)" % (param_ordinal_to_check, op_in_callee, get_varnode_representation(value_stored_vn, current_hf, current_prog_ref)))
                        worklist.append((current_hf, value_stored_vn, current_inter_depth, None, {"from_by_ref_store_to_param": param_ordinal_to_check, "original_caller_var_repr": original_caller_var_repr}, original_target_info_for_current_item)) 
            if not found_writes:
                 master_origins_list.append({"source_type": "BY_REF_PARAM_NO_WRITES_FOUND", "function_name": current_hf.getFunction().getName(), "param_name": param_symbol.getName(), "param_ordinal": param_ordinal_to_check, "details": "No STOREs found using param %s as address." % param_symbol.getName(), "original_target_info": original_target_info_for_current_item})
            continue 

        dprint("\\n[INTER-MANAGER] Worklist item #%s: Analyzing VN %s in Func %s (InterDepth %s/%s) for Original Target: %s" % (
            str(processed_count), get_varnode_representation(current_vn, current_hf, current_prog_ref),
            current_hf.getFunction().getName(), str(current_inter_depth), str(MAX_BACKWARD_TRACE_DEPTH_INTER),
            original_target_info_for_current_item.get("initial_xi_repr")))
        visited_intra_vns_for_this_call = {} 
        intra_origins_and_signals = trace_variable_origin_backward_recursive(current_hf, current_vn, 0, MAX_BACKWARD_TRACE_DEPTH_INTRA, 
                                                                           visited_intra_vns_for_this_call, current_inter_depth, MAX_BACKWARD_TRACE_DEPTH_INTER, 
                                                                           global_visited_interproc_states, println_func, current_prog_ref, original_target_info_for_current_item)
        for origin_signal in intra_origins_and_signals:
            if "original_target_info" not in origin_signal: origin_signal["original_target_info"] = original_target_info_for_current_item
            if isinstance(task_info, dict) and task_info.get("from_by_ref_store_to_param") is not None:
                origin_signal["details"] = "Origin via by-ref param #%s: %s. %s" % (task_info["from_by_ref_store_to_param"], task_info.get("original_caller_var_repr", ""), origin_signal.get("details", ""))
                origin_signal["source_type"] += "_VIA_BY_REF_PARAM_STORE"

            if origin_signal.get("source_type", "").startswith("_OBJECT_ALLOCATION_SITE_"):
                println_func("  " * (current_inter_depth*2+1) + "[INTER] Object allocation site detected. Initiating vtable scan.")
                obj_ptr_hv_alloc = origin_signal.get("object_ptr_hv"); alloc_call_op = origin_signal.get("allocator_call_op"); func_where_alloc_hf = origin_signal.get("function_where_allocated")
                if obj_ptr_hv_alloc and alloc_call_op and func_where_alloc_hf:
                    prog_ref_for_vtable_scan = func_where_alloc_hf.getFunction().getProgram()
                    vtable_scan_results = find_and_report_vtable_assignment(obj_ptr_hv_alloc, alloc_call_op, func_where_alloc_hf, original_target_info_for_current_item, println_func, prog_ref_for_vtable_scan)
                    if vtable_scan_results: master_origins_list.extend(vtable_scan_results)
                    master_origins_list.append(origin_signal) 
                else:
                    err_details = [f for f,v in [("object_ptr_hv",obj_ptr_hv_alloc), ("allocator_call_op",alloc_call_op), ("function_where_allocated",func_where_alloc_hf)] if not v]
                    println_func("    Error: Missing data for vtable scan: %s. Signal: %s" % (", ".join(err_details), origin_signal))
                    master_origins_list.append(origin_signal)

            elif origin_signal.get("source_type") == "_INTERPROC_FUNCTION_INPUT_":
                callee_func_obj = origin_signal["function_object"]; param_index = origin_signal["param_index"]
                if param_index == -1: master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_UNKNOWN_INDEX", details=origin_signal.get("details", "") + " (Could not determine param ordinal).")); continue
                ref_iter = callee_func_obj.getProgram().getReferenceManager().getReferencesTo(callee_func_obj.getEntryPoint())
                callers_found_for_this_param = False
                for ref in ref_iter:
                    caller_func_obj = getFunctionContaining(ref.getFromAddress()) 
                    if caller_func_obj:
                        if caller_func_obj.equals(callee_func_obj) and current_inter_depth > 0 : println_func("  " * (current_inter_depth*2+3) + "[INTER]     Skipping direct recursive call to self (%s)." % callee_func_obj.getName()); continue
                        callers_found_for_this_param = True
                        caller_hf = get_high_function(caller_func_obj, caller_func_obj.getProgram())
                        if caller_hf:
                            call_pcode_op = None
                            ops_at_call_site = caller_hf.getPcodeOps(ref.getFromAddress())
                            while ops_at_call_site.hasNext():
                                op = ops_at_call_site.next()
                                if op.getMnemonic() in ["CALL", "CALLIND"]:
                                    call_target_vn_op = op.getInput(0)
                                    is_target_match = False
                                    if call_target_vn_op.isConstant() and call_target_vn_op.getAddress().equals(callee_func_obj.getEntryPoint()): is_target_match = True
                                    if is_target_match: call_pcode_op = op; break
                            if call_pcode_op and call_pcode_op.getNumInputs() > param_index + 1:
                                arg_vn_in_caller = call_pcode_op.getInput(param_index + 1)
                                if current_inter_depth < MAX_BACKWARD_TRACE_DEPTH_INTER:
                                    worklist.append((caller_hf, arg_vn_in_caller, current_inter_depth + 1, None, None, original_target_info_for_current_item))
                                else: master_origins_list.append(dict(origin_signal, source_type="MAX_INTER_DEPTH_REACHED_AT_CALLER_PARAM", details=origin_signal.get("details","") + " (Max inter-depth for param from %s)" % caller_func_obj.getName()))
                            elif call_pcode_op: master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAM_INDEX_OUT_OF_BOUNDS", details=origin_signal.get("details","") + " (Caller %s call op lacks index %s)" % (caller_func_obj.getName(), param_index)))
                            else: master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_NO_CALL_OP_AT_SITE", details=origin_signal.get("details","") + " (No CALL op at site %s in %s)" % (ref.getFromAddress(), caller_func_obj.getName())))
                        else: master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_CALLER_DECOMP_FAIL", details=origin_signal.get("details","") + " (Caller %s failed decompile)" % caller_func_obj.getName()))
                if not callers_found_for_this_param: master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_NO_CALLERS", details=origin_signal.get("details", "") + " (No callers found)."))
            
            elif origin_signal.get("source_type") == "_INTERPROC_HF_INPUT_":
                master_origins_list.append(dict(origin_signal, source_type="HIGH_FUNCTION_RAW_INPUT_TERMINAL", details=origin_signal.get("details", "") + " (Raw HF input)."))
            
            elif origin_signal.get("source_type") == "_INTERPROC_MODIFIED_BY_CALL_EFFECT_":
                caller_hf_for_effect = current_hf; call_op_seq_str_for_effect = origin_signal["call_op_seqnum_str"]; modified_vn_info_for_effect = origin_signal["modified_vn_info"]; call_op_in_caller_for_effect = None
                for op_lookup in caller_hf_for_effect.getPcodeOps():
                    if str(op_lookup.getSeqnum()) == call_op_seq_str_for_effect: call_op_in_caller_for_effect = op_lookup; break
                if call_op_in_caller_for_effect and modified_vn_info_for_effect and modified_vn_info_for_effect.get("is_stack"):
                    target_ghidra_stack_offset = modified_vn_info_for_effect.get("offset"); target_var_repr = origin_signal.get("source_value_repr", "UnknownTargetStackVar"); found_ref_param_match = False
                    println_func("  " * (current_inter_depth*2+2) + "  Checking CALL Op args for match with %s (offset: %#x)" % (target_var_repr, target_ghidra_stack_offset))
                    for i in range(1, call_op_in_caller_for_effect.getNumInputs()):
                        arg_vn = call_op_in_caller_for_effect.getInput(i); param_ordinal_for_callee = i - 1; temp_arg_vn = arg_vn; arg_def_op = temp_arg_vn.getDef(); num_copy_unwrap = 0
                        while arg_def_op and arg_def_op.getMnemonic() == "COPY" and num_copy_unwrap < 3:
                            temp_arg_vn = arg_def_op.getInput(0); arg_def_op = temp_arg_vn.getDef(); num_copy_unwrap += 1
                        if arg_def_op and arg_def_op.getMnemonic() in ["INT_ADD", "PTRADD", "PTRSUB"]:
                            is_ptrsub = arg_def_op.getMnemonic() == "PTRSUB"; op_in0 = arg_def_op.getInput(0); op_in1 = arg_def_op.getInput(1); base_vn_of_arg = None; raw_pcode_offset_val = None
                            if op_in1.isConstant(): base_vn_of_arg = op_in0; raw_pcode_offset_val = op_in1.getOffset()
                            elif op_in0.isConstant() and not is_ptrsub: base_vn_of_arg = op_in1; raw_pcode_offset_val = op_in0.getOffset()
                            if base_vn_of_arg and base_vn_of_arg.isRegister() and raw_pcode_offset_val is not None:
                                base_reg_obj = current_prog_ref.getRegister(base_vn_of_arg.getAddress()); base_reg_name_str = base_reg_obj.getName() if base_reg_obj else "Reg@%s" % base_vn_of_arg.getAddress()
                                effective_added_offset = -raw_pcode_offset_val if is_ptrsub else raw_pcode_offset_val
                                if (base_reg_name_str == "sp" or base_reg_name_str == "x29") and abs(effective_added_offset) == abs(target_ghidra_stack_offset):
                                    println_func("  " * (current_inter_depth*2+5) + "      SUCCESSFUL MATCH: Arg #%s seems to be %s." % (i, target_var_repr)); found_ref_param_match = True
                                    callee_target_vn = call_op_in_caller_for_effect.getInput(0); target_call_address = callee_target_vn.getAddress(); actual_callee_hf = None; callee_func_obj = None
                                    if target_call_address and target_call_address.isMemoryAddress():
                                        callee_func_obj = getFunctionAt(target_call_address)
                                        if callee_func_obj: actual_callee_hf = get_high_function(callee_func_obj, callee_func_obj.getProgram())
                                    if actual_callee_hf:
                                        if current_inter_depth < MAX_BACKWARD_TRACE_DEPTH_INTER:
                                            worklist.append((actual_callee_hf, "_TRACE_WRITES_TO_PARAM_", current_inter_depth + 1, "_TRACE_WRITES_TO_PARAM_", {"param_ordinal": param_ordinal_for_callee, "original_caller_var_repr": target_var_repr}, original_target_info_for_current_item))
                                        else: master_origins_list.append(dict(origin_signal, source_type="MAX_INTER_DEPTH_AT_MODIFIED_BY_CALL", details="Max depth tracing into callee for " + target_var_repr))
                                    else: master_origins_list.append(dict(origin_signal, source_type="MODIFIED_BY_CALL_CALLEE_UNRESOLVED", details="Callee for " +target_var_repr + " not resolved/decompiled."))
                                    break 
                    if not found_ref_param_match: master_origins_list.append(origin_signal)
                else: master_origins_list.append(origin_signal)
            else: master_origins_list.append(origin_signal)
            
    final_deduplicated_origins = []
    seen_reprs_final = set()
    for res in master_origins_list:
        orig_target_key_part = ()
        if "original_target_info" in res and isinstance(res["original_target_info"], dict) :
            orig_target_key_part = (res["original_target_info"].get("str_address", "N/A"), res["original_target_info"].get("initial_xi_repr", "N/A"))
        vtable_addr_details_key = res.get("vtable_address_details", "N/A") if res.get("source_type") == "VTABLE_ADDRESS_FOUND" else "N/A_VTABLE"
        # Ensure all parts of the key are hashable, convert lists/dicts if necessary, or use stable string representations
        details_key_part = str(res.get("details", "")) # Example: convert details to string if it can be complex
        repr_key_tuple = (res.get("address", "N/A"), res.get("pcode_op_str", "N/A"), res.get("source_type", "Unknown"), 
                          res.get("source_value_repr", "N/A"), res.get("function_name", "N/A"), 
                          vtable_addr_details_key, details_key_part) + orig_target_key_part
        
        if repr_key_tuple not in seen_reprs_final:
            final_deduplicated_origins.append(res); seen_reprs_final.add(repr_key_tuple)
    return final_deduplicated_origins

def print_backward_analysis_results(results_list):
    vtable_addresses = set() 
    for res in results_list:
        if res.get("source_type") == "VTABLE_ADDRESS_FOUND":
            address_value = res.get("resolved_vtable_address_value")
            if address_value is not None:
                try: vtable_addresses.add(long(address_value)) 
                except (TypeError, ValueError): 
                    try: vtable_addresses.add(long(address_value.longValue()))
                    except Exception as e_conv: dprint("[PRINT_RESULTS_WARN] Could not convert %s to long: %s" % (str(address_value), str(e_conv)))
    if vtable_addresses:
        sorted_addresses = sorted(list(vtable_addresses))
        print("\\n--- Aggregated VTable Addresses Found (Transformed) ---") # Title updated
        for original_addr in sorted_addresses:
            # Apply the transformation: 0xffffffffffffffff - original_addr
            # The '& 0xffffffffffffffffL' ensures it's treated as a 64-bit unsigned value for printing
            transformed_addr = ( (0xffffffffffffffff - original_addr + 1) & 0xffffffffffffffff )
            print("0x%x" % transformed_addr)
    else:
        print("\\n--- No VTable Addresses Found from this run ---")

def resolve_varnode_to_constant(vn_to_resolve, func_hf, current_prog_ref, println_func_resolve, max_depth=7, _visited_vns_for_resolve=None):
    if vn_to_resolve is None: return None
    # println_func_resolve("      [CONST_RESOLVE_DEBUG] Enter resolve_varnode_to_constant. VN: %s" % vn_to_resolve.toString()) # Verbose
    if _visited_vns_for_resolve is None: _visited_vns_for_resolve = set()
    vn_repr_for_debug = get_varnode_representation(vn_to_resolve, func_hf, current_prog_ref)
    vn_key_tuple_part = None
    if vn_to_resolve.isUnique():
        def_op_key = vn_to_resolve.getDef(); seq_target_str = "NoDefOp"; seq_order_val = -2; seq_time_val = -2
        if def_op_key: seq_key = def_op_key.getSeqnum(); seq_target_str = str(seq_key.getTarget()) if seq_key else "NoSeqNum"; seq_order_val = seq_key.getOrder() if seq_key else -1; seq_time_val = seq_key.getTime() if seq_key else -1
        vn_key_tuple_part = ("unique", vn_to_resolve.getOffset(), seq_target_str, seq_order_val, seq_time_val)
    elif vn_to_resolve.getAddress(): vn_key_tuple_part = ("addr", str(vn_to_resolve.getAddress()), vn_to_resolve.getSize())
    else: 
        if vn_to_resolve.isConstant(): return vn_to_resolve.getOffset()
        # println_func_resolve("      [CONST_RESOLVE_DEBUG] Cannot form key for VN: %s" % vn_repr_for_debug); 
        return None 
    current_func_entry_str = str(func_hf.getFunction().getEntryPoint())
    vn_resolution_key = (current_func_entry_str,) + vn_key_tuple_part
    if vn_resolution_key in _visited_vns_for_resolve: 
        # println_func_resolve("      [CONST_RESOLVE_DEBUG] Already visited %s in this path." % vn_repr_for_debug); 
        return None
    _visited_vns_for_resolve.add(vn_resolution_key)
    # println_func_resolve("      [CONST_RESOLVE_DEBUG] Trying to resolve: %s (Depth: %d)" % (vn_repr_for_debug, max_depth))
    if vn_to_resolve.isConstant(): 
        # println_func_resolve("        [CONST_RESOLVE_DEBUG] IS Constant: %#x" % vn_to_resolve.getOffset()); 
        return vn_to_resolve.getOffset()
    if max_depth <= 0: 
        # println_func_resolve("        [CONST_RESOLVE_DEBUG] Max depth reached for %s." % vn_repr_for_debug); 
        return None
    def_op = vn_to_resolve.getDef()
    if def_op is None:
        mem_addr_obj = vn_to_resolve.getAddress()
        if (mem_addr_obj and mem_addr_obj.isMemoryAddress() and not mem_addr_obj.isUniqueAddress() and
            not mem_addr_obj.isRegisterAddress() and not mem_addr_obj.isStackAddress() and not mem_addr_obj.isConstantAddress()):
            try:
                val_size = vn_to_resolve.getSize(); loaded_value = None; mem = current_prog_ref.getMemory()
                if val_size == 8: loaded_value = mem.getLong(mem_addr_obj)
                elif val_size == 4: loaded_value = mem.getInt(mem_addr_obj) 
                elif val_size == 2: loaded_value = mem.getShort(mem_addr_obj)
                elif val_size == 1: loaded_value = mem.getByte(mem_addr_obj)
                else: return None
                # println_func_resolve("            [CONST_RESOLVE_DEBUG] Read from direct mem addr %s (size %d) value: %#x" % (mem_addr_obj, val_size, loaded_value));
                return loaded_value & 0xFFFFFFFFFFFFFFFF 
            except Exception as e_mem_direct: 
                # println_func_resolve("            [CONST_RESOLVE_DEBUG] Error reading mem for %s: %s" % (mem_addr_obj, str(e_mem_direct))); 
                return None
        return None
    op_mnemonic = def_op.getMnemonic()
    # println_func_resolve("        [CONST_RESOLVE_DEBUG] Def op for %s is %s" % (vn_repr_for_debug, op_mnemonic))
    if op_mnemonic == "LOAD":
        load_addr_vn = def_op.getInput(1)
        resolved_load_addr_const = resolve_varnode_to_constant(load_addr_vn, func_hf, current_prog_ref, println_func_resolve, max_depth - 1, _visited_vns_for_resolve.copy())
        if resolved_load_addr_const is not None:
            try:
                ghidra_load_addr = current_prog_ref.getAddressFactory().getDefaultAddressSpace().getAddress(long(resolved_load_addr_const))
                val_size = vn_to_resolve.getSize(); loaded_value = None; mem = current_prog_ref.getMemory()
                if val_size == 8: loaded_value = mem.getLong(ghidra_load_addr)
                elif val_size == 4: loaded_value = mem.getInt(ghidra_load_addr) 
                elif val_size == 2: loaded_value = mem.getShort(ghidra_load_addr)
                elif val_size == 1: loaded_value = mem.getByte(ghidra_load_addr)
                else: return None
                # println_func_resolve("            [CONST_RESOLVE_DEBUG] LOAD from %#x (size %d) value: %#x" % (long(resolved_load_addr_const), val_size, loaded_value));
                return loaded_value & 0xFFFFFFFFFFFFFFFF
            except Exception as e_mem: 
                # println_func_resolve("            [CONST_RESOLVE_DEBUG] Error reading mem for LOAD %#x: %s" % (resolved_load_addr_const, str(e_mem))); 
                return None
        return None
    elif op_mnemonic == "INDIRECT": # Simplified INDIRECT handling for constants
        if vn_to_resolve.isAddress() and vn_to_resolve.getAddress().isMemoryAddress() and not vn_to_resolve.getAddress().isStackAddress():
            direct_mem_addr = vn_to_resolve.getAddress()
            try:
                read_size = vn_to_resolve.getSize(); 
                if read_size not in [1,2,4,8]: read_size = 8 # Default for pointers
                loaded_value = None; mem = current_prog_ref.getMemory()
                if read_size == 8: loaded_value = mem.getLong(direct_mem_addr)
                elif read_size == 4: loaded_value = mem.getInt(direct_mem_addr)
                elif read_size == 2: loaded_value = mem.getShort(direct_mem_addr)
                elif read_size == 1: loaded_value = mem.getByte(direct_mem_addr)
                else: return None
                return loaded_value & 0xFFFFFFFFFFFFFFFF
            except Exception as e_mem_indirect: return None
        return None # Deeper INDIRECT analysis is complex for simple const resolving
    elif op_mnemonic == "COPY" or op_mnemonic == "CAST":
        return resolve_varnode_to_constant(def_op.getInput(0), func_hf, current_prog_ref, println_func_resolve, max_depth - 1, _visited_vns_for_resolve)
    elif op_mnemonic in ["INT_ADD", "PTRADD"]:
        val0 = resolve_varnode_to_constant(def_op.getInput(0), func_hf, current_prog_ref, println_func_resolve, max_depth - 1, _visited_vns_for_resolve.copy())
        if val0 is not None:
            val1 = resolve_varnode_to_constant(def_op.getInput(1), func_hf, current_prog_ref, println_func_resolve, max_depth - 1, _visited_vns_for_resolve.copy())
            if val1 is not None: return (val0 + val1) & 0xFFFFFFFFFFFFFFFF
    elif op_mnemonic == "PTRSUB" or op_mnemonic == "INT_SUB": 
        val0 = resolve_varnode_to_constant(def_op.getInput(0), func_hf, current_prog_ref, println_func_resolve, max_depth - 1, _visited_vns_for_resolve.copy())
        if val0 is not None:
            val1 = resolve_varnode_to_constant(def_op.getInput(1), func_hf, current_prog_ref, println_func_resolve, max_depth - 1, _visited_vns_for_resolve.copy())
            if val1 is not None: return (val0 - val1) & 0xFFFFFFFFFFFFFFFF
    return None

def find_and_report_vtable_assignment(obj_ptr_hv, alloc_call_op, func_where_alloc_hf, original_target_info_for_report, println_func, current_prog_ref_of_alloc_func):
    # println_func("      [VTABLE_SCAN] Initiated for object HV: %s in %s" % (get_varnode_representation(obj_ptr_hv, func_where_alloc_hf, current_prog_ref_of_alloc_func), func_where_alloc_hf.getFunction().getName()))
    return scan_for_vtable_store_recursive(obj_ptr_hv, alloc_call_op.getSeqnum(), func_where_alloc_hf, original_target_info_for_report, println_func, current_prog_ref_of_alloc_func, 0)

MAX_VTABLE_SCAN_DEPTH = 2
def scan_for_vtable_store_recursive(current_obj_ptr_hv, start_after_seqnum, current_scan_hf, original_target_info_for_report, println_func, current_prog_ref, current_depth):
    vtable_results = []
    current_obj_ptr_direct_vn = current_obj_ptr_hv.getRepresentative() if current_obj_ptr_hv else None
    if not current_obj_ptr_direct_vn: return vtable_results
    if current_depth > MAX_VTABLE_SCAN_DEPTH: return vtable_results
    # println_func("      [VTABLE_SCAN_REC depth=%d] Scanning for obj %s in %s" % (current_depth, get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref), current_scan_hf.getFunction().getName()))
    equivalent_obj_ptr_vns = {current_obj_ptr_direct_vn}
    obj_def_op = current_obj_ptr_direct_vn.getDef()
    if obj_def_op and obj_def_op.getMnemonic() == "CALL" and obj_def_op.getOutput() and obj_def_op.getOutput().equals(current_obj_ptr_direct_vn):
         equivalent_obj_ptr_vns.add(obj_def_op.getOutput())
    ops_iterator = current_scan_hf.getPcodeOps(); found_start_op = False if start_after_seqnum else True
    while ops_iterator.hasNext():
        pcode_op = ops_iterator.next()
        if not found_start_op:
            if pcode_op.getSeqnum().equals(start_after_seqnum): found_start_op = True
            continue 
        current_op_output_vn = pcode_op.getOutput()
        if current_op_output_vn:
            op_mnemonic_alias = pcode_op.getMnemonic()
            if op_mnemonic_alias == "COPY" or op_mnemonic_alias == "CAST":
                input_vn_for_copy_cast = pcode_op.getInput(0)
                if input_vn_for_copy_cast in equivalent_obj_ptr_vns and current_op_output_vn not in equivalent_obj_ptr_vns:
                    equivalent_obj_ptr_vns.add(current_op_output_vn)
        if pcode_op.getMnemonic() == "STORE":
            stored_to_addr_vn = pcode_op.getInput(1); value_stored_vn = pcode_op.getInput(2); base_being_stored_to = None
            if stored_to_addr_vn in equivalent_obj_ptr_vns: base_being_stored_to = stored_to_addr_vn
            else:
                addr_def_op = stored_to_addr_vn.getDef()
                if addr_def_op:
                    def_op_mnemonic = addr_def_op.getMnemonic()
                    if def_op_mnemonic == "COPY" and addr_def_op.getInput(0) in equivalent_obj_ptr_vns: base_being_stored_to = addr_def_op.getInput(0)
                    elif def_op_mnemonic in ["INT_ADD", "PTRADD"]:
                        add_in0 = addr_def_op.getInput(0); add_in1 = addr_def_op.getInput(1)
                        if (add_in0 in equivalent_obj_ptr_vns and add_in1.isConstant() and add_in1.getOffset() == 0): base_being_stored_to = add_in0
                        elif (add_in1 in equivalent_obj_ptr_vns and add_in0.isConstant() and add_in0.getOffset() == 0): base_being_stored_to = add_in1
            if base_being_stored_to is not None: 
                resolved_numerical_value = resolve_varnode_to_constant(value_stored_vn, current_scan_hf, current_prog_ref, dprint) # Use dprint for const_resolve verbosity if needed
                vtable_address_details_str = "Resolved Constant Addr: %#x" % resolved_numerical_value if resolved_numerical_value is not None else "Not a direct constant or resolvable"
                println_func("          [VTABLE_SCAN_REC depth=%d] >>> Potential VTABLE Assignment at %s in %s. Value: %s (%s)" % 
                             (current_depth, pcode_op.getSeqnum().getTarget(), current_scan_hf.getFunction().getName(), 
                              get_varnode_representation(value_stored_vn, current_scan_hf, current_prog_ref), vtable_address_details_str))
                vtable_results.append({
                    "source_type": "VTABLE_ADDRESS_FOUND", "address": pcode_op.getSeqnum().getTarget().toString(), "pcode_op_str": str(pcode_op),
                    "function_name": current_scan_hf.getFunction().getName(), "object_instance_repr": get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref),
                    "vtable_pointer_raw_repr": get_varnode_representation(value_stored_vn, current_scan_hf, current_prog_ref), 
                    "vtable_address_details": vtable_address_details_str, "resolved_vtable_address_value": resolved_numerical_value,
                    "details": "VTable pointer assigned to object (depth %d)." % current_depth, "original_target_info": original_target_info_for_report,
                    "str_address": original_target_info_for_report.get("str_address"), "str_instr": original_target_info_for_report.get("str_instr"),
                    "initial_xi_repr": original_target_info_for_report.get("initial_xi_repr")
                })
                return vtable_results 
        if pcode_op.getMnemonic() in ["CALL", "CALLIND"] and not vtable_results and pcode_op.getNumInputs() > 1:
            first_arg_vn = pcode_op.getInput(1)
            if first_arg_vn in equivalent_obj_ptr_vns:
                call_target_addr_vn = pcode_op.getInput(0); target_func_obj = None; target_func_addr = call_target_addr_vn.getAddress()
                if target_func_addr: target_func_obj = current_prog_ref.getFunctionManager().getFunctionAt(target_func_addr)
                if not target_func_obj and target_func_addr: target_func_obj = current_prog_ref.getFunctionManager().getFunctionContaining(target_func_addr)
                if target_func_obj and not target_func_obj.equals(current_scan_hf.getFunction()):
                    callee_hf = get_high_function(target_func_obj, target_func_obj.getProgram())
                    if callee_hf:
                        first_param_hv_callee = None; callee_function_obj = callee_hf.getFunction(); callee_prog_ref = callee_function_obj.getProgram()
                        if callee_function_obj.getParameterCount() > 0:
                            param_obj = callee_function_obj.getParameter(0)
                            if param_obj:
                                try: first_param_hv_callee = param_obj.getHighVariable()
                                except: pass
                                if not first_param_hv_callee:
                                    try: 
                                        storage = param_obj.getVariableStorage()
                                        if storage and not storage.isBadStorage() and storage.size() > 0:
                                            first_storage_vn = param_obj.getFirstStorageVarnode()
                                            if first_storage_vn: first_param_hv_callee = callee_hf.getHighVariable(first_storage_vn)
                                    except: pass
                                if not first_param_hv_callee:
                                    try: 
                                        sym = param_obj.getSymbol()
                                        if sym: first_param_hv_callee = sym.getHighVariable()
                                    except: pass
                        if not first_param_hv_callee: # Fallback to x0/r0
                            reg_name_fallback = "x0" # ARM64, adjust for other arch
                            reg_fb = callee_prog_ref.getRegister(reg_name_fallback)
                            if reg_fb:
                                for sym_callee in callee_hf.getLocalSymbolMap().getSymbols():
                                    if sym_callee.isParameter():
                                        try:
                                            if sym_callee.getStorage().isRegisterStorage() and sym_callee.getStorage().getRegister().equals(reg_fb):
                                                first_param_hv_callee = sym_callee.getHighVariable(); break
                                        except: pass
                        if first_param_hv_callee:
                            recursive_results = scan_for_vtable_store_recursive(first_param_hv_callee, None, callee_hf, original_target_info_for_report, println_func, target_func_obj.getProgram(), current_depth + 1)
                            if recursive_results: vtable_results.extend(recursive_results); return vtable_results
    return vtable_results

def get_register_name_from_varnode_phase1(varnode, current_program_ref):
    if varnode is not None and varnode.isRegister():
        reg = current_program_ref.getRegister(varnode.getAddress()) # No getRegister(Varnode) in API, use getRegister(Address)
        if reg is not None: return reg.getName()
    return None

def get_add_components_generic(add_op, high_func_ctx, current_program_ref):
    if add_op is None or add_op.getOpcode() != PcodeOp.INT_ADD: return None, None, None
    input0 = add_op.getInput(0); input1 = add_op.getInput(1); offset_val = None; base_val_vn = None
    if input1.isConstant(): offset_val = input1.getOffset(); base_val_vn = input0
    elif input0.isConstant(): offset_val = input0.getOffset(); base_val_vn = input1
    if base_val_vn is None or offset_val is None: return None, None, None
    base_name_repr = get_varnode_representation(base_val_vn, high_func_ctx, current_program_ref)
    return base_val_vn, offset_val, base_name_repr

def find_specific_str_instructions(target_offset_for_search, current_program_ref_local, ghidra_monitor):
    dprint("Starting Phase 1 (STR Search): Searching for STR/STUR xi, [xj, #0x%x] ..." % target_offset_for_search)
    found_instructions_info = []
    listing = current_program_ref_local.getListing()
    instructions = listing.getInstructions(True)
    for instr in instructions:
        if ghidra_monitor.isCancelled(): break
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic == "STR" or mnemonic == "STUR":
            pcode_ops = instr.getPcode(); store_op = None; store_op_pcode_index = -1
            if not pcode_ops: continue
            for p_op_idx, p_op in enumerate(pcode_ops):
                if p_op.getOpcode() == PcodeOp.STORE: store_op = p_op; store_op_pcode_index = p_op_idx; break
            if store_op and store_op.getNumInputs() == 3:
                value_stored_vn = store_op.getInput(2); address_calculation_vn = store_op.getInput(1)
                instruction_text = instr.toString(); mnemonic_str = instr.getMnemonicString(); first_operand_str = None
                if instruction_text.startswith(mnemonic_str):
                    operands_part = instruction_text[len(mnemonic_str):].lstrip()
                    comma_index = operands_part.find(',')
                    if comma_index != -1: first_operand_str = operands_part[:comma_index].rstrip()
                is_zero_store = False
                if first_operand_str and first_operand_str.lower() in ["xzr", "wzr"]: is_zero_store = True
                else:
                    val_def_op = value_stored_vn.getDef()
                    if val_def_op is None and value_stored_vn.isUnique() and store_op_pcode_index > 0 : # Check preceding ops for unique
                        for k_val in range(store_op_pcode_index -1, -1, -1):
                            prev_op = pcode_ops[k_val]
                            if prev_op.getOutput() and prev_op.getOutput().equals(value_stored_vn): val_def_op = prev_op; break
                    if val_def_op and val_def_op.getOpcode() == PcodeOp.COPY and val_def_op.getInput(0).isConstant() and val_def_op.getInput(0).getOffset() == 0: is_zero_store = True
                if is_zero_store: continue
                if first_operand_str:
                    parsed_op_lower = first_operand_str.lower()
                    if (len(parsed_op_lower) > 1 and (parsed_op_lower.startswith('d') or parsed_op_lower.startswith('w')) and parsed_op_lower[1:].isdigit()): continue
                
                addr_def_op = address_calculation_vn.getDef()
                if addr_def_op is None and address_calculation_vn.isUnique() and store_op_pcode_index > 0: # Check preceding ops for unique
                    for k_addr in range(store_op_pcode_index -1, -1, -1):
                        prev_op = pcode_ops[k_addr]
                        if prev_op.getOutput() and prev_op.getOutput().equals(address_calculation_vn): addr_def_op = prev_op; break

                if addr_def_op and addr_def_op.getOpcode() == PcodeOp.INT_ADD:
                    base_reg_vn_raw, imm_val_raw, base_reg_name_raw = get_add_components_generic(addr_def_op, None, current_program_ref_local)
                    if base_reg_vn_raw and imm_val_raw == target_offset_for_search:
                        if get_register_name_from_varnode_phase1(base_reg_vn_raw, current_program_ref_local) == "sp": continue 
                        pcode_based_xi_reg_name_for_log = get_register_name_from_varnode_phase1(value_stored_vn, current_program_ref_local)
                        final_xi_name_for_log = pcode_based_xi_reg_name_for_log if pcode_based_xi_reg_name_for_log else get_varnode_representation(value_stored_vn, None, current_program_ref_local)
                        raw_base_reg_addr_for_phase2 = base_reg_vn_raw.getAddress() if base_reg_vn_raw.isRegister() else None
                        found_instructions_info.append({
                            "address": instr.getAddress(), "instr_obj": instr, "xi_varnode_raw": value_stored_vn, 
                            "xi_reg_name_log": final_xi_name_for_log, "xj_reg_name_raw_log": base_reg_name_raw, 
                            "raw_base_reg_addr": raw_base_reg_addr_for_phase2, "offset": imm_val_raw
                        })
    if found_instructions_info:
        print("\\nPhase 1 (STR Search for offset 0x%x) Complete: Found %d matching STR/STUR instructions:" % (target_offset_for_search, len(found_instructions_info)))
        for item in found_instructions_info: print("  - Address: %s, Instruction: %s (Storing %s from base %s + #0x%x)" % (item["address"], item["instr_obj"].toString(), item["xi_reg_name_log"], item["xj_reg_name_raw_log"], item["offset"]))
    else:
        print("\\nPhase 1 (STR Search for offset 0x%x) Complete: No STR/STUR instructions matching criteria found." % target_offset_for_search)
    return found_instructions_info

# --- Functions from backword_vtable_call.py (END) ---

# --- Functions from vcall_offset_find.py (adapted START) ---

def get_true_defining_op_vcall(varnode, expected_opcode_val, current_program_ref_local, high_func_for_repr): # Added prog_ref for get_varnode_repr
    if varnode is None: dprint("GTDO_VCALL: Varnode input is None"); return None
    current_vn = varnode
    for _ in range(5): 
        defining_op = current_vn.getDef()
        if defining_op is None: dprint("GTDO_VCALL: Def op for %s is None." % get_varnode_representation(current_vn, high_func_for_repr, current_program_ref_local)); return None 
        actual_opcode = defining_op.getOpcode()
        if actual_opcode == PcodeOp.COPY or actual_opcode == PcodeOp.CAST:
            # dprint("GTDO_VCALL: Skipping %s for %s. Next VN: %s" % (PcodeOp.getMnemonic(actual_opcode), get_varnode_representation(current_vn, high_func_for_repr, current_program_ref_local), get_varnode_representation(defining_op.getInput(0), high_func_for_repr, current_program_ref_local) ))
            current_vn = defining_op.getInput(0)
            if current_vn is None: dprint("GTDO_VCALL: Next VN after COPY/CAST is None."); return None
        else:
            # dprint("GTDO_VCALL: VN %s def by %s. Expecting %s" % (get_varnode_representation(current_vn, high_func_for_repr, current_program_ref_local), PcodeOp.getMnemonic(actual_opcode), PcodeOp.getMnemonic(expected_opcode_val)))
            return defining_op if actual_opcode == expected_opcode_val else None
    dprint("GTDO_VCALL: Exceeded depth for %s" % get_varnode_representation(varnode, high_func_for_repr, current_program_ref_local)); return None

def get_constant_value_vcall(varnode):
    if varnode is not None and varnode.isConstant(): return varnode.getOffset()
    return None

def get_add_components_vcall(add_op, current_program_ref_local, high_func_for_repr): # Added prog_ref for get_varnode_repr
    if add_op is None or add_op.getOpcode() != PcodeOp.INT_ADD: return None, None
    input0 = add_op.getInput(0); input1 = add_op.getInput(1)
    offset_val = get_constant_value_vcall(input1); base_val_vn = input0
    if offset_val is None:
        offset_val = get_constant_value_vcall(input0); base_val_vn = input1
    if offset_val is None: dprint("GAC_VCALL: No const offset in INT_ADD: %s" % add_op); return None, None
    return base_val_vn, offset_val

def extract_offset1_from_function(func_to_analyze, current_program_ref_local, ghidra_monitor): # monitor already passed
    if func_to_analyze is None:
        print("Error: (extract_offset1) Function to analyze is None.")
        return []
    print("\\nPhase 0: Analyzing function for Offset1/Offset2 patterns: %s at %s" % (func_to_analyze.getName(), func_to_analyze.getEntryPoint()))
    
    high_func = get_high_function(func_to_analyze, current_program_ref_local) # Uses global decompiler_interfaces
    if not high_func:
        print("Error: (extract_offset1) Could not decompile function %s" % func_to_analyze.getName())
        return []

    opiter = high_func.getPcodeOps()
    found_call_infos = [] # Changed from set to list of dicts

    for callind_op in opiter:
        if ghidra_monitor.isCancelled(): break
        if callind_op.getOpcode() != PcodeOp.CALLIND: continue
        dprint("Found CALLIND at %s in %s" % (callind_op.getSeqnum().getTarget(), func_to_analyze.getName()))
        
        callind_input_vn = callind_op.getInput(0)
        if callind_input_vn is None: dprint("Step 0 FAIL (VCALL): CALLIND input VN is None."); continue
            
        temp_def_op = callind_input_vn.getDef(); target_func_ptr_vn = None 
        if temp_def_op is not None and temp_def_op.getOpcode() == PcodeOp.COPY:
            target_func_ptr_vn = temp_def_op.getInput(0)
        else: target_func_ptr_vn = callind_input_vn 
        if target_func_ptr_vn is None: dprint("Step 0 FAIL (VCALL): Could not get target_func_ptr_vn."); continue

        op_load_func_ptr = get_true_defining_op_vcall(target_func_ptr_vn, PcodeOp.LOAD, current_program_ref_local, high_func)
        if op_load_func_ptr is None: dprint("Step 1 FAIL (VCALL) for target_func_ptr_vn: %s" % get_varnode_representation(target_func_ptr_vn, high_func, current_program_ref_local)); continue
        addr_of_func_ptr_vn = op_load_func_ptr.getInput(1)

        op_add_offset2 = get_true_defining_op_vcall(addr_of_func_ptr_vn, PcodeOp.INT_ADD, current_program_ref_local, high_func)
        if op_add_offset2 is None: dprint("Step 2 FAIL (VCALL) for addr_of_func_ptr_vn: %s" % get_varnode_representation(addr_of_func_ptr_vn, high_func, current_program_ref_local)); continue
        vtable_ptr_vn, offset2_val = get_add_components_vcall(op_add_offset2, current_program_ref_local, high_func)
        if offset2_val is None or vtable_ptr_vn is None: dprint("Step 2.1 FAIL (VCALL) get_add_components for op_add_offset2: %s" % op_add_offset2); continue
        dprint("Step 2 OK (VCALL): offset2 = 0x%x, vtable_ptr_vn = %s" % (offset2_val, get_varnode_representation(vtable_ptr_vn, high_func, current_program_ref_local)))

        op_load_vtable_ptr = get_true_defining_op_vcall(vtable_ptr_vn, PcodeOp.LOAD, current_program_ref_local, high_func)
        if op_load_vtable_ptr is None: dprint("Step 3 FAIL (VCALL) for vtable_ptr_vn: %s" % get_varnode_representation(vtable_ptr_vn, high_func, current_program_ref_local)); continue
        addr_of_vtable_ptr_storage_vn = op_load_vtable_ptr.getInput(1)
        dprint("Step 3 OK (VCALL): addr_of_vtable_ptr_storage_vn = %s" % get_varnode_representation(addr_of_vtable_ptr_storage_vn, high_func, current_program_ref_local))
        
        op_add_offset1 = get_true_defining_op_vcall(addr_of_vtable_ptr_storage_vn, PcodeOp.INT_ADD, current_program_ref_local, high_func)
        if op_add_offset1 is None:
            op_load_intermediate_ptr = get_true_defining_op_vcall(addr_of_vtable_ptr_storage_vn, PcodeOp.LOAD, current_program_ref_local, high_func)
            if op_load_intermediate_ptr:
                 addr_for_intermediate_load_vn = op_load_intermediate_ptr.getInput(1)
                 dprint("Step 4 (VCALL) via intermediate LOAD: addr_for_intermediate_load_vn = %s" % get_varnode_representation(addr_for_intermediate_load_vn, high_func, current_program_ref_local))
                 op_add_offset1 = get_true_defining_op_vcall(addr_for_intermediate_load_vn, PcodeOp.INT_ADD, current_program_ref_local, high_func)
            
        if op_add_offset1 is None:
            dprint("Step 5 FAIL (VCALL) for addr_of_vtable_ptr_storage_vn (or its load source): %s" % get_varnode_representation(addr_of_vtable_ptr_storage_vn, high_func, current_program_ref_local))
            continue
            
        base_reg_vn, offset1_val = get_add_components_vcall(op_add_offset1, current_program_ref_local, high_func)
        if offset1_val is None or base_reg_vn is None: dprint("Step 5.1 FAIL (VCALL) get_add_components for op_add_offset1: %s" % op_add_offset1); continue
        
        dprint("SUCCESS (VCALL pattern): CALLIND at %s. Offset1=0x%x, Offset2=0x%x" % (callind_op.getSeqnum().getTarget(), offset1_val, offset2_val))
        found_call_infos.append({
            "call_site_address": callind_op.getSeqnum().getTarget().toString(), # Store call site address
            "offset1": offset1_val,
            "offset2": offset2_val
        })
        
    if found_call_infos:
        print("Found %d potential indirect call patterns in %s with Offset1/Offset2." % (len(found_call_infos), func_to_analyze.getName()))
        # for info in found_call_infos: # Optional: print details if needed
        #     print("  Call Site: %s, Offset1: 0x%x, Offset2: 0x%x" % (info["call_site_address"], info["offset1"], info["offset2"]))
    else:
        print("No Offset1/Offset2 patterns matching the criteria found in %s." % func_to_analyze.getName())
    return found_call_infos

# --- Functions from vcall_offset_find.py (adapted END) ---

# --- Main execution ---
if __name__ == "__main__":
    currentProgram = getCurrentProgram() # Ghidra global
    monitor = ConsoleTaskMonitor()    # Ghidra global
    
    try:
        target_func_for_offset1_detection = None # Renamed for clarity
        func_addr_str = askString("Enter Function Address for Initial Offset1/Offset2 Analysis", 
                                  "Enter start address of function (e.g., 0x100400), or leave blank to use current function:")
        if not func_addr_str or func_addr_str.strip() == "":
            target_func_for_offset1_detection = getFunctionContaining(currentAddress) # Ghidra global currentAddress
            if target_func_for_offset1_detection:
                print("Using current function for Offset1/Offset2 analysis: %s" % target_func_for_offset1_detection.getName())
            else:
                print("Error: No function at current address, and no address provided for initial analysis.")
        else:
            try:
                func_address = currentProgram.getAddressFactory().getAddress(func_addr_str)
                target_func_for_offset1_detection = getFunctionAt(func_address)
                if target_func_for_offset1_detection is None: target_func_for_offset1_detection = getFunctionContaining(func_address)
                if target_func_for_offset1_detection is None: print("Error: Could not find function at address %s for initial analysis" % func_addr_str)
            except Exception as e: print("Error: Invalid address format for initial analysis function - %s" % str(e))

        if target_func_for_offset1_detection:
            # Phase 0: Extract (call_site_addr, offset1, offset2) tuples
            indirect_call_infos = extract_offset1_from_function(target_func_for_offset1_detection, currentProgram, monitor)

            if not indirect_call_infos:
                print("\\nNo indirect call patterns (Offset1/Offset2) found in %s. Aborting." % target_func_for_offset1_detection.getName())
            else:
                dprint("\\nFound %d indirect call pattern instances." % len(indirect_call_infos))
                
                offset1_to_call_details = {}
                for info in indirect_call_infos:
                    o1 = info["offset1"]
                    if o1 not in offset1_to_call_details:
                        offset1_to_call_details[o1] = []
                    offset1_to_call_details[o1].append({
                        "call_site_address": info["call_site_address"], 
                        "offset2": info["offset2"]
                    })

                overall_json_results = []

                for offset1_val, call_details_list_for_o1 in offset1_to_call_details.items():
                    print("\\n--- Processing for Offset1 = 0x%x ---" % offset1_val)
                    print("  (Associated with %d call site(s) from Phase 0)" % len(call_details_list_for_o1))

                    # Phase 1: STR Search (uses offset1_val)
                    found_str_instructions = find_specific_str_instructions(offset1_val, currentProgram, monitor)

                    if not found_str_instructions:
                        print("  Phase 1 (STR Search for offset 0x%x) found no relevant STR/STUR. VTable cannot be resolved for this Offset1." % offset1_val)
                        for detail in call_details_list_for_o1:
                            overall_json_results.append({
                                "indirect_call_site_address": detail["call_site_address"],
                                "offset1": "0x%x" % offset1_val,
                                "offset2": "0x%x" % detail["offset2"],
                                "vtable_base_address": None,
                                "calculated_target_function_address_value": None,
                                "calculated_target_function_name": "STR search failed for this Offset1"
                            })
                        continue # to next offset1_val in offset1_to_call_details

                    # Phase 2: Backward Trace & VTable Scan for this offset1_val
                    dprint("  Starting Phase 2 (Backward Trace & VTable Scan for offset 0x%x)." % offset1_val)
                    vtable_origins_for_this_offset1 = [] # Collect all trace results for this offset1
                    for item_idx, item_info in enumerate(found_str_instructions):
                        instr_addr = item_info["address"]
                        current_str_details_for_report = {
                            "str_address": instr_addr.toString(),
                            "str_instr": item_info["instr_obj"].toString(),
                        }
                        dprint("\\n  --- Analyzing STR at %s (Instruction %d of %d for offset 0x%x) ---" % (instr_addr, item_idx + 1, len(found_str_instructions), offset1_val))
                        dprint("    Target STR: %s" % item_info["instr_obj"].toString())
                        dprint("    Raw `xi` (from Phase 1 PCode): %s" % item_info["xi_reg_name_log"]) 

                        containing_func_of_str = getFunctionContaining(instr_addr) 
                        if not containing_func_of_str:
                            dprint("    Error: Could not find function containing STR at %s" % str(instr_addr)); continue
                        
                        program_of_containing_func = containing_func_of_str.getProgram()
                        high_func_for_str = get_high_function(containing_func_of_str, program_of_containing_func)
                        if not high_func_for_str:
                            dprint("    Skipping Phase 2 for STR at %s (decompilation failure)." % instr_addr); continue
                        
                        initial_vn_to_trace_hf = None
                        op_iter_hf = high_func_for_str.getPcodeOps(instr_addr)
                        while op_iter_hf.hasNext():
                            hf_pcode_op = op_iter_hf.next()
                            if hf_pcode_op.getOpcode() == PcodeOp.STORE:
                                initial_vn_to_trace_hf = hf_pcode_op.getInput(2); break
                        
                        if initial_vn_to_trace_hf:
                            dprint("    Starting INTER-PROCEDURAL backward trace for `xi_hf`: %s" % get_varnode_representation(initial_vn_to_trace_hf, high_func_for_str, program_of_containing_func))
                            # Pass dprint as the println_func for start_interprocedural_backward_trace
                            origins_for_this_str = start_interprocedural_backward_trace(
                                high_func_for_str, initial_vn_to_trace_hf, dprint,  # dprint for detailed tracing output
                                program_of_containing_func, current_str_details_for_report )
                            vtable_origins_for_this_offset1.extend(origins_for_this_str)
                        else:
                            dprint("    Error: No STORE P-code or input[2] for STR at %s in HighFunction." % instr_addr)
                    
                    current_original_vtables = set() # Use a set to store unique vtable addresses
                    for res in vtable_origins_for_this_offset1:
                        if res.get("source_type") == "VTABLE_ADDRESS_FOUND":
                            address_value = res.get("resolved_vtable_address_value") # This is the original vtable address
                            if address_value is not None:
                                original_addr_val = None
                                if isinstance(address_value, (int, long)): # Python int/long
                                    original_addr_val = long(address_value)
                                elif hasattr(address_value, 'longValue'): # Java Long
                                    try: original_addr_val = long(address_value.longValue())
                                    except Exception as e_conv_long: 
                                        dprint("      Warning: Could not convert Java Long %s to python long: %s" % (str(address_value), str(e_conv_long)))
                                else: # Try direct conversion if type is unknown but might work
                                     try: original_addr_val = long(address_value)
                                     except Exception as e_conv_unknown:
                                        dprint("      Warning: Could not convert %s (type %s) to python long: %s" % (str(address_value), type(address_value), str(e_conv_unknown)))

                                if original_addr_val is not None:
                                    current_original_vtables.add(original_addr_val)
                    
                    if not current_original_vtables:
                        print("  Phase 2 (Backward Trace for offset 0x%x) did not resolve any VTable base addresses." % offset1_val)
                        for detail in call_details_list_for_o1:
                            overall_json_results.append({
                                "indirect_call_site_address": detail["call_site_address"],
                                "offset1": "0x%x" % offset1_val,
                                "offset2": "0x%x" % detail["offset2"],
                                "vtable_base_address": None,
                                "calculated_target_function_address_value": None,
                                "calculated_target_function_name": "VTable base not resolved for this Offset1"
                            })
                    else:
                        print("  Phase 2 (Backward Trace for offset 0x%x) resolved %d unique VTable base address(es): %s" % (
                            offset1_val, len(current_original_vtables), ", ".join(["0x%x" % v for v in sorted(list(current_original_vtables))]) ))
                        for detail in call_details_list_for_o1: # detail is {"call_site_address": ..., "offset2": ...}
                            for vtable_base_addr in current_original_vtables:
                                calculated_target_func_val = vtable_base_addr + detail["offset2"]
                                
                                target_func_ghidra_addr = None
                                try:
                                    # Ensure the value is correctly formatted for getAddress
                                    hex_addr_str_for_api = java.lang.Long.toHexString(calculated_target_func_val)
                                    target_func_ghidra_addr = currentProgram.getAddressFactory().getAddress(hex_addr_str_for_api)
                                except Exception as e_addr_conv:
                                    dprint("      Error converting calculated address 0x%x to Ghidra address: %s" % (calculated_target_func_val, str(e_addr_conv)))
                                
                                target_func_obj = None
                                target_func_name_str = None
                                if target_func_ghidra_addr:
                                    target_func_obj = getFunctionAt(target_func_ghidra_addr)
                                    if target_func_obj:
                                        target_func_name_str = target_func_obj.getName(True) # True for demangled
                                    else: # Check for symbol if no function
                                        sym = getSymbolAt(target_func_ghidra_addr)
                                        if sym: target_func_name_str = sym.getName(True) + " (Symbol)"

                                # Apply the transformation for JSON output
                                temp_val1 = (0xffffffffffffffff - vtable_base_addr + 1)
                                transformed_vtable_base_addr_json = temp_val1 & 0xffffffffffffffff
                                
                                # Calculate the target function address for JSON as: T(V_orig) + O2_orig
                                # Ensure original_calculated_target_func_address (V_orig + O2_orig) is used for Ghidra API lookups before this point.
                                # detail["offset2"] is O2_orig
                                temp_val2 = transformed_vtable_base_addr_json + detail["offset2"]
                                calculated_target_function_address_json = temp_val2 & 0xffffffffffffffff

                                # Start: New code block for dereferencing
                                final_pointed_to_function_address_str = None
                                final_pointed_to_function_name_str = None
                                
                                address_to_dereference_numeric = calculated_target_function_address_json

                                pointer_location_ghidra_addr = None
                                try:
                                    # Ensure the numeric value is correctly handled by toHexString, especially if it could be negative from Python's perspective
                                    # For positive long values fitting in Java long, it's fine.
                                    hex_str_for_ptr_loc = java.lang.Long.toHexString(address_to_dereference_numeric)
                                    pointer_location_ghidra_addr = currentProgram.getAddressFactory().getAddress(hex_str_for_ptr_loc)
                                except Exception as e_ptr_loc_conv:
                                    dprint("      Error converting address_to_dereference 0x%x to Ghidra address: %s" % (address_to_dereference_numeric, str(e_ptr_loc_conv)))

                                if pointer_location_ghidra_addr:
                                    try:
                                        pointer_size = currentProgram.getAddressFactory().getDefaultAddressSpace().getPointerSize()
                                        pointed_to_numerical_addr_val = None
                                        mem = currentProgram.getMemory()

                                        if pointer_size == 8: # 64-bit
                                            pointed_to_numerical_addr_val = mem.getLong(pointer_location_ghidra_addr)
                                        elif pointer_size == 4: # 32-bit
                                            # getInt returns signed int, convert to unsigned long for consistency if it's an address
                                            pointed_to_numerical_addr_val = mem.getInt(pointer_location_ghidra_addr) & 0xFFFFFFFF
                                        # Add other sizes if necessary

                                        if pointed_to_numerical_addr_val is not None:
                                            # Ensure the value is treated as unsigned for hex string and Ghidra address conversion
                                            if pointer_size == 8:
                                                pointed_to_numerical_addr_val &= 0xFFFFFFFFFFFFFFFF
                                            
                                            final_pointed_to_function_address_str = "0x%x" % pointed_to_numerical_addr_val
                                            
                                            pointed_to_ghidra_addr_obj = None
                                            try:
                                                hex_str_for_final_func = java.lang.Long.toHexString(pointed_to_numerical_addr_val)
                                                pointed_to_ghidra_addr_obj = currentProgram.getAddressFactory().getAddress(hex_str_for_final_func)
                                            except Exception as e_final_addr_conv:
                                                dprint("      Error converting final function value 0x%x to Ghidra address: %s" % (pointed_to_numerical_addr_val, str(e_final_addr_conv)))

                                            if pointed_to_ghidra_addr_obj:
                                                final_func_obj_at_ptr = getFunctionAt(pointed_to_ghidra_addr_obj)
                                                if final_func_obj_at_ptr:
                                                    final_pointed_to_function_name_str = final_func_obj_at_ptr.getName(True)
                                                else:
                                                    final_sym_at_ptr = getSymbolAt(pointed_to_ghidra_addr_obj)
                                                    if final_sym_at_ptr:
                                                        final_pointed_to_function_name_str = final_sym_at_ptr.getName(True) + " (Symbol)"
                                                    else:
                                                        final_pointed_to_function_name_str = "No function/symbol at 0x%x" % pointed_to_numerical_addr_val
                                            else:
                                                final_pointed_to_function_name_str = "Failed to create Ghidra address for value 0x%x" % pointed_to_numerical_addr_val
                                        else:
                                            final_pointed_to_function_name_str = "Unsupported pointer size (%d bytes) for memory read at 0x%x or read failed" % (pointer_size, address_to_dereference_numeric)
                                    
                                    except java.lang.Exception as e_mem_read_java: # Catch Ghidra/Java memory access exceptions
                                        dprint("      Memory read error (Java Exception) at %s (0x%x): %s" % (pointer_location_ghidra_addr.toString(), address_to_dereference_numeric, str(e_mem_read_java)))
                                        final_pointed_to_function_name_str = "Memory read error (e.g., invalid address, page fault)"
                                    except Exception as e_mem_read_py: # Catch other Python exceptions during memory read
                                        dprint("      Memory read error (Python Exception) at %s (0x%x): %s" % (pointer_location_ghidra_addr.toString(), address_to_dereference_numeric, str(e_mem_read_py)))
                                        final_pointed_to_function_name_str = "Memory read processing error"
                                else:
                                    final_pointed_to_function_name_str = "Failed to create Ghidra address for dereference location 0x%x" % address_to_dereference_numeric
                                # End: New code block

                                overall_json_results.append({
                                    "indirect_call_site_address": detail["call_site_address"],
                                    "offset1": "0x%x" % offset1_val,
                                    "offset2": "0x%x" % detail["offset2"],
                                    "vtable_base_address": "0x%x" % transformed_vtable_base_addr_json,
                                    "calculated_target_function_address_value": "0x%x" % calculated_target_function_address_json, # This is the address of the pointer
                                    "calculated_target_function_name": target_func_name_str, # Name at V_orig + O2_orig
                                    "final_pointed_to_function_address": final_pointed_to_function_address_str, # Address read from memory (*calculated_target_function_address_value)
                                    "final_pointed_to_function_name": final_pointed_to_function_name_str # Name at final_pointed_to_function_address
                                })
                # End of loop over offset1_to_call_details

                if overall_json_results:
                    try:
                        # Default filename proposal based on program name
                        prog_name_sanitized = "".join(c if c.isalnum() else "_" for c in currentProgram.getName())
                        default_json_filename = prog_name_sanitized + "_resolved_calls.json"
                        
                        # Ghidra Jython's askFile might not have default_filename parameter in all versions
                        # For simplicity, let's use a fixed name or a simpler prompt if askFile variant is an issue.
                        # Standard askFile(title, button_text)
                        output_file_obj = askFile("Save JSON Report As", "Save Report") 
                        if output_file_obj: # User selected a file
                            output_filename_str = output_file_obj.getAbsolutePath()
                            with open(output_filename_str, "w") as f:
                                json.dump(overall_json_results, f, indent=4, sort_keys=True) # sort_keys for consistent output
                            print("\\nJSON report successfully saved to: %s" % output_filename_str)
                        else: # User cancelled
                            print("\\nJSON report generation cancelled by user (no file selected).")
                    except Exception as e_json_save:
                        print("\\nError encountered while saving JSON report: %s" % str(e_json_save))
                        import traceback
                        traceback.print_exc()
                else:
                    print("\\nNo data was generated for the JSON report.")
            
            # The old print_backward_analysis_results is no longer called.
            # all_final_vtable_results_across_offsets is also no longer centrally accumulated.

    except Exception as e_main:
        import traceback
        print("Script execution error: %s" % str(e_main))
        traceback.print_exc()
    finally:
        dispose_decompilers() 
        print("\\nCombined script finished.") 