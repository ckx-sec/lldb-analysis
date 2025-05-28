# Ghidra Python Script - Merged Analysis (STR_Analyzer_Interprocedural_Enhanced_RefParam.py)
# Phase 1: Find specific STR/STUR instructions globally.
# Phase 2: For STRs found, trace the source of the stored value (xi)
#          using inter-procedural backward taint tracing, with enhanced
#          stack load analysis and new handling for by-reference parameters.
# @author MergedScriptUser (integrating concepts from TaintEngine.java and user feedback)
# @category Analysis

from ghidra.program.model.listing import Instruction, Function, Parameter, VariableStorage
from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable, PcodeOpAST
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import Reference, ReferenceIterator

import java.lang.Long # For toHexString

# --- Configuration ---
TARGET_OFFSET_FOR_STR_SEARCH = 0x1e8 # For Phase 1 STR/STUR search
MAX_BACKWARD_TRACE_DEPTH_INTRA = 7  # Max depth for intra-procedural trace legs
MAX_BACKWARD_TRACE_DEPTH_INTER = 3  # Max depth for inter-procedural jumps
EFFECTIVE_ADDR_MAX_DEPTH = 4        # Max depth for get_effective_defining_op_for_address
ENABLE_DEBUG_PRINTS = True        # Global debug print flag
# --- End Configuration ---

# Global store for decompiler interfaces to avoid re-initializing for same program
decompiler_interfaces = {}
# Global 'program' is set by Ghidra's environment when script runs
# program = getCurrentProgram() # This will be assigned by Ghidra

def dprint(s):
    if ENABLE_DEBUG_PRINTS:
        s_str = str(s)
        if not s_str.endswith("\n"):
             print("[DEBUG] " + s_str)
        else:
             print("[DEBUG] " + s_str.rstrip("\n"))

def get_decompiler(current_prog_ref):
    """Gets or initializes a decompiler interface for a given program."""
    prog_id = current_prog_ref.getUniqueProgramID()
    if prog_id not in decompiler_interfaces:
        dprint("Initializing decompiler interface for program: %s" % current_prog_ref.getName())
        ifc = DecompInterface()
        # Set up decompiler options if needed, e.g., for analysis configuration
        options = DecompileOptions()
        # GhidraScript or Plugin specific: currentProgram.getProject().getOptions("Decompiler")
        # For standalone, default options are usually fine.
        # ifc.setOptions(options)
        ifc.openProgram(current_prog_ref)
        decompiler_interfaces[prog_id] = ifc
    return decompiler_interfaces[prog_id]

def dispose_decompilers():
    """Disposes all initialized decompiler interfaces."""
    global decompiler_interfaces
    for ifc in decompiler_interfaces.values():
        ifc.dispose()
    decompiler_interfaces = {}
    dprint("All decompiler interfaces disposed.")

def get_high_function(func_obj, current_program_ref):
    if func_obj is None: return None
    ifc = get_decompiler(current_program_ref) # Use the helper

    if func_obj.isExternal():
        dprint("Function %s in program %s is external. No P-code to analyze." % (func_obj.getName(), current_program_ref.getName()))
        return None
    if func_obj.isThunk():
        dprint("Function %s in program %s is a thunk. Attempting to get thunked function." % (func_obj.getName(), current_program_ref.getName()))
        thunked_func = func_obj.getThunkedFunction(True) # Follow multiple thunks
        if thunked_func is not None and not thunked_func.equals(func_obj):
            dprint("  Thunk resolves to: %s in program %s" % (thunked_func.getName(), thunked_func.getProgram().getName()))
            # Important: The thunked function might be in a DIFFERENT program if it's an external thunk.
            # We need to use the program context of the thunked_func.
            return get_high_function(thunked_func, thunked_func.getProgram()) # Recursive call with potentially new program context
        else:
            dprint("  Could not resolve thunk or thunk to self for %s. Skipping." % func_obj.getName())
            return None
    try:
        # Timeout for decompilation, can be adjusted
        timeout_seconds = 60
        decompile_options = ifc.getOptions() # Get options from the interface
        if decompile_options is not None:
             # Example: if you have specific options to set on decompile_options object
             # decompile_options.grabFromToolAndProgram(None, current_program_ref) # If running in full Ghidra
             timeout_seconds = decompile_options.getDefaultTimeout() # Use default from options
        else:
            dprint("Warning: Decompiler options (ifc.getOptions()) for %s returned None. Using hardcoded timeout of %s seconds." % (current_program_ref.getName(), timeout_seconds))

        results = ifc.decompileFunction(func_obj, timeout_seconds, monitor) # monitor is a global from Ghidra
        if results is not None and results.getHighFunction() is not None:
            return results.getHighFunction()
        else:
            err_msg = results.getErrorMessage() if results and results.getErrorMessage() else "Decompilation returned no HighFunction."
            print("Warning: Could not decompile function %s in program %s. Reason: %s" % (func_obj.getName(), current_program_ref.getName(), err_msg))
            return None
    except Exception as e:
        print("Exception during decompilation of %s in program %s: %s" % (func_obj.getName(), current_program_ref.getName(), str(e)))
        # import traceback
        # traceback.print_exc()
        return None


# --- Helper Function: get_varnode_representation (from function-taint.py user provided file) ---
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
                elif isinstance(actual_high_var_target, ghidra.program.model.pcode.HighOther): # Java package path
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


# --- Helper Function: find_prior_stores_to_stack_location ---
def find_prior_stores_to_stack_location(high_func, target_stack_addr_hv, load_op,
                                        current_intra_depth, # For recursive call to core tracer
                                        max_intra_depth,     # For recursive call
                                        current_inter_depth, # For full inter-proc trace if needed
                                        max_inter_depth,     # For full inter-proc trace
                                        global_visited_interproc_states, # For full inter-proc trace
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

        # CRITICAL: For values from stack stores, we should initiate a *new* full inter-procedural trace.
        # This is complex. For now, we continue with the current intra-procedural tracer,
        # but this is a point of deep recursion that might need the full inter-proc manager.
        # Let's pass the inter-proc context to trace_variable_origin_backward_recursive
        # which will handle if this value_stored_vn itself is a parameter.
        sub_trace_visited_intra = {} # Fresh for this specific value trace from STORE
        origins = trace_variable_origin_backward_recursive(
            high_func, value_stored_vn,
            0, max_intra_depth, # Start fresh intra-depth for this value
            sub_trace_visited_intra, # Fresh intra-visited set
            current_inter_depth, max_inter_depth, global_visited_interproc_states, # Pass inter-proc context
            println_func, current_program_ref
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


# --- Core Backward Tracing Logic (INTRA-PROCEDURAL part) ---
def trace_variable_origin_backward_recursive(
    high_func, current_vn,
    current_intra_depth, max_intra_depth,
    visited_intra_vns, # Specific to this function call leg for intra-procedural cycle detection
    current_inter_depth, max_inter_depth, # Passed through for context, inter-proc decisions are by manager
    global_visited_interproc_states, # Passed for use by helpers like find_prior_stores
    println_func, current_program_ref
    ):
    origins = []
    current_vn_repr = get_varnode_representation(current_vn, high_func, current_program_ref)
    trace_prefix = "  " * (current_inter_depth * 2) + "  " * current_intra_depth + "|- " # Indent by inter then intra
    println_func(trace_prefix + "Tracing Varnode (intra): %s (InterDepth: %s, IntraDepth: %s)" % (current_vn_repr, current_inter_depth, current_intra_depth))

    # Intra-procedural visited check for the current trace leg
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
            "details": "Intra-procedural trace stopped at max depth.", "function_name": high_func.getFunction().getName()
        })
        return origins

    if current_vn.isConstant():
        println_func(trace_prefix + "Source Found: Constant %s" % current_vn_repr)
        origins.append({"address": "N/A", "pcode_op_str": "Constant", "source_type": "CONSTANT",
                       "source_value_repr": current_vn_repr, "function_name": high_func.getFunction().getName()})
        return origins

    # --- Parameter Check (will signal to inter-procedural manager) ---
    hv = current_vn.getHigh()
    if hv:
        symbol = hv.getSymbol()
        if symbol and symbol.isParameter():
            param_name = symbol.getName()
            param_index = -1
            try:
                # Try to get parameter index (ordinal)
                func_params = high_func.getFunction().getParameters()
                for i, p_obj in enumerate(func_params):
                    # Check if the HighVariable's symbol matches the parameter's symbol
                    # or if the varnode is part of the parameter's storage
                    if p_obj.getSymbol() and p_obj.getSymbol().equals(symbol):
                         param_index = p_obj.getOrdinal()
                         break
                    # Fallback: Check storage if symbol direct match fails (e.g. for split vars)
                    # This can be complex. A simpler check is if the representative varnode matches.
                    if param_index == -1 and p_obj.getVariableStorage().contains(current_vn):
                         param_index = p_obj.getOrdinal()
                         break
                if param_index == -1 and hasattr(symbol, 'getCategoryIndex') and symbol.getCategoryIndex() >=0: # Ghidra specific for param category
                    param_index = symbol.getCategoryIndex()

            except Exception as e_param:
                println_func(trace_prefix + "  Warning: Error getting parameter ordinal for %s: %s" % (param_name, e_param))

            println_func(trace_prefix + "Source is Function Input Parameter '%s' (Ordinal: %s). Signaling for inter-procedural analysis." % (param_name, param_index if param_index != -1 else "Unknown"))
            origins.append({
                "source_type": "_INTERPROC_FUNCTION_INPUT_", # Signal for manager
                "function_object": high_func.getFunction(),
                "param_high_var": hv, # Pass the HighVariable
                "param_varnode_repr": current_vn_repr,
                "param_name": param_name,
                "param_index": param_index,
                "details": "Parameter '%s' of function %s. Requires inter-procedural analysis." % (param_name, high_func.getFunction().getName()),
                "function_name": high_func.getFunction().getName() # For context
            })
            return origins # Return signal to manager

    defining_op = current_vn.getDef()
    if defining_op is None:
        source_type = "INPUT_VARNODE_OR_UNRESOLVED"
        details = "Varnode has no defining P-code op in this function's P-code."
        # Check for direct HighFunction inputs (not formal parameters but still inputs)
        if current_vn.isInput() and not (hv and hv.getSymbol() and hv.getSymbol().isParameter()): # Avoid double-reporting params
            println_func(trace_prefix + "Hit Direct HighFunction Input Varnode (not a formal parameter symbol). Signaling for inter-procedural analysis.")
            origins.append({
                "source_type": "_INTERPROC_HF_INPUT_", # Signal for manager
                "function_object": high_func.getFunction(),
                "input_varnode": current_vn,
                "input_varnode_repr": current_vn_repr,
                "details": "Direct HighFunction input in %s. May require inter-proc analysis if it's an implicit parameter or global." % high_func.getFunction().getName(),
                "function_name": high_func.getFunction().getName()
            })
            return origins
        elif current_vn.isPersistant() or current_vn.isAddrTied(): # Check for globals
            source_type = "GLOBAL_OR_PERSISTENT_VAR"
            details = "Varnode may represent a global variable or persistent storage."
        
        println_func(trace_prefix + "Source Found: %s (%s)" % (source_type, current_vn_repr))
        origins.append({"address": "N/A", "pcode_op_str": "No Defining PCodeOp", "source_type": source_type,
                       "source_value_repr": current_vn_repr, "details": details, "function_name": high_func.getFunction().getName()})
        return origins

    op_mnemonic = defining_op.getMnemonic()
    op_address_str = defining_op.getSeqnum().getTarget().toString()
    println_func(trace_prefix + "Defined by PCodeOp: %s (%s) at %s" % (op_mnemonic, defining_op, op_address_str))
    source_op_details_base = {"address": op_address_str, "pcode_op_str": str(defining_op), 
                              "source_value_repr": current_vn_repr, "function_name": high_func.getFunction().getName()}

    # Recursive calls for inputs
    next_intra_depth = current_intra_depth + 1

    if op_mnemonic == "LOAD":
        addr_vn = defining_op.getInput(1)
        addr_vn_repr = get_varnode_representation(addr_vn, high_func, current_program_ref)
        println_func(trace_prefix + "  -> Value from LOAD. Tracing address: %s" % addr_vn_repr)
        load_event_origin = dict(source_op_details_base, **{
            "source_type": "LOAD_FROM_MEMORY",
            "details": "Value loaded from address specified by: %s. Tracing address origin." % addr_vn_repr
        })
        origins.append(load_event_origin)
        origins.extend(trace_variable_origin_backward_recursive(high_func, addr_vn, next_intra_depth, max_intra_depth, 
                                                               visited_intra_vns, current_inter_depth, max_inter_depth, 
                                                               global_visited_interproc_states, println_func, current_program_ref))
        addr_hv_for_stack_check = addr_vn.getHigh()
        if addr_hv_for_stack_check and addr_hv_for_stack_check.isStackVariable():
            println_func(trace_prefix + "    LOAD is from HighStackVariable: %s. Attempting to find prior STOREs." % addr_hv_for_stack_check.getName())
            prior_store_value_origins = find_prior_stores_to_stack_location(
                high_func, addr_hv_for_stack_check, defining_op,
                next_intra_depth, max_intra_depth, # Pass current intra depth for recursive calls from find_prior_stores
                current_inter_depth, max_inter_depth, global_visited_interproc_states, # Pass inter context
                println_func, current_program_ref
            )
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
                if candidate_op.getSeqnum().getTime() == target_time_or_order: # Match based on 'time'
                    actual_effect_op = candidate_op; break
        
        if actual_effect_op:
            actual_effect_op_mnemonic = actual_effect_op.getMnemonic()
            details_indirect = "Value from indirect effect of PCodeOp: %s (%s)" % (actual_effect_op_mnemonic, actual_effect_op)
            
            if actual_effect_op_mnemonic in ["CALL", "CALLIND"]:
                # This is where local_60 modified by CALL FUN_0010d650 is caught.
                # current_vn is local_60 (output of INDIRECT). actual_effect_op is the CALL.
                call_target_vn_repr = get_varnode_representation(actual_effect_op.getInput(0), high_func, current_program_ref)
                
                # Emit a special signal for the inter-procedural manager to analyze this case.
                modified_vn_stack_info = None
                if current_vn.getAddress() and current_vn.getAddress().isStackAddress():
                    modified_vn_stack_info = {
                        "is_stack": True,
                        "offset": current_vn.getAddress().getOffset(),
                        "space_name": current_vn.getAddress().getAddressSpace().getName(),
                        "size": current_vn.getSize()
                    }
                elif hv and hv.isStackVariable(): # Check HighVariable as well
                     modified_vn_stack_info = {
                        "is_stack": True,
                        "offset": hv.getStackOffset(),
                        "space_name": "stack", # Assume standard stack space for HighStackVar
                        "size": hv.getSize()
                    }


                origins.append(dict(source_op_details_base, **{
                    "pcode_op_str": str(actual_effect_op), 
                    "address": actual_effect_op.getSeqnum().getTarget().toString(),
                    "source_type": "_INTERPROC_MODIFIED_BY_CALL_EFFECT_", # New signal
                    "call_op_seqnum_str": str(actual_effect_op.getSeqnum()), 
                    "modified_vn_info": modified_vn_stack_info, # Pass info about current_vn
                    "details": "Modified by indirect effect of call to: %s. (Original var: %s). Potential by-ref modification." % (
                        call_target_vn_repr, current_vn_repr)
                }))
                return origins # Let manager handle this complex case.
            else: # Indirect effect from non-call op
                origins.append(dict(source_op_details_base, **{
                    "pcode_op_str": str(actual_effect_op), "address": actual_effect_op.getSeqnum().getTarget().toString(),
                    "source_type": "COMPLEX_INDIRECT_EFFECT_FROM_%s" % actual_effect_op_mnemonic, 
                    "details": details_indirect
                }))

        else: # Could not resolve PCodeOp for indirect effect
            origins.append(dict(source_op_details_base, **{
                "source_type": "UNHANDLED_INDIRECT_EFFECT_RESOLUTION_FAILURE", 
                "details": "Could not resolve PCodeOp for indirect effect (ref_key: %#x at %s)." % (
                    effect_op_ref_vn.getOffset() if effect_op_ref_vn.isConstant() else -1, 
                    defining_op.getSeqnum().getTarget().toString())
            }))

    elif op_mnemonic in ["CALL", "CALLIND"]:
        # This handles cases where current_vn is the *direct output* of a call.
        call_target_vn = defining_op.getInput(0)
        # TODO: Similar to INDIRECT from CALL, if this output corresponds to a by-ref argument
        # that was modified, we might want to trace into the callee.
        # For now, this is a terminal point for this specific path.
        origins.append(dict(source_op_details_base, **{
            "source_type": "FUNCTION_CALL_OUTPUT",
            "details": "Output of call to target: %s" % get_varnode_representation(call_target_vn, high_func, current_program_ref)}))

    elif op_mnemonic in ["COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT_NEGATE", "INT_2COMP", "BOOL_NEGATE", "POPCOUNT",
                         "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND",
                         "INT2FLOAT", "FLOAT2INT", "SUBPIECE"]: # Unary or effectively unary for data flow
        input_vn = defining_op.getInput(0)
        if input_vn:
            origins.extend(trace_variable_origin_backward_recursive(high_func, input_vn, next_intra_depth, max_intra_depth,
                                                                   visited_intra_vns, current_inter_depth, max_inter_depth,
                                                                   global_visited_interproc_states, println_func, current_program_ref))
    elif op_mnemonic in ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
                         "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
                         "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
                         "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
                         "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV",
                         "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
                         "BOOL_XOR", "BOOL_AND", "BOOL_OR",
                         "MULTIEQUAL", "PIECE", "PTRADD", "PTRSUB"]: # Binary or multi-input ops
        for i in range(defining_op.getNumInputs()):
            input_vn = defining_op.getInput(i)
            if input_vn:
                 origins.extend(trace_variable_origin_backward_recursive(high_func, input_vn, next_intra_depth, max_intra_depth,
                                                                        visited_intra_vns, current_inter_depth, max_inter_depth,
                                                                        global_visited_interproc_states, println_func, current_program_ref))
    else: # Unhandled PCodeOp
        inputs_repr = [get_varnode_representation(defining_op.getInput(j), high_func, current_program_ref) for j in range(defining_op.getNumInputs())]
        origins.append(dict(source_op_details_base, **{
            "source_type": "UNHANDLED_PCODE_OP",
            "details": "PCodeOp %s is not specifically handled. Inputs: %s" % (op_mnemonic, inputs_repr)}))
    return origins


# --- Inter-procedural Trace Manager ---
def start_interprocedural_backward_trace(initial_hf, initial_vn_to_trace, println_func, current_program_ref_of_initial_trace):
    master_origins_list = []
    # global_visited_interproc_states: Key is (program_unique_id_str, function_entry_addr_str, varnode_key_tuple, special_state_marker_str)
    # varnode_key_tuple can be complex to ensure uniqueness of the Varnode being traced.
    # special_state_marker_str can be e.g. "_TRACE_WRITES_TO_PARAM_X"
    global_visited_interproc_states = set()
    
    # Worklist item: (HighFunction, Varnode_to_trace, current_inter_depth, 
    #                 special_task_marker=None, task_extra_info=None)
    # special_task_marker e.g. "_TRACE_WRITES_TO_PARAM_"
    # task_extra_info e.g. param_ordinal for _TRACE_WRITES_TO_PARAM_
    worklist = [(initial_hf, initial_vn_to_trace, 0, None, None)] 
    
    processed_count = 0
    while worklist:
        processed_count += 1
        if monitor.isCancelled(): dprint("Inter-procedural trace cancelled.")
        
        current_hf, current_vn, current_inter_depth, special_task, task_info = worklist.pop(0)
        
        current_prog_ref = current_hf.getFunction().getProgram() # Program context for current_hf
        func_entry_str = str(current_hf.getFunction().getEntryPoint())
        prog_id_str = str(current_prog_ref.getUniqueProgramID())

        vn_key_part = None
        if isinstance(current_vn, Varnode): # Regular varnode tracing
            # Create a unique key for the varnode
            if current_vn.isUnique():
                def_op = current_vn.getDef()
                vn_key_part = ("unique", str(def_op.getSeqnum().getTarget()) if def_op else "nodef", 
                               def_op.getSeqnum().getOrder() if def_op else -1, 
                               def_op.getSeqnum().getTime() if def_op else -1, 
                               current_vn.getOffset())
            else: # Register, Constant, Stack, Memory
                vn_key_part = ("addr_vn", str(current_vn.getAddress()), current_vn.getOffset(), current_vn.getSize())
        elif isinstance(current_vn, (str, unicode)) and current_vn == "_TRACE_WRITES_TO_PARAM_": # Special task
            vn_key_part = ("special_task_writes_to_param", task_info) # task_info is param_ordinal
        else: # Should not happen if worklist is managed correctly
            println_func("Error: Unknown item type on worklist: %s" % current_vn)
            continue

        current_processing_key = (prog_id_str, func_entry_str, vn_key_part)
        if current_processing_key in global_visited_interproc_states:
            println_func("  " * (current_inter_depth * 2) + "[INTER] Globally skipping already processed state (func, vn_key): %s" % current_processing_key)
            continue
        global_visited_interproc_states.add(current_processing_key)
        
        # --- Handle Special Task: _TRACE_WRITES_TO_PARAM_ ---
        if special_task == "_TRACE_WRITES_TO_PARAM_":
            param_ordinal_to_check = task_info # This is param_ordinal from worklist
            original_caller_var_repr = task_info.get("original_caller_var_repr", "UnknownOriginalVar") if isinstance(task_info, dict) else "UnknownOriginalVar" # Unpack if dict
            if isinstance(task_info, dict): param_ordinal_to_check = task_info.get("param_ordinal")


            println_func("  " * (current_inter_depth * 2) + "[INTER] Special Task: Tracing writes to param #%s in %s (orig_var: %s)" % (
                param_ordinal_to_check, current_hf.getFunction().getName(), original_caller_var_repr))

            param_symbol = current_hf.getLocalSymbolMap().getParamSymbol(param_ordinal_to_check)
            if not param_symbol:
                println_func("    Error: Could not get param symbol for ordinal %s in %s" % (param_ordinal_to_check, current_hf.getFunction().getName()))
                master_origins_list.append({"source_type": "ERROR_NO_PARAM_SYMBOL_FOR_WRITE_TRACE", "function_name": current_hf.getFunction().getName(), "details": "Param ordinal %s invalid." % param_ordinal_to_check})
                continue
            
            param_hv = param_symbol.getHighVariable()
            if not param_hv:
                 println_func("    Error: Could not get HighVariable for param symbol %s in %s" % (param_symbol.getName(), current_hf.getFunction().getName()))
                 master_origins_list.append({"source_type": "ERROR_NO_PARAM_HV_FOR_WRITE_TRACE", "function_name": current_hf.getFunction().getName(), "details": "Param %s has no HV." % param_symbol.getName()})
                 continue

            param_vn_rep_in_callee = param_hv.getRepresentative() # This varnode holds the address passed by caller

            found_writes = False
            for op_in_callee in current_hf.getPcodeOps():
                if op_in_callee.getMnemonic() == "STORE":
                    # getInput(0) is spaceID, getInput(1) is offset/address, getInput(2) is value stored
                    store_dest_addr_vn = op_in_callee.getInput(1)
                    
                    # Check if store_dest_addr_vn is equivalent to param_vn_rep_in_callee
                    # This is a simplified check. Real alias analysis is harder.
                    # It means the STORE is writing to the memory location pointed to by the parameter.
                    is_match = False
                    if store_dest_addr_vn.equals(param_vn_rep_in_callee):
                        is_match = True
                    else:
                        def_of_store_addr = store_dest_addr_vn.getDef()
                        if def_of_store_addr and def_of_store_addr.getMnemonic() == "COPY" and \
                           def_of_store_addr.getInput(0).equals(param_vn_rep_in_callee):
                            is_match = True
                        # TODO: Add checks for INT_ADD (param_vn_rep_in_callee, small_const_offset) for struct/array fields

                    if is_match:
                        found_writes = True
                        value_stored_vn = op_in_callee.getInput(2)
                        value_stored_repr = get_varnode_representation(value_stored_vn, current_hf, current_prog_ref)
                        println_func("    Found STORE to by-ref param #%s: %s (value: %s)" % (
                            param_ordinal_to_check, op_in_callee, value_stored_repr))
                        # Add the value being stored as a new regular trace item to the worklist
                        # The inter_depth remains the same as we are still "resolving" the modification within the callee
                        worklist.append((current_hf, value_stored_vn, current_inter_depth, None, {"from_by_ref_store_to_param": param_ordinal_to_check, "original_caller_var_repr": original_caller_var_repr})) 
            
            if not found_writes:
                 println_func("    No direct STORE operations found writing via param #%s (%s) in %s." % (
                     param_ordinal_to_check, get_varnode_representation(param_vn_rep_in_callee, current_hf, current_prog_ref), current_hf.getFunction().getName()))
                 # This path becomes a terminal point for this specific "trace writes" task.
                 # We might add a specific origin type here.
                 master_origins_list.append({"source_type": "BY_REF_PARAM_NO_WRITES_FOUND", 
                                            "function_name": current_hf.getFunction().getName(),
                                            "param_name": param_symbol.getName(),
                                            "param_ordinal": param_ordinal_to_check,
                                            "details": "No STOREs found directly using parameter %s as address in %s." % (param_symbol.getName(), current_hf.getFunction().getName())})
            continue # Finished processing this special task for this function

        # --- Regular Varnode Tracing ---
        dprint("\n[INTER-MANAGER] Worklist item #%s: Analyzing VN %s in Func %s (InterDepth %s/%s)" % (
            str(processed_count), 
            get_varnode_representation(current_vn, current_hf, current_prog_ref),
            current_hf.getFunction().getName(), 
            str(current_inter_depth), 
            str(MAX_BACKWARD_TRACE_DEPTH_INTER)
        ))

        visited_intra_vns_for_this_call = {} # Fresh for each new entry point into trace_variable_origin_backward_recursive from manager
        
        intra_origins_and_signals = trace_variable_origin_backward_recursive(
            current_hf, current_vn, 
            0, MAX_BACKWARD_TRACE_DEPTH_INTRA, # Start intra-depth at 0
            visited_intra_vns_for_this_call,
            current_inter_depth, MAX_BACKWARD_TRACE_DEPTH_INTER, # Pass current inter-depth
            global_visited_interproc_states, # Pass global visited set
            println_func, current_prog_ref
        )

        for origin_signal in intra_origins_and_signals:
            # Annotate with original traced varnode if it was from a special task previously
            if isinstance(task_info, dict) and task_info.get("from_by_ref_store_to_param") is not None:
                origin_signal["details"] = "Origin via by-ref param #%s: %s. %s" % (
                    task_info["from_by_ref_store_to_param"], 
                    task_info.get("original_caller_var_repr", ""),
                    origin_signal.get("details", ""))
                origin_signal["source_type"] += "_VIA_BY_REF_PARAM_STORE"


            if origin_signal.get("source_type") == "_INTERPROC_FUNCTION_INPUT_":
                if current_inter_depth < MAX_BACKWARD_TRACE_DEPTH_INTER:
                    println_func("  " * (current_inter_depth*2+1) + "[INTER] Parameter hit: %s. Processing jump to callers (Next InterDepth %s)." % (origin_signal.get("param_name"), current_inter_depth + 1))
                    callee_func_obj = origin_signal["function_object"] # This is the function whose param was hit
                    param_index = origin_signal["param_index"]

                    if param_index == -1:
                        println_func("  " * (current_inter_depth*2+1) + "[INTER] Warning: Unknown parameter index for %s. Cannot trace inter-procedurally." % origin_signal.get("param_name"))
                        master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_UNKNOWN_INDEX", 
                                                       details=origin_signal.get("details", "") + " (Could not determine param ordinal)."))
                        continue
                    
                    # Find callers of callee_func_obj
                    # References are specific to a program, ensure callee_func_obj.getProgram() is used
                    ref_iter = callee_func_obj.getProgram().getReferenceManager().getReferencesTo(callee_func_obj.getEntryPoint())
                    callers_found_for_this_param = False
                    for ref in ref_iter:
                        if monitor.isCancelled(): break
                        call_site_addr = ref.getFromAddress()
                        # Ensure the reference is a CALL type (though getReferencesTo entry usually are from calls)
                        # ref_type = ref.getReferenceType()
                        # if not (ref_type.isCall() or ref_type.isIndirect()): continue

                        caller_func_obj = getFunctionContaining(call_site_addr) # Ghidra API
                        if caller_func_obj and caller_func_obj.getProgram().equals(callee_func_obj.getProgram()): # Stay within same program unless handling externals explicitly
                            callers_found_for_this_param = True
                            println_func("  " * (current_inter_depth*2+2) + "[INTER]   Found caller: %s at %s" % (caller_func_obj.getName(), call_site_addr))
                            caller_hf = get_high_function(caller_func_obj, caller_func_obj.getProgram())
                            if caller_hf:
                                call_pcode_op = None
                                ops_at_call_site = caller_hf.getPcodeOps(call_site_addr)
                                while ops_at_call_site.hasNext():
                                    op = ops_at_call_site.next()
                                    if op.getMnemonic() in ["CALL", "CALLIND"]:
                                        # Check if this call actually targets our callee_func_obj
                                        call_target_vn_op = op.getInput(0)
                                        if call_target_vn_op.isConstant() and call_target_vn_op.getAddress().equals(callee_func_obj.getEntryPoint()):
                                            call_pcode_op = op; break
                                        # TODO: Add check for CALLIND if target can be resolved
                                if call_pcode_op:
                                    if call_pcode_op.getNumInputs() > param_index + 1:
                                        arg_vn_in_caller = call_pcode_op.getInput(param_index + 1) # +1 because input(0) is call target
                                        println_func("  " * (current_inter_depth*2+3) + "[INTER]     Adding to worklist: Arg #%s (%s) in caller %s." % (
                                            param_index, get_varnode_representation(arg_vn_in_caller, caller_hf, caller_func_obj.getProgram()), caller_func_obj.getName()))
                                        worklist.append((caller_hf, arg_vn_in_caller, current_inter_depth + 1, None, None))
                                    else: println_func("  " * (current_inter_depth*2+3) + "[INTER]     Warning: CALL op at %s in %s lacks param index %s (has %s inputs)." % (call_site_addr, caller_func_obj.getName(), param_index, call_pcode_op.getNumInputs()))
                                else: println_func("  " * (current_inter_depth*2+3) + "[INTER]     Warning: No matching CALL PcodeOp found at %s in %s for target %s." % (call_site_addr, caller_func_obj.getName(), callee_func_obj.getName()))
                            else: println_func("  " * (current_inter_depth*2+2) + "[INTER]   Warning: Could not decompile caller %s." % caller_func_obj.getName())
                    
                    if not callers_found_for_this_param:
                        println_func("  " * (current_inter_depth*2+1) + "[INTER] No suitable callers found for param %s in %s. Terminal." % (origin_signal.get("param_name"), callee_func_obj.getName()))
                        master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_NO_CALLERS",
                                                       details=origin_signal.get("details", "") + " (No callers found)."))
                else: # Max inter-procedural depth reached for a parameter
                    println_func("  " * (current_inter_depth*2+1) + "[INTER] Max inter-depth for param %s in %s. Terminal." % (origin_signal.get("param_name"), origin_signal["function_object"].getName()))
                    master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_MAX_INTER_DEPTH",
                                                   details=origin_signal.get("details", "") + " (Max inter-procedural depth reached)."))
            
            elif origin_signal.get("source_type") == "_INTERPROC_HF_INPUT_":
                println_func("  " * (current_inter_depth*2+1) + "[INTER] Direct HighFunction input %s encountered. Terminal for this path." % origin_signal.get("input_varnode_repr"))
                master_origins_list.append(dict(origin_signal, source_type="HIGH_FUNCTION_RAW_INPUT_TERMINAL",
                                               details=origin_signal.get("details", "") + " (Raw HF input, inter-proc trace complex)."))

            elif origin_signal.get("source_type") == "_INTERPROC_MODIFIED_BY_CALL_EFFECT_":
                # This is the new signal indicating current_vn was modified by a CALL's effect.
                # We need to check if current_vn (modified_vn_info) was an argument to that call.
                println_func("  " * (current_inter_depth*2+1) + "[INTER] Variable %s modified by CALL effect. Checking if passed by reference." % origin_signal.get("modified_vn_info", {}).get("repr", "UnknownVar"))
                
                caller_hf_for_effect = current_hf 
                call_op_seq_str_for_effect = origin_signal["call_op_seqnum_str"]
                modified_vn_info_for_effect = origin_signal["modified_vn_info"] 

                call_op_in_caller_for_effect = None
                for op_lookup in caller_hf_for_effect.getPcodeOps():
                    if str(op_lookup.getSeqnum()) == call_op_seq_str_for_effect:
                        call_op_in_caller_for_effect = op_lookup
                        break
                
                if not call_op_in_caller_for_effect:
                    println_func("    Error: Could not re-locate CALL op with seqnum %s in %s" % (call_op_seq_str_for_effect, caller_hf_for_effect.getFunction().getName()))
                    master_origins_list.append(dict(origin_signal, source_type="ERROR_CALL_OP_LOOKUP_FAILED"))
                    continue 
                else:
                    println_func("  " * (current_inter_depth*2+2) + "  Successfully located the CALL PCodeOp: %s" % call_op_in_caller_for_effect)

                found_ref_param_match = False 
                if modified_vn_info_for_effect and modified_vn_info_for_effect.get("is_stack"):
                    target_ghidra_stack_offset = modified_vn_info_for_effect.get("offset")
                    
                    target_var_repr = origin_signal.get("source_value_repr", "UnknownTargetStackVar") 

                    println_func("  " * (current_inter_depth*2+2) + "  Now checking arguments of CALL Op for a match with %s (offset: %#x or decimal %s)" % (
                        target_var_repr, target_ghidra_stack_offset, target_ghidra_stack_offset))

                    for i in range(1, call_op_in_caller_for_effect.getNumInputs()):
                        arg_vn = call_op_in_caller_for_effect.getInput(i)
                        arg_vn_repr = get_varnode_representation(arg_vn, caller_hf_for_effect, current_prog_ref)
                        param_ordinal_for_callee = i - 1

                        println_func("  " * (current_inter_depth*2+3) + "    Checking CALL Argument #%s (Param %s for callee): %s" % (i, param_ordinal_for_callee, arg_vn_repr))

                        temp_arg_vn = arg_vn
                        arg_def_op = temp_arg_vn.getDef()
                        num_copy_unwrap = 0
                        max_copy_unwrap = 3

                        while arg_def_op and arg_def_op.getMnemonic() == "COPY" and num_copy_unwrap < max_copy_unwrap:
                            
                            copied_from_vn = arg_def_op.getInput(0)
                            copied_from_vn_repr = get_varnode_representation(copied_from_vn, caller_hf_for_effect, current_prog_ref)
                            println_func("  " * (current_inter_depth*2+4) + "      Arg #%s is a COPY from %s, unwrapping... Def of copy source: %s" % (
                                i, copied_from_vn_repr, copied_from_vn.getDef() if copied_from_vn else "None"
                            ))
                            if not copied_from_vn:
                                arg_def_op = None; break
                            temp_arg_vn = copied_from_vn
                            arg_def_op = temp_arg_vn.getDef()
                            num_copy_unwrap += 1
                        
                        if arg_def_op and arg_def_op.getMnemonic() in ["INT_ADD", "PTRADD", "PTRSUB"]: 
                            is_ptrsub = arg_def_op.getMnemonic() == "PTRSUB"
                            op_in0 = arg_def_op.getInput(0)
                            op_in1 = arg_def_op.getInput(1)
                            base_vn_of_arg = None
                            raw_pcode_offset_val = None 

                            if op_in1.isConstant():
                                base_vn_of_arg = op_in0
                                raw_pcode_offset_val = op_in1.getOffset()
                            elif op_in0.isConstant() and not is_ptrsub: 
                                base_vn_of_arg = op_in1
                                raw_pcode_offset_val = op_in0.getOffset()
                            
                            if base_vn_of_arg and base_vn_of_arg.isRegister() and raw_pcode_offset_val is not None:
                                base_reg_obj = current_prog_ref.getRegister(base_vn_of_arg.getAddress())
                                base_reg_name_str = base_reg_obj.getName() if base_reg_obj else "Reg@%s" % base_vn_of_arg.getAddress()
                                
                                effective_added_offset = None
                                if is_ptrsub:
                                    
                                    
                                    effective_added_offset = -raw_pcode_offset_val 
                                else: # INT_ADD or PTRADD base, K
                                    effective_added_offset = raw_pcode_offset_val

                                println_func("  " * (current_inter_depth*2+4) + "      Arg #%s defined by %s: BaseReg=%s, RawPCodeOffsetVal=%#x (%s), EffectiveAddedOffset=%#x (%s)" % (
                                    i, arg_def_op.getMnemonic(), base_reg_name_str, 
                                    raw_pcode_offset_val, raw_pcode_offset_val, 
                                    effective_added_offset, effective_added_offset 
                                ))
                                
                               
                                abs_effective_offset = abs(effective_added_offset)
                                abs_target_stack_offset = abs(target_ghidra_stack_offset)

                                println_func("  " * (current_inter_depth*2+5) + "        Target: Var=%s, TargetStackOffset(signed)=%#x (%s)" % (
                                    target_var_repr, target_ghidra_stack_offset, target_ghidra_stack_offset
                                ))
                                println_func("  " * (current_inter_depth*2+5) + "        ABS COMPARISON: abs(EffectiveAddedOffset)=%#x (%s), abs(TargetStackOffset)=%#x (%s)" % (
                                    abs_effective_offset, abs_effective_offset, 
                                    abs_target_stack_offset, abs_target_stack_offset
                                ))

                                
                                if (base_reg_name_str == "sp" or base_reg_name_str == "x29") and \
                                   abs_effective_offset == abs_target_stack_offset:
                                    println_func("  " * (current_inter_depth*2+5) + "      SUCCESSFUL MATCH (abs values): Arg #%s (Base: %s) seems to be the address of %s." % (
                                        i, base_reg_name_str, target_var_repr))
                                    
                                    callee_target_vn = call_op_in_caller_for_effect.getInput(0)
                                    if callee_target_vn.isConstant():
                                
                                        if callee_hf_for_effect:
                                            if current_inter_depth < MAX_BACKWARD_TRACE_DEPTH_INTER:
                                                
                                                task_info_for_callee = {
                                                    "param_ordinal": param_ordinal_for_callee,
                                                    "original_caller_var_repr": target_var_repr
                                                }
                                                worklist.append((callee_hf_for_effect, 
                                                                 "_TRACE_WRITES_TO_PARAM_",
                                                                 current_inter_depth + 1,
                                                                 "_TRACE_WRITES_TO_PARAM_", # special_task marker
                                                                 task_info_for_callee))    # task_info
                                                found_ref_param_match = True
                                                break 
                                # ... (else if max depth reached) ...
                                else:
                                    mismatch_reason = []
                                    if not (base_reg_name_str == "sp" or base_reg_name_str == "x29"):
                                        mismatch_reason.append("BaseReg ('%s') not sp/x29" % base_reg_name_str)
                                    if abs_effective_offset != abs_target_stack_offset:
                                        mismatch_reason.append("AbsOffsets differ (%#x vs %#x)" % (abs_effective_offset, abs_target_stack_offset))
                                    if not mismatch_reason: mismatch_reason.append("Conditions not met")
                                    println_func("  " * (current_inter_depth*2+5) + "        MISMATCH (abs values): %s." % " AND ".join(mismatch_reason))
                            else:
                                println_func("  " * (current_inter_depth*2+4) + "      Arg #%s definition %s (or its source after COPY) does not have a clear register base and constant offset." % (i, arg_def_op))
                        elif arg_def_op:
                            println_func("  " * (current_inter_depth*2+4) + "      Arg #%s definition %s is not an INT_ADD/PTRADD/PTRSUB (even after unwrapping COPYs)." % (i, arg_def_op))
                        else:
                            println_func("  " * (current_inter_depth*2+4) + "      Arg #%s (or its source after COPY) has no defining PCode op." % i)
                        
                        if found_ref_param_match: 
                            break
                    
                    if not found_ref_param_match:
                        println_func("  " * (current_inter_depth*2+3) + "    No by-reference argument match found (using abs offset comparison) after checking all %s arguments for %s." % (
                            call_op_in_caller_for_effect.getNumInputs() -1 if call_op_in_caller_for_effect.getNumInputs() >0 else 0, 
                            target_var_repr ))
                        master_origins_list.append(origin_signal) 
                else: 
                    println_func("  " * (current_inter_depth*2+2) + "  Skipping by-reference check because 'modified_vn_info_for_effect' is not a stack variable or is missing.")
                    master_origins_list.append(origin_signal)

    
    # Deduplicate final results (simple deduplication based on a tuple of key fields)
    final_deduplicated_origins = []
    seen_reprs_final = set()
    for res in master_origins_list:
        # Create a representative tuple for the result to check for duplicates
        # Adjust fields as necessary for meaningful deduplication
        repr_key_tuple = (res.get("address", "N/A"), res.get("pcode_op_str", "N/A"), 
                          res.get("source_type", "Unknown"), res.get("source_value_repr", "N/A"),
                          res.get("function_name", "N/A"), res.get("details", "")) # Details can make it too unique
        if repr_key_tuple not in seen_reprs_final:
            final_deduplicated_origins.append(res)
            seen_reprs_final.add(repr_key_tuple)
            
    return final_deduplicated_origins

# --- Helper functions for Phase 1 (from original STR_Analyzer.py) ---
def get_register_name_from_varnode_phase1(varnode, current_program_ref): # Added current_program_ref
    if varnode is not None and varnode.isRegister():
        reg = current_program_ref.getRegister(varnode.getAddress())
        if reg is not None:
            return reg.getName()
    return None

def get_add_components_generic(add_op, high_func_ctx, current_program_ref): # Takes current_program_ref now
    if add_op is None or add_op.getOpcode() != PcodeOp.INT_ADD:
        return None, None, None
    input0 = add_op.getInput(0)
    input1 = add_op.getInput(1)
    offset_val = None
    base_val_vn = None

    if input1.isConstant():
        offset_val = input1.getOffset()
        base_val_vn = input0
    elif input0.isConstant():
        offset_val = input0.getOffset()
        base_val_vn = input1
    
    if base_val_vn is None or offset_val is None:
        return None, None, None # Could not determine base and offset
    
    base_name_repr = get_varnode_representation(base_val_vn, high_func_ctx, current_program_ref)
    return base_val_vn, offset_val, base_name_repr

# --- Phase 1: Global Search for STR/STUR Instructions (from original STR_Analyzer.py) ---
def find_specific_str_instructions(target_offset, current_program_ref): # Added current_program_ref
    dprint("Starting Phase 1: Searching for STR/STUR xi, [xj, #0x%x] instructions..." % target_offset)
    found_instructions_info = []
    listing = current_program_ref.getListing() # Use current_program_ref
    instructions = listing.getInstructions(True) # Get all instructions

    for instr_idx, instr in enumerate(instructions):
        if monitor.isCancelled(): # Ghidra global 'monitor'
            break
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic == "STR" or mnemonic == "STUR":
            pcode_ops = instr.getPcode() # Get P-code for the instruction
            if pcode_ops is None or len(pcode_ops) == 0:
                continue
            
            # Find the STORE P-code op
            store_op = None
            store_op_pcode_index = -1 # To help find defs of unique inputs if needed
            for p_op_idx, p_op in enumerate(pcode_ops):
                if p_op.getOpcode() == PcodeOp.STORE:
                    store_op = p_op
                    store_op_pcode_index = p_op_idx
                    break

            if store_op is not None and store_op.getNumInputs() == 3: # STORE space, offset, value
                value_stored_vn = store_op.getInput(2) # This is xi
                address_calculation_vn = store_op.getInput(1) # This leads to xj + offset

                # Filter out stores of zero (XZR/WZR or constant 0)
                is_zero_store = False
                value_stored_reg_name = get_register_name_from_varnode_phase1(value_stored_vn, current_program_ref) # Pass program

                if value_stored_reg_name in ["xzr", "wzr"]: # ARM64 zero registers
                    is_zero_store = True
                else: # Check if it's a COPY from a constant 0
                    val_def_op = value_stored_vn.getDef()
                    # If unique and no direct def, look back in instruction's pcode list (simple heuristic)
                    if val_def_op is None and value_stored_vn.isUnique():
                        for k_val in range(store_op_pcode_index - 1, -1, -1): # Look backwards from STORE
                            prev_op_val = pcode_ops[k_val]
                            if prev_op_val.getOutput() is not None and prev_op_val.getOutput().equals(value_stored_vn):
                                val_def_op = prev_op_val; break
                    
                    if val_def_op is not None and val_def_op.getOpcode() == PcodeOp.COPY:
                        copied_from_vn = val_def_op.getInput(0)
                        if copied_from_vn.isConstant() and copied_from_vn.getOffset() == 0:
                            is_zero_store = True
                            value_stored_reg_name = "xzr_via_copy" # For logging
                if is_zero_store:
                    continue # Skip stores of zero

                # Analyze the address calculation part: should be INT_ADD(base_reg, immediate_offset)
                addr_def_op = address_calculation_vn.getDef()
                if addr_def_op is None and address_calculation_vn.isUnique(): # Try to find def for unique address varnode
                     for k_addr in range(store_op_pcode_index - 1, -1, -1):
                        prev_op_addr = pcode_ops[k_addr]
                        if prev_op_addr.getOutput() is not None and prev_op_addr.getOutput().equals(address_calculation_vn):
                            addr_def_op = prev_op_addr; break
                
                if addr_def_op is not None and addr_def_op.getOpcode() == PcodeOp.INT_ADD:
                    # Get base register and immediate value from INT_ADD
                    base_reg_vn_raw, imm_val_raw, base_reg_name_raw = get_add_components_generic(addr_def_op, None, current_program_ref) # Pass program
                    
                    if base_reg_vn_raw is not None and imm_val_raw == target_offset:
                        # Filter out SP-based stores if needed (often less interesting for this type of analysis)
                        if base_reg_name_raw == "sp": # Check if base_reg_name_raw (string) is "sp"
                            continue 
                            
                        final_xi_name_for_log = value_stored_reg_name if value_stored_reg_name else get_varnode_representation(value_stored_vn, None, current_program_ref)
                        # Store raw address of base register if it's a register, for later matching in HF if needed
                        raw_base_reg_addr_for_phase2 = base_reg_vn_raw.getAddress() if base_reg_vn_raw.isRegister() else None

                        found_instructions_info.append({
                            "address": instr.getAddress(), "instr_obj": instr,
                            "xi_varnode_raw": value_stored_vn, # Keep the raw varnode for Phase 2 HF re-mapping
                            "xi_reg_name_log": final_xi_name_for_log, # For logging
                            "xj_reg_name_raw_log": base_reg_name_raw, # For logging
                            "raw_base_reg_addr": raw_base_reg_addr_for_phase2, # Physical address of base reg
                            "offset": imm_val_raw
                        })
    
    if found_instructions_info:
        print("\nPhase 1 Complete: Found %d matching STR/STUR instructions (after all filtering):" % len(found_instructions_info))
        for item in found_instructions_info:
            print("  - Address: %s, Instruction: %s (Storing %s from base %s + #0x%x)" % \
                  (item["address"], item["instr_obj"].toString(), item["xi_reg_name_log"], item["xj_reg_name_raw_log"], item["offset"]))
    else:
        print("\nPhase 1 Complete: No STR/STUR instructions matching criteria found with offset 0x%x." % target_offset)
    return found_instructions_info

# --- Helper function to find effective defining op for an address (from original STR_Analyzer.py) ---
def get_effective_defining_op_for_address(vn, max_depth=EFFECTIVE_ADDR_MAX_DEPTH):
    current_vn = vn
    current_def_op = vn.getDef()
    for i in range(max_depth): # Limit depth to avoid excessive recursion on complex chains
        if not current_def_op: # No definition
            return current_vn, current_def_op # Return the last known varnode and no op
        
        op_mnemonic = current_def_op.getMnemonic()
        if op_mnemonic == "INT_ADD": # Found the INT_ADD we are typically looking for
            return current_vn, current_def_op
        elif op_mnemonic in ["CAST", "COPY"]: # Look through CAST or COPY
            if current_def_op.getNumInputs() > 0:
                next_vn = current_def_op.getInput(0)
                next_def_op = next_vn.getDef()
                if i < max_depth - 1: # Only continue if not at max depth
                    current_vn = next_vn
                    current_def_op = next_def_op
                    if not current_def_op: # Chain ends
                        return current_vn, None 
                    continue # Continue to next iteration of loop
                else: # Reached max depth while looking through CAST/COPY
                    return next_vn, next_def_op # Return what we found at max depth
            else: # CAST/COPY with no input, unexpected
                return current_vn, current_def_op # Stop here
        else: # Not INT_ADD, CAST, or COPY, so this is the effective defining op
            return current_vn, current_def_op
            
    return current_vn, current_def_op # Return current state if loop finishes (e.g. max_depth reached)

def print_backward_analysis_results(results_list):
    if not results_list:
        print("\nNo definitive origins found for the target variable within the trace depth.")
        return
    print("\n--- Detected Potential Origins/Sources (Backward Trace) ---")
    unique_results_for_print = []
    seen_print_keys = set()

    for res in results_list:
        # Create a more robust key for de-duplication for printing
        # Focusing on essential fields that define uniqueness of an origin point
        print_key = (
            res.get("address", "N/A"),
            res.get("pcode_op_str", "N/A"), # The specific PCodeOp
            res.get("source_type", "Unknown"),
            res.get("source_value_repr", "N/A"), # The value at that point
            res.get("function_name", "N/A")
        )
        if print_key not in seen_print_keys:
            unique_results_for_print.append(res)
            seen_print_keys.add(print_key)

    for i, res in enumerate(unique_results_for_print):
        print("Origin Candidate #%s:" % (i + 1))
        func_name_str = " in function %s" % res.get("function_name") if res.get("function_name") else ""
        print("  PCode Op Address:    %s%s" % (res.get("address", "N/A") + func_name_str, func_name_str))
        print("  Defining PCode Op:   %s" % res.get("pcode_op_str", "N/A"))
        print("  Source Type:         %s" % res.get("source_type", "Unknown"))
        if "source_value_repr" in res:
            print("  Source Value/Var:    %s" % res["source_value_repr"])
        if "details" in res and res["details"]:
            print("  Details:             %s" % res["details"])
        print("-" * 40)

# --- Main execution ---
if __name__ == "__main__":
    # Ghidra script environment provides 'currentProgram' and 'monitor'
    current_program = getCurrentProgram() 

    try:
        print("Starting script with TARGET_OFFSET_FOR_STR_SEARCH = %#x" % TARGET_OFFSET_FOR_STR_SEARCH)
        found_str_instructions = find_specific_str_instructions(TARGET_OFFSET_FOR_STR_SEARCH, current_program)

        if not found_str_instructions:
            print("\nPhase 1 found no relevant STR/STUR instructions. Skipping Phase 2.")
        else:
            print("\nStarting Phase 2: Tracing origin of `xi` for each STR instruction found in Phase 1.")
            for item_idx, item_info in enumerate(found_str_instructions):
                instr_addr = item_info["address"]
                phase1_xi_varnode_raw = item_info["xi_varnode_raw"] # This is from low-level PCode

                print("\n--- Analyzing STR at %s (Instruction %d of %d from Phase 1) ---" % (instr_addr, item_idx + 1, len(found_str_instructions)))
                dprint("  Target STR: %s" % item_info["instr_obj"].toString())
                dprint("  Raw `xi` (from Phase 1 PCode): %s" % item_info["xi_reg_name_log"]) # This is just for logging

                containing_func = getFunctionContaining(instr_addr) # Ghidra API
                if not containing_func:
                    print("  Error: Could not find function containing address %s" % str(instr_addr))
                    continue
                
                # Ensure we use the program context of the function where STR is found
                program_of_containing_func = containing_func.getProgram()
                high_func = get_high_function(containing_func, program_of_containing_func)

                if not high_func:
                    print("  Skipping Phase 2 for STR at %s due to decompilation failure." % instr_addr)
                    continue
                
                # Find the corresponding STORE P-code op in the HighFunction
                # and the Varnode for `xi` within the HighFunction context.
                initial_vn_to_trace_hf = None
                op_iter_hf = high_func.getPcodeOps(instr_addr)
                found_hf_store_op_for_xi = False
                while op_iter_hf.hasNext():
                    hf_pcode_op = op_iter_hf.next()
                    if hf_pcode_op.getOpcode() == PcodeOp.STORE:
                        # Basic check: does this STORE op in HF correspond to our STR?
                        # A more robust check would compare operand structures if Phase1_xi_varnode_raw could be mapped to HF.
                        # For now, assume first STORE at instruction address is the one if multiple exist (rare for single asm).
                        initial_vn_to_trace_hf = hf_pcode_op.getInput(2) # Value stored in HighFunction context
                        dprint("  Located STORE P-code op in HighFunction at address %s: %s" % (instr_addr, hf_pcode_op))
                        dprint("    Taking its input(2) as the value to trace (xi_hf): %s" % get_varnode_representation(initial_vn_to_trace_hf, high_func, program_of_containing_func))
                        found_hf_store_op_for_xi = True
                        break 
                
                if initial_vn_to_trace_hf:
                    dprint("  Starting INTER-PROCEDURAL backward trace for `xi_hf`: %s" % get_varnode_representation(initial_vn_to_trace_hf, high_func, program_of_containing_func))
                    println_for_trace = dprint # Use global dprint
                    
                    all_origins = start_interprocedural_backward_trace(
                        high_func, initial_vn_to_trace_hf, 
                        println_for_trace, program_of_containing_func # Pass program context of the initial trace
                    )
                    print_backward_analysis_results(all_origins)
                elif found_hf_store_op_for_xi: # Store op found, but input(2) was None
                     print("  Error: Located STORE P-code op in HighFunction, but could not extract value to trace (input[2] was None or invalid) for STR at %s." % instr_addr)
                else:
                    print("  Error: No STORE P-code operation found in HighFunction at address %s to analyze." % instr_addr)

    except Exception as e:
        import traceback
        print("Script execution error: %s" % str(e))
        traceback.print_exc()
    finally:
        dispose_decompilers() # Clean up all decompiler interfaces
        print("Script finished.")