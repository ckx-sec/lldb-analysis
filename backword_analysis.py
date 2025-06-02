# Ghidra Python Script - Merged Analysis (STR_Analyzer_Interprocedural_Enhanced_RefParam.py)
# Phase 1: Find specific STR/STUR instructions globally.
# Phase 2: For STRs found, trace the source of the stored value (xi)
#          using inter-procedural backward taint tracing, with enhanced
#          stack load analysis and new handling for by-reference parameters.
#          Includes forward scan for vtable pointer after object allocation.
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
TARGET_OFFSET_FOR_STR_SEARCH = 0x1d0 # For Phase 1 STR/STUR search
MAX_BACKWARD_TRACE_DEPTH_INTRA = 15  # Max depth for intra-procedural trace legs (Increased for deeper vtable related traces)
MAX_BACKWARD_TRACE_DEPTH_INTER = 5  # Max depth for inter-procedural jumps (Increased)
ENABLE_DEBUG_PRINTS = True        # Global debug print flag

KNOWN_ALLOCATOR_FUNCTIONS = ["operator.new", "malloc", "_Znwm", "_Znam", "_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t"] # Added common C++ new mangled names
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
        options = DecompileOptions()
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
    ifc = get_decompiler(current_program_ref)

    if func_obj.isExternal():
        # Try to get thunked function even for externals, might resolve to an internal stub
        thunked_func_for_external = func_obj.getThunkedFunction(True)
        if thunked_func_for_external is not None and not thunked_func_for_external.equals(func_obj) and not thunked_func_for_external.isExternal():
            dprint("External function %s in %s is thunk to internal %s in %s. Using thunked." % (
                func_obj.getName(), current_program_ref.getName(),
                thunked_func_for_external.getName(), thunked_func_for_external.getProgram().getName()
            ))
            return get_high_function(thunked_func_for_external, thunked_func_for_external.getProgram())
        # If it's an allocator name, we might still want to process its PCodeOp if it's a CALL to it.
        if func_obj.getName() in KNOWN_ALLOCATOR_FUNCTIONS:
            dprint("Function %s in program %s is an external allocator. P-code for CALLs to it will be analyzed." % (func_obj.getName(), current_program_ref.getName()))
            # We can't decompile it, but the CALL op itself is what matters for allocators.
            # The check for allocators will happen based on the PCodeOp's target.
            return None # Cannot get HighFunction for true external
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
        decompile_options = ifc.getOptions() 
        if decompile_options is not None:
             timeout_seconds = decompile_options.getDefaultTimeout() 
        else:
            dprint("Warning: Decompiler options (ifc.getOptions()) for %s returned None. Using hardcoded timeout of %s seconds." % (current_program_ref.getName(), timeout_seconds))

        results = ifc.decompileFunction(func_obj, timeout_seconds, monitor) 
        if results is not None and results.getHighFunction() is not None:
            return results.getHighFunction()
        else:
            err_msg = results.getErrorMessage() if results and results.getErrorMessage() else "Decompilation returned no HighFunction."
            # printerr function is not defined here, use print
            print("Warning: Could not decompile function %s in program %s. Reason: %s" % (func_obj.getName(), current_program_ref.getName(), err_msg))
            return None
    except Exception as e:
        print("Exception during decompilation of %s in program %s: %s" % (func_obj.getName(), current_program_ref.getName(), str(e)))
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
                elif str(type(actual_high_var_target)) == "<type 'ghidra.program.model.pcode.HighOther'>": 
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
        
        sub_trace_visited_intra = {} # Fresh for this specific value trace from STORE
        origins = trace_variable_origin_backward_recursive(
            high_func, value_stored_vn,
            0, max_intra_depth, # Start fresh intra-depth for this value
            sub_trace_visited_intra, # Fresh intra-visited set
            current_inter_depth, max_inter_depth, global_visited_interproc_states, # Pass inter-proc context
            println_func, current_program_ref, None # Pass None for original_target_info
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
    println_func, current_program_ref,
    original_target_info # New parameter to pass context for vtable search
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
                "details": "Parameter '%s' of function %s." % (param_name, high_func.getFunction().getName()),
                "function_name": high_func.getFunction().getName(),
                "original_target_info": original_target_info
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
                "details": "Direct HighFunction input in %s." % high_func.getFunction().getName(),
                "function_name": high_func.getFunction().getName(),
                "original_target_info": original_target_info
            })
            return origins
        elif current_vn.isPersistant() or current_vn.isAddrTied(): # Check for globals
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

    # Recursive calls for inputs
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
                next_intra_depth, max_intra_depth, # Pass current intra depth for recursive calls from find_prior_stores
                current_inter_depth, max_inter_depth, global_visited_interproc_states, # Pass inter context
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
                    "details": "Modified by indirect effect of call to: %s. (Original var: %s)." % (
                        call_target_vn_repr, current_vn_repr),
                    "original_target_info": original_target_info
                }))
                return origins # Let manager handle this complex case.
            else: # Indirect effect from non-call op
                origins.append(dict(source_op_details_base, **{
                    "pcode_op_str": str(actual_effect_op), "address": actual_effect_op.getSeqnum().getTarget().toString(),
                    "source_type": "COMPLEX_INDIRECT_EFFECT_FROM_%s" % actual_effect_op_mnemonic, 
                    "details": details_indirect,
                    "original_target_info": original_target_info
                }))

        else: # Could not resolve PCodeOp for indirect effect
            origins.append(dict(source_op_details_base, **{
                "source_type": "UNHANDLED_INDIRECT_EFFECT_RESOLUTION_FAILURE", 
                "details": "Could not resolve PCodeOp for indirect effect (ref_key: %#x at %s)." % (
                    effect_op_ref_vn.getOffset() if effect_op_ref_vn.isConstant() else -1, 
                    defining_op.getSeqnum().getTarget().toString()),
                "original_target_info": original_target_info
            }))

    elif op_mnemonic in ["CALL", "CALLIND"]:
        # This handles cases where current_vn is the *direct output* of a call.
        call_target_vn = defining_op.getInput(0)
        # TODO: Similar to INDIRECT from CALL, if this output corresponds to a by-ref argument
        # that was modified, we might want to trace into the callee.
        # For now, this is a terminal point for this specific path.
        origins.append(dict(source_op_details_base, **{
            "source_type": "FUNCTION_CALL_OUTPUT",
            "details": "Output of call to target: %s" % get_varnode_representation(call_target_vn, high_func, current_program_ref),
            "original_target_info": original_target_info
        }))

    elif op_mnemonic in ["COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT_NEGATE", "INT_2COMP", "BOOL_NEGATE", "POPCOUNT",
                         "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND",
                         "INT2FLOAT", "FLOAT2INT", "SUBPIECE"]: # Unary or effectively unary for data flow
        input_vn = defining_op.getInput(0)
        if input_vn:
            origins.extend(trace_variable_origin_backward_recursive(high_func, input_vn, next_intra_depth, max_intra_depth,
                                                                   visited_intra_vns, current_inter_depth, max_inter_depth,
                                                                   global_visited_interproc_states, println_func, current_program_ref,
                                                                   original_target_info))
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
                                                                        global_visited_interproc_states, println_func, current_program_ref,
                                                                        original_target_info))
    else: # Unhandled PCodeOp
        inputs_repr = [get_varnode_representation(defining_op.getInput(j), high_func, current_program_ref) for j in range(defining_op.getNumInputs())]
        origins.append(dict(source_op_details_base, **{
            "source_type": "UNHANDLED_PCODE_OP",
            "details": "PCodeOp %s is not specifically handled. Inputs: %s" % (op_mnemonic, inputs_repr),
            "original_target_info": original_target_info
        }))

    # --- Allocator Check ---
    if op_mnemonic == "CALL" or op_mnemonic == "CALLIND":
        call_target_vn = defining_op.getInput(0)
        called_function_name = None
        called_function_obj = None # Store the Function object if resolved
        is_known_allocator = False

        # Revised logic to get function address and name
        func_addr = call_target_vn.getAddress()
        if func_addr and func_addr.isMemoryAddress():
            # dprint(trace_prefix + "  Call target is direct address: %s" % func_addr)
            func_at_addr = current_program_ref.getFunctionManager().getFunctionAt(func_addr)
            dprint(trace_prefix + "    Raw func_at_addr object: %s" % func_at_addr) # New debug print
            if func_at_addr:
                raw_name = func_at_addr.getName()
                dprint(trace_prefix + "    Raw func_at_addr.getName(): %s" % raw_name) # New debug print
                dprint(trace_prefix + "    func_at_addr.isExternal(): %s" % func_at_addr.isExternal()) # New debug print
                dprint(trace_prefix + "    func_at_addr.isThunk(): %s" % func_at_addr.isThunk()) # New debug print
                called_function_name = raw_name
                called_function_obj = func_at_addr
                # dprint(trace_prefix + "    Resolved function at address: %s" % called_function_name)
            # else:
                # dprint(trace_prefix + "    No function symbol found at address: %s." % func_addr)
        # Fallback for constant varnodes if the above doesn't catch it (e.g., some specific types of constants)
        # or if it's an imported symbol represented by a constant offset in an external space.
        elif call_target_vn.isConstant(): 
            # This case might be less common for direct calls like (ram, addr, size) but good to keep for other consts.
            const_addr = call_target_vn.getAddress() # This might be an offset in a different space
            if const_addr:
                # dprint(trace_prefix + "  Call target is constant (type 2): %s" % const_addr)
                func_at_addr = current_program_ref.getFunctionManager().getFunctionAt(const_addr)
                if func_at_addr:
                    called_function_name = func_at_addr.getName()
                    called_function_obj = func_at_addr
                    # dprint(trace_prefix + "    Resolved function at constant address: %s" % called_function_name)
        else:
            # dprint(trace_prefix + "  Call target VN %s is not a direct memory address or resolvable constant." % call_target_vn)
            pass
        
        # Debug print before allocator check
        dprint(trace_prefix + "  Evaluating CALL to: %s (Name: %s, AddrFromVN: %s, VN: %s)" % (
            op_mnemonic, 
            called_function_name if called_function_name else "<UnknownName>",
            func_addr.toString() if func_addr else (call_target_vn.getAddress().toString() if call_target_vn.getAddress() else "<NoAddressFromVN>"), # More detailed address log
            call_target_vn
            ))

        if called_function_name:
            if called_function_name in KNOWN_ALLOCATOR_FUNCTIONS:
                is_known_allocator = True
            else:
                if any(mangled_name == called_function_name for mangled_name in KNOWN_ALLOCATOR_FUNCTIONS if called_function_name.startswith("_Z")):
                    is_known_allocator = True
                # elif called_function_name.lower().startswith("malloc") or called_function_name.lower().startswith("new") or called_function_name.lower().startswith("alloc") :
                    # dprint(trace_prefix + "    WARN: Call target '%s' matches broad allocator pattern but not in KNOWN_ALLOCATOR_FUNCTIONS. Consider adding if it is an allocator." % called_function_name)
                    # pass # Not treating as known allocator unless explicitly in list or specific mangled pattern

        if is_known_allocator:
            println_func(trace_prefix + "Allocator Call Found: %s to %s" % (op_mnemonic, called_function_name))
            origins.append(dict(source_op_details_base, **{
                "source_type": "_OBJECT_ALLOCATION_SITE_",
                "details": "Call to known allocator function %s" % called_function_name,
                "object_ptr_hv": current_vn.getHigh(),      # HighVariable of the allocated pointer (output of CALL)
                "allocator_call_op": defining_op,          # The PcodeOp of the CALL itself
                "function_where_allocated": high_func,     # The HighFunction where this allocation happened
                "original_target_info": original_target_info
            }))
    return origins


# --- Inter-procedural Trace Manager ---
def start_interprocedural_backward_trace(initial_hf, initial_vn_to_trace, println_func, current_program_ref_of_initial_trace, initial_target_details_for_report):
    master_origins_list = []
    global_visited_interproc_states = set()
    
    # original_target_info is a dictionary that can be passed through the trace
    # It should contain details about the very first variable/STR we are analyzing
    # e.g., {"str_address": "0x...", "str_instr": "...", "initial_xi_repr": "..."}
    initial_original_target_info = {"str_address": initial_target_details_for_report.get("str_address", "N/A"),
                                    "str_instr": initial_target_details_for_report.get("str_instr", "N/A"),
                                    "initial_xi_repr": get_varnode_representation(initial_vn_to_trace, initial_hf, current_program_ref_of_initial_trace)
                                   }
    
    worklist = [(initial_hf, initial_vn_to_trace, 0, None, None, initial_original_target_info)] 
    
    processed_count = 0
    while worklist:
        processed_count += 1
        if monitor.isCancelled(): dprint("Inter-procedural trace cancelled.")
        
        # Unpack original_target_info_for_current_item from worklist
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
                               def_op.getSeqnum().getTime() if def_op else -1, 
                               current_vn.getOffset())
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
            println_func("  " * (current_inter_depth * 2) + "[INTER] Globally skipping already processed state (func, vn_key_with_orig_target_context): %s" % str(current_processing_key))
            continue
        global_visited_interproc_states.add(current_processing_key)
        
        if special_task == "_TRACE_WRITES_TO_PARAM_":
            param_ordinal_to_check = task_info 
            original_caller_var_repr = "UnknownOriginalVar" 
            if isinstance(task_info, dict): 
                param_ordinal_to_check = task_info.get("param_ordinal")
                original_caller_var_repr = task_info.get("original_caller_var_repr", "UnknownOriginalVar")

            println_func("  " * (current_inter_depth * 2) + "[INTER] Special Task: Tracing writes to param #%s in %s (orig_var: %s, initial_target: %s)" % (
                param_ordinal_to_check, current_hf.getFunction().getName(), original_caller_var_repr, original_target_info_for_current_item.get("initial_xi_repr")))

            param_symbol = current_hf.getLocalSymbolMap().getParamSymbol(param_ordinal_to_check)
            if not param_symbol:
                println_func("    Error: Could not get param symbol for ordinal %s in %s" % (param_ordinal_to_check, current_hf.getFunction().getName()))
                master_origins_list.append({"source_type": "ERROR_NO_PARAM_SYMBOL_FOR_WRITE_TRACE", "function_name": current_hf.getFunction().getName(), "details": "Param ordinal %s invalid." % param_ordinal_to_check, "original_target_info": original_target_info_for_current_item})
                continue
            param_hv = param_symbol.getHighVariable()
            if not param_hv:
                 println_func("    Error: Could not get HighVariable for param symbol %s in %s" % (param_symbol.getName(), current_hf.getFunction().getName()))
                 master_origins_list.append({"source_type": "ERROR_NO_PARAM_HV_FOR_WRITE_TRACE", "function_name": current_hf.getFunction().getName(), "details": "Param %s has no HV." % param_symbol.getName(), "original_target_info": original_target_info_for_current_item})
                 continue

            param_vn_rep_in_callee = param_hv.getRepresentative() 

            found_writes = False
            for op_in_callee in current_hf.getPcodeOps():
                if op_in_callee.getMnemonic() == "STORE":
                    store_dest_addr_vn = op_in_callee.getInput(1)
                    is_match = False
                    if store_dest_addr_vn.equals(param_vn_rep_in_callee):
                        is_match = True
                    else:
                        def_of_store_addr = store_dest_addr_vn.getDef()
                        if def_of_store_addr and def_of_store_addr.getMnemonic() == "COPY" and \
                           def_of_store_addr.getInput(0).equals(param_vn_rep_in_callee):
                            is_match = True
                    if is_match:
                        found_writes = True
                        value_stored_vn = op_in_callee.getInput(2)
                        value_stored_repr = get_varnode_representation(value_stored_vn, current_hf, current_prog_ref)
                        println_func("    Found STORE to by-ref param #%s: %s (value: %s)" % (
                            param_ordinal_to_check, op_in_callee, value_stored_repr))
                        
                        # Pass original_target_info_for_current_item to the new worklist item
                        worklist.append((current_hf, value_stored_vn, current_inter_depth, None, 
                                         {"from_by_ref_store_to_param": param_ordinal_to_check, "original_caller_var_repr": original_caller_var_repr},
                                         original_target_info_for_current_item)) 
            if not found_writes:
                 println_func("    No direct STORE operations found writing via param #%s (%s) in %s." % (
                     param_ordinal_to_check, get_varnode_representation(param_vn_rep_in_callee, current_hf, current_prog_ref), current_hf.getFunction().getName()))
                 master_origins_list.append({"source_type": "BY_REF_PARAM_NO_WRITES_FOUND", 
                                            "function_name": current_hf.getFunction().getName(),
                                            "param_name": param_symbol.getName(),
                                            "param_ordinal": param_ordinal_to_check,
                                            "details": "No STOREs found directly using parameter %s as address in %s." % (param_symbol.getName(), current_hf.getFunction().getName()),
                                            "original_target_info": original_target_info_for_current_item})
            continue 

        dprint("\n[INTER-MANAGER] Worklist item #%s: Analyzing VN %s in Func %s (InterDepth %s/%s) for Original Target: %s" % (
            str(processed_count), 
            get_varnode_representation(current_vn, current_hf, current_prog_ref),
            current_hf.getFunction().getName(), 
            str(current_inter_depth), 
            str(MAX_BACKWARD_TRACE_DEPTH_INTER),
            original_target_info_for_current_item.get("initial_xi_repr")
        ))

        visited_intra_vns_for_this_call = {} 
        
        intra_origins_and_signals = trace_variable_origin_backward_recursive(
            current_hf, current_vn, 
            0, MAX_BACKWARD_TRACE_DEPTH_INTRA, 
            visited_intra_vns_for_this_call,
            current_inter_depth, MAX_BACKWARD_TRACE_DEPTH_INTER, 
            global_visited_interproc_states, 
            println_func, current_prog_ref,
            original_target_info_for_current_item
        )

        for origin_signal in intra_origins_and_signals:
            # Ensure original_target_info is part of the origin_signal if not already added by recursive call
            if "original_target_info" not in origin_signal:
                origin_signal["original_target_info"] = original_target_info_for_current_item

            if isinstance(task_info, dict) and task_info.get("from_by_ref_store_to_param") is not None:
                origin_signal["details"] = "Origin via by-ref param #%s: %s. %s" % (
                    task_info["from_by_ref_store_to_param"], 
                    task_info.get("original_caller_var_repr", ""),
                    origin_signal.get("details", ""))
                origin_signal["source_type"] += "_VIA_BY_REF_PARAM_STORE"

            if origin_signal.get("source_type", "").startswith("_OBJECT_ALLOCATION_SITE_"):
                println_func("  " * (current_inter_depth*2+1) + "[INTER] Object allocation site detected. Initiating vtable scan.")
                obj_ptr_hv_alloc = origin_signal.get("object_ptr_hv")
                alloc_call_op = origin_signal.get("allocator_call_op")
                func_where_alloc_hf = origin_signal.get("function_where_allocated")
                
                if obj_ptr_hv_alloc and alloc_call_op and func_where_alloc_hf:
                    # Ensure current_prog_ref is correctly passed.
                    # The func_where_alloc_hf comes from the origin_signal, so its program context should be correct.
                    prog_ref_for_vtable_scan = func_where_alloc_hf.getFunction().getProgram()

                    vtable_scan_results = find_and_report_vtable_assignment(
                        obj_ptr_hv_alloc, alloc_call_op, func_where_alloc_hf, # Pass HighFunction
                        original_target_info_for_current_item,
                        println_func, prog_ref_for_vtable_scan # Pass program ref
                    )
                    if vtable_scan_results:
                        master_origins_list.extend(vtable_scan_results)
                    # It's important to also add the allocation site itself to the results
                    master_origins_list.append(origin_signal) 
                else:
                    # Add more detailed error printing here
                    err_details = []
                    if not obj_ptr_hv_alloc: err_details.append("object_ptr_hv is missing")
                    if not alloc_call_op: err_details.append("allocator_call_op is missing")
                    if not func_where_alloc_hf: err_details.append("function_where_allocated is missing")
                    println_func("    Error: Missing data for vtable scan for allocation site: %s. Signal was: %s" % (", ".join(err_details), origin_signal))
                    master_origins_list.append(origin_signal) # Still add the allocation site

            elif origin_signal.get("source_type") == "_INTERPROC_FUNCTION_INPUT_":
                callee_func_obj = origin_signal["function_object"] 
                param_index = origin_signal["param_index"]
                if param_index == -1:
                    master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_UNKNOWN_INDEX", 
                                                   details=origin_signal.get("details", "") + " (Could not determine param ordinal)."))
                    continue
                
                ref_iter = callee_func_obj.getProgram().getReferenceManager().getReferencesTo(callee_func_obj.getEntryPoint())
                callers_found_for_this_param = False
                for ref in ref_iter:
                    caller_func_obj = getFunctionContaining(ref.getFromAddress()) 
                    if caller_func_obj:
                        # Prevent infinite recursion if caller is the same as callee (direct recursion on this path)
                        # This check is simplified; a more robust check would involve the full call stack context if needed.
                        if caller_func_obj.equals(callee_func_obj) and current_inter_depth > 0 : # Allow first call into self, but not deeper
                            println_func("  " * (current_inter_depth*2+3) + "[INTER]     Skipping direct recursive call to self (%s) to avoid loop on param trace." % callee_func_obj.getName())
                            continue

                        callers_found_for_this_param = True
                        caller_hf = get_high_function(caller_func_obj, caller_func_obj.getProgram())
                        if caller_hf:
                            call_pcode_op = None
                            ops_at_call_site = caller_hf.getPcodeOps(ref.getFromAddress())
                            while ops_at_call_site.hasNext():
                                op = ops_at_call_site.next()
                                if op.getMnemonic() in ["CALL", "CALLIND"]:
                                    call_target_vn_op = op.getInput(0)
                                    # Check if the call target matches the callee function's entry point
                                    # For direct calls, target is a constant address.
                                    # For indirect, it's more complex, but this check primarily handles direct.
                                    is_target_match = False
                                    if call_target_vn_op.isConstant() and call_target_vn_op.getAddress().equals(callee_func_obj.getEntryPoint()):
                                        is_target_match = True
                                    # TODO: Add check for indirect calls if needed, though resolving target of CALLIND is harder
                                    
                                    if is_target_match:
                                        call_pcode_op = op; break
                            if call_pcode_op and call_pcode_op.getNumInputs() > param_index + 1: # param_index is 0-based, PCode inputs for args start at 1
                                arg_vn_in_caller = call_pcode_op.getInput(param_index + 1)
                                if current_inter_depth < MAX_BACKWARD_TRACE_DEPTH_INTER:
                                    worklist.append((caller_hf, arg_vn_in_caller, current_inter_depth + 1, None, None, original_target_info_for_current_item))
                                else:
                                    master_origins_list.append(dict(origin_signal, source_type="MAX_INTER_DEPTH_REACHED_AT_CALLER_PARAM",
                                                                   details=origin_signal.get("details","") + " (Max inter-depth for param from %s)" % caller_func_obj.getName()))

                            elif call_pcode_op: # Call op found, but not enough inputs for the param index
                                println_func("  " * (current_inter_depth*2+3) + "[INTER]     Warning: CALL op at %s in %s to %s lacks param index %s (has %s inputs). Op: %s" % (
                                    ref.getFromAddress(), caller_func_obj.getName(), callee_func_obj.getName(), param_index, call_pcode_op.getNumInputs(), call_pcode_op))
                                master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAM_INDEX_OUT_OF_BOUNDS",
                                                               details=origin_signal.get("details","") + " (Caller %s call op has insufficient args for index %s)" % (caller_func_obj.getName(), param_index)))
                            else: # No matching CALL/CALLIND PCodeOp found at reference site
                                println_func("  " * (current_inter_depth*2+3) + "[INTER]     Warning: No CALL/CALLIND PCodeOp found at reference %s in %s to %s for param analysis." % (
                                    ref.getFromAddress(), caller_func_obj.getName(), callee_func_obj.getName()))
                                master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_NO_CALL_OP_AT_SITE",
                                                               details=origin_signal.get("details","") + " (No CALL op at site %s in %s)" % (ref.getFromAddress(), caller_func_obj.getName())))

                        else: # Could not decompile caller
                            println_func("  " * (current_inter_depth*2+3) + "[INTER]     Warning: Could not decompile caller %s." % caller_func_obj.getName())
                            master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_CALLER_DECOMP_FAIL",
                                                           details=origin_signal.get("details","") + " (Caller %s failed decompile)" % caller_func_obj.getName()))
                    
                if not callers_found_for_this_param:
                    master_origins_list.append(dict(origin_signal, source_type="FUNCTION_INPUT_PARAMETER_NO_CALLERS",
                                                   details=origin_signal.get("details", "") + " (No callers found)."))
            elif origin_signal.get("source_type") == "_INTERPROC_HF_INPUT_":
                println_func("  " * (current_inter_depth*2+1) + "[INTER] Direct HighFunction input %s encountered. Terminal for this path." % origin_signal.get("input_varnode_repr"))
                master_origins_list.append(dict(origin_signal, source_type="HIGH_FUNCTION_RAW_INPUT_TERMINAL",
                                               details=origin_signal.get("details", "") + " (Raw HF input, inter-proc trace complex)."))
            elif origin_signal.get("source_type") == "_INTERPROC_MODIFIED_BY_CALL_EFFECT_":
                caller_hf_for_effect = current_hf 
                call_op_seq_str_for_effect = origin_signal["call_op_seqnum_str"]
                modified_vn_info_for_effect = origin_signal["modified_vn_info"] 
                call_op_in_caller_for_effect = None
                for op_lookup in caller_hf_for_effect.getPcodeOps():
                    if str(op_lookup.getSeqnum()) == call_op_seq_str_for_effect:
                        call_op_in_caller_for_effect = op_lookup; break
                
                if call_op_in_caller_for_effect:
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
                                        found_ref_param_match = True
                                        callee_target_vn = call_op_in_caller_for_effect.getInput(0)
                                        target_call_address = callee_target_vn.getAddress()
                                        actual_callee_hf = None ; callee_func_obj = None
                                        if target_call_address is not None and target_call_address.isMemoryAddress():
                                            callee_func_obj = getFunctionAt(target_call_address)
                                            if callee_func_obj: actual_callee_hf = get_high_function(callee_func_obj, callee_func_obj.getProgram())
                                        
                                        if actual_callee_hf:
                                            if current_inter_depth < MAX_BACKWARD_TRACE_DEPTH_INTER:
                                                task_info_for_callee = {
                                                    "param_ordinal": param_ordinal_for_callee,
                                                    "original_caller_var_repr": target_var_repr
                                                }
                                                worklist.append((actual_callee_hf, 
                                                                 "_TRACE_WRITES_TO_PARAM_", 
                                                                 current_inter_depth + 1,  
                                                                 "_TRACE_WRITES_TO_PARAM_", 
                                                                 task_info_for_callee,
                                                                 original_target_info_for_current_item))
                                                println_func("  " * (current_inter_depth*2+6) + "        Added task to trace writes to param #%s in callee %s." % (param_ordinal_for_callee, actual_callee_hf.getFunction().getName()))
                                            else: 
                                                println_func("  " * (current_inter_depth*2+6) + "        Max inter-depth reached. Cannot trace writes into callee %s for %s." % (actual_callee_hf.getFunction().getName(), target_var_repr))
                                                master_origins_list.append(dict(origin_signal, source_type="MAX_INTER_DEPTH_AT_MODIFIED_BY_CALL", details="Max depth tracing writes into callee for " + target_var_repr))
                                        else: 
                                            if callee_func_obj:
                                                println_func("  " * (current_inter_depth*2+6) + "        Could not decompile callee function %s at %s for %s. Cannot trace writes." % (callee_func_obj.getName(),target_call_address, target_var_repr))
                                            elif target_call_address:
                                                println_func("  " * (current_inter_depth*2+6) + "        Could not resolve callee function at %s for %s. Cannot trace writes." % (target_call_address, target_var_repr))
                                            else:
                                                println_func("  " * (current_inter_depth*2+6) + "        Callee target VN %s did not resolve to a callable address." % callee_target_vn)
                                            master_origins_list.append(dict(origin_signal, source_type="MODIFIED_BY_CALL_CALLEE_UNRESOLVED", details="Callee for " +target_var_repr + " not resolved/decompiled."))

                                        break # from argument loop, since we found the matching by-ref param
                                    else: # Mismatch reasons
                                        mismatch_reason = []
                                        if not (base_reg_name_str == "sp" or base_reg_name_str == "x29"):
                                            mismatch_reason.append("BaseReg ('%s') not sp/x29" % base_reg_name_str)
                                        if abs_effective_offset != abs_target_stack_offset:
                                            mismatch_reason.append("Effective/TargetStack Offsets differ (%#x vs %#x)" % (effective_added_offset, target_ghidra_stack_offset))
                                        if not mismatch_reason: mismatch_reason.append("Conditions not met (logic error in mismatch_reason generation or unexpected case)")
                                        println_func("  " * (current_inter_depth*2+5) + "        MISMATCH (signed comparison): %s." % " AND ".join(mismatch_reason))
                                else: # base_vn_of_arg or raw_pcode_offset_val is None or base_vn_of_arg is not register
                                    println_func("  " * (current_inter_depth*2+4) + "      Arg #%s definition %s (or its source after COPY) does not have a clear register base and constant offset pattern." % (i, arg_def_op))
                            elif arg_def_op:
                                println_func("  " * (current_inter_depth*2+4) + "      Arg #%s definition %s is not an INT_ADD/PTRADD/PTRSUB (even after unwrapping COPYs)." % (i, arg_def_op))
                            # else arg_def_op is None (e.g. register input to function), cannot match by offset pattern
                        
                        if not found_ref_param_match: # If loop completes without finding a match
                            master_origins_list.append(origin_signal) # Add original signal if no by-ref param path taken
                    else:
                        master_origins_list.append(origin_signal)
                else: # Could not find the CALL PCodeOp for the effect
                    master_origins_list.append(origin_signal)
            else: # Not an interprocedural signal, just add to master list
                master_origins_list.append(origin_signal)
            
    final_deduplicated_origins = []
    seen_reprs_final = set()
    for res in master_origins_list:
        orig_target_key_part = ()
        if "original_target_info" in res and isinstance(res["original_target_info"], dict) :
            orig_target_key_part = (res["original_target_info"].get("str_address", "N/A"), 
                                    res["original_target_info"].get("initial_xi_repr", "N/A"))

        # Include more fields for robust deduplication, esp. for VTABLE results
        vtable_addr_details_key = res.get("vtable_address_details", "N/A") if res.get("source_type") == "VTABLE_ADDRESS_FOUND" else "N/A_VTABLE"
        
        repr_key_tuple = (res.get("address", "N/A"), res.get("pcode_op_str", "N/A"), 
                          res.get("source_type", "Unknown"), res.get("source_value_repr", "N/A"),
                          res.get("function_name", "N/A"), vtable_addr_details_key) + orig_target_key_part
        
        if repr_key_tuple not in seen_reprs_final:
            final_deduplicated_origins.append(res)
            seen_reprs_final.add(repr_key_tuple)
            
    return final_deduplicated_origins

def print_backward_analysis_results(results_list):
    vtable_addresses = set() 

    for res in results_list:
        if res.get("source_type") == "VTABLE_ADDRESS_FOUND":
            address_value = res.get("resolved_vtable_address_value")
            if address_value is not None:
                try:
                    # Use long for Jython to handle large unsigned 64-bit values correctly
                    # Ensure it's a base type before adding to set for consistent sorting and printing
                    vtable_addresses.add(long(address_value)) 
                except TypeError: 
                    try:
                        # Handle case where it might already be a Java Long or similar that needs .longValue()
                        vtable_addresses.add(long(address_value.longValue()))
                    except Exception as e_conv: # Catch any other conversion error
                         dprint("[PRINT_RESULTS_WARN] Could not convert address_value %s (type %s) to long for printing: %s" % (str(address_value), type(address_value), str(e_conv)))
                except ValueError: # Handle case where conversion to long fails (e.g. non-numeric string, though less likely here)
                     dprint("[PRINT_RESULTS_WARN] Could not convert address_value %s (type %s) to long due to ValueError for printing: %s" % (str(address_value), type(address_value), str(e_conv)))


    if vtable_addresses:
        # Sort numerically, then format as hex
        sorted_addresses = sorted(list(vtable_addresses))
        for addr in sorted_addresses:
            print("0x%x" % addr) # Ensure hex formatting
    # If vtable_addresses is empty, this function prints nothing.

# --- New Helper Function: Resolve Varnode to Constant ---
def resolve_varnode_to_constant(vn_to_resolve, func_hf, current_prog_ref, println_func, max_depth=7, _visited_vns_for_resolve=None):
    """
    Tries to resolve a Varnode to a constant value by tracing its defining P-code ops.
    Handles COPY, CAST, INT_ADD, PTRADD, INT_SUB, PTRSUB. Max_depth prevents excessive recursion.
    _visited_vns_for_resolve is for internal cycle detection during a single resolution attempt.
    """
    if vn_to_resolve is None:
        return None

    # --- Added Detailed Print --- 
    raw_vn_str = vn_to_resolve.toString()
    hv_for_vn = vn_to_resolve.getHigh()
    hv_repr_for_debug = "None" 
    if hv_for_vn:
        # Use the main get_varnode_representation for consistency if possible, 
        # but ensure func_hf and current_prog_ref are available or pass them.
        # For a quick local debug, can just get name and storage.
        hv_name = hv_for_vn.getName() if hv_for_vn.getName() else "UnnamedHighVar"
        try:
            storage_info = hv_for_vn.getStorage().toString() if hv_for_vn.getStorage() else "NoStorage"
            hv_repr_for_debug = "%s(%s)" % (hv_name, storage_info)
        except:
            hv_repr_for_debug = "%s(ErrorGettingStorage)" % hv_name
    
    println_func("      [CONST_RESOLVE_DEBUG] Enter resolve_varnode_to_constant. Raw VN: %s, HV Repr: %s" % (raw_vn_str, hv_repr_for_debug))
    # --- End Detailed Print ---

    if _visited_vns_for_resolve is None:
        _visited_vns_for_resolve = set()

    vn_repr_for_debug = get_varnode_representation(vn_to_resolve, func_hf, current_prog_ref) # Get representation early for all prints

    # Create a unique key for the varnode
    vn_key_tuple_part = None
    if vn_to_resolve.isUnique():
        def_op_key = vn_to_resolve.getDef()
        seq_target_str = "NoDefOp"
        seq_order_val = -2 
        seq_time_val = -2
        if def_op_key: 
            seq_key = def_op_key.getSeqnum()
            seq_target_str = str(seq_key.getTarget()) if seq_key else "NoSeqNum" 
            seq_order_val = seq_key.getOrder() if seq_key else -1
            seq_time_val = seq_key.getTime() if seq_key else -1
        vn_key_tuple_part = ("unique", vn_to_resolve.getOffset(), seq_target_str, seq_order_val, seq_time_val)
    elif vn_to_resolve.getAddress():
        vn_key_tuple_part = ("addr", str(vn_to_resolve.getAddress()), vn_to_resolve.getSize())
    else: 
        if vn_to_resolve.isConstant():
            return vn_to_resolve.getOffset()
        println_func("      [CONST_RESOLVE_DEBUG] Cannot form key for non-addr, non-unique, non-const VN: %s" % vn_repr_for_debug)
        return None 

    current_func_entry_str = str(func_hf.getFunction().getEntryPoint())
    vn_resolution_key = (current_func_entry_str,) + vn_key_tuple_part

    if vn_resolution_key in _visited_vns_for_resolve:
        println_func("      [CONST_RESOLVE_DEBUG] Already visited %s (%s) in this resolution path." % (vn_repr_for_debug, str(vn_resolution_key)))
        return None
    _visited_vns_for_resolve.add(vn_resolution_key)
    
    println_func("      [CONST_RESOLVE_DEBUG] Trying to resolve: %s (Depth: %d, Key: %s)" % (vn_repr_for_debug, max_depth, str(vn_resolution_key)))

    if vn_to_resolve.isConstant():
        println_func("        [CONST_RESOLVE_DEBUG] %s IS a direct Constant: %#x" % (vn_repr_for_debug, vn_to_resolve.getOffset()))
        return vn_to_resolve.getOffset()

    if max_depth <= 0:
        println_func("        [CONST_RESOLVE_DEBUG] Max depth reached for %s." % vn_repr_for_debug)
        return None

    def_op = vn_to_resolve.getDef()
    if def_op is None:
        println_func("        [CONST_RESOLVE_DEBUG] No defining P-code op for %s." % vn_repr_for_debug)
        mem_addr_obj = vn_to_resolve.getAddress()
        # Check if it's a direct RAM-like address (global variable pointer, function pointer, etc.)
        if (mem_addr_obj and mem_addr_obj.isMemoryAddress() and
            not mem_addr_obj.isUniqueAddress() and
            not mem_addr_obj.isRegisterAddress() and
            not mem_addr_obj.isStackAddress() and
            not mem_addr_obj.isConstantAddress()): # Excludes 'const' space, focuses on RAM/Code
            println_func("          [CONST_RESOLVE_DEBUG] %s has no def op, IS a direct memory address: %s. Attempting to read from this address." % (vn_repr_for_debug, mem_addr_obj))
            try:
                val_size = vn_to_resolve.getSize()
                loaded_value = None
                mem = current_prog_ref.getMemory()
                # mem_addr_obj is already a Ghidra Address object

                if val_size == 8: loaded_value = mem.getLong(mem_addr_obj)
                elif val_size == 4: loaded_value = mem.getInt(mem_addr_obj) # & 0xFFFFFFFF
                elif val_size == 2: loaded_value = mem.getShort(mem_addr_obj) # & 0xFFFF
                elif val_size == 1: loaded_value = mem.getByte(mem_addr_obj) # & 0xFF
                else:
                    println_func("            [CONST_RESOLVE_DEBUG] Read from direct memory address %s of unhandled size %d." % (mem_addr_obj, val_size))
                    return None
                println_func("            [CONST_RESOLVE_DEBUG] Read from direct memory address %s (size %d) resolved to value: %#x" % (mem_addr_obj, val_size, loaded_value))
                return loaded_value & 0xFFFFFFFFFFFFFFFF # Ensure 64-bit unsigned
            except Exception as e_mem_direct:
                println_func("            [CONST_RESOLVE_DEBUG] Error reading memory for direct address %s: %s" % (mem_addr_obj, str(e_mem_direct)))
                return None
        println_func("          [CONST_RESOLVE_DEBUG] %s has no def op and is not a resolvable direct memory address (or not a standard RAM address). Returning None." % vn_repr_for_debug)
        return None

    op_mnemonic = def_op.getMnemonic()
    println_func("        [CONST_RESOLVE_DEBUG] Defining op for %s is %s at %s." % (vn_repr_for_debug, op_mnemonic, def_op.getSeqnum().getTarget()))

    if op_mnemonic == "LOAD":
        load_addr_vn = def_op.getInput(1) # Varnode representing the address to load from
        # Input 0 is the space ID, input 1 is the address varnode
        println_func("          [CONST_RESOLVE_DEBUG] %s from LOAD. Tracing load address: %s" % (vn_repr_for_debug, get_varnode_representation(load_addr_vn, func_hf, current_prog_ref)))
        
        resolved_load_addr_const = resolve_varnode_to_constant(load_addr_vn, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve.copy())
        
        if resolved_load_addr_const is not None:
            try:
                load_address_long = long(resolved_load_addr_const)
                ghidra_load_addr = current_prog_ref.getAddressFactory().getDefaultAddressSpace().getAddress(load_address_long)
                val_size = vn_to_resolve.getSize()
                loaded_value = None
                mem = current_prog_ref.getMemory()
                if val_size == 8: loaded_value = mem.getLong(ghidra_load_addr)
                elif val_size == 4: loaded_value = mem.getInt(ghidra_load_addr) # & 0xFFFFFFFF
                elif val_size == 2: loaded_value = mem.getShort(ghidra_load_addr) # & 0xFFFF
                elif val_size == 1: loaded_value = mem.getByte(ghidra_load_addr) # & 0xFF
                else:
                    println_func("            [CONST_RESOLVE_DEBUG] LOAD of unhandled size %d for %s from %#x." % (val_size, vn_repr_for_debug, load_address_long))
                    return None
                println_func("            [CONST_RESOLVE_DEBUG] LOAD from %#x (size %d) resolved to value: %#x" % (load_address_long, val_size, loaded_value))
                return loaded_value & 0xFFFFFFFFFFFFFFFF
            except Exception as e_mem:
                println_func("            [CONST_RESOLVE_DEBUG] Error reading memory for LOAD of %s from %#x: %s" % (vn_repr_for_debug, resolved_load_addr_const, str(e_mem)))
                return None
        else:
            println_func("            [CONST_RESOLVE_DEBUG] LOAD address %s for %s did not resolve to constant." % (get_varnode_representation(load_addr_vn, func_hf, current_prog_ref), vn_repr_for_debug))
            return None
    
    elif op_mnemonic == "INDIRECT":
        # Heuristic: If the varnode defined by INDIRECT is itself a direct memory address,
        # it might mean we need the value AT that address, especially if it's a global.
        if vn_to_resolve.isAddress() and vn_to_resolve.getAddress().isMemoryAddress() and not vn_to_resolve.getAddress().isStackAddress():
            direct_mem_addr = vn_to_resolve.getAddress()
            println_func("          [CONST_RESOLVE_DEBUG] %s from INDIRECT, and is a direct memory address: %s. Attempting direct memory read from this address." % (vn_repr_for_debug, direct_mem_addr))
            try:
                load_address_long = long(direct_mem_addr.getOffset())
                # Determine the size to read. Often, if a global address is used as a value, it's a pointer.
                # We'll use the size of vn_to_resolve itself, defaulting to pointer size (8 for ARM64) if ambiguous.
                read_size = vn_to_resolve.getSize()
                if read_size not in [1, 2, 4, 8]: # Default to 8 for pointers if size is unusual (e.g. from HighOther)
                    println_func("            [CONST_RESOLVE_DEBUG] INDIRECT (address) read for %s had unusual size %d, defaulting to 8." % (vn_repr_for_debug, read_size))
                    read_size = 8 
                
                loaded_value = None
                mem = current_prog_ref.getMemory()

                if read_size == 8: loaded_value = mem.getLong(direct_mem_addr)
                elif read_size == 4: loaded_value = mem.getInt(direct_mem_addr)
                elif read_size == 2: loaded_value = mem.getShort(direct_mem_addr)
                elif read_size == 1: loaded_value = mem.getByte(direct_mem_addr)
                else: # Should be caught by default above
                    println_func("            [CONST_RESOLVE_DEBUG] INDIRECT (address) read of unhandled/defaulted size %d for %s." % (read_size, vn_repr_for_debug))
                    return None
                
                println_func("            [CONST_RESOLVE_DEBUG] INDIRECT (address) read from %s (offset %#x, size %d) resolved to value: %#x" % (direct_mem_addr, load_address_long, read_size, loaded_value))
                return loaded_value & 0xFFFFFFFFFFFFFFFF # Ensure 64-bit unsigned for pointers
            except Exception as e_mem_indirect:
                println_func("            [CONST_RESOLVE_DEBUG] Error reading memory for INDIRECT (address) %s: %s" % (direct_mem_addr, str(e_mem_indirect)))
                return None
        else:
            # Fallback to previous (less effective) INDIRECT handling if the above heuristic doesn't apply
            effect_op_ref_vn = def_op.getInput(1) 
            actual_effect_op = None
            if effect_op_ref_vn.isConstant():
                target_op_ref_offset = effect_op_ref_vn.getOffset()
                # Search within the same instruction as the INDIRECT op (original limited heuristic)
                instr_address_of_indirect = def_op.getSeqnum().getTarget()
                ops_at_instr_addr_iter = func_hf.getPcodeOps(instr_address_of_indirect)
                while ops_at_instr_addr_iter.hasNext():
                    candidate_op = ops_at_instr_addr_iter.next()
                    if candidate_op.getOutput() and candidate_op.getOutput().equals(vn_to_resolve) and candidate_op.getMnemonic() == "LOAD":
                        actual_effect_op = candidate_op
                        break
                    if not actual_effect_op and candidate_op.getSeqnum().getTime() == target_op_ref_offset: # Match by time
                        actual_effect_op = candidate_op 
            
            if actual_effect_op and actual_effect_op.getMnemonic() == "LOAD":
                println_func("          [CONST_RESOLVE_DEBUG] %s from INDIRECT effect of LOAD (fallback heuristic): %s. Tracing this LOAD." % (vn_repr_for_debug, actual_effect_op))
                load_addr_vn_from_indirect = actual_effect_op.getInput(1)
                # (rest of LOAD logic as before)
                resolved_load_addr_const_indirect = resolve_varnode_to_constant(load_addr_vn_from_indirect, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve.copy())
                if resolved_load_addr_const_indirect is not None:
                    try:
                        load_address_long_indirect = long(resolved_load_addr_const_indirect)
                        val_size_indirect = vn_to_resolve.getSize()
                        loaded_value_indirect = None
                        mem_indirect = current_prog_ref.getMemory()
                        if val_size_indirect == 8: loaded_value_indirect = mem_indirect.getLong(current_prog_ref.getAddressFactory().getDefaultAddressSpace().getAddress(load_address_long_indirect))
                        elif val_size_indirect == 4: loaded_value_indirect = mem_indirect.getInt(current_prog_ref.getAddressFactory().getDefaultAddressSpace().getAddress(load_address_long_indirect))
                        # ... (add short and byte if necessary, ensure address creation)
                        else:
                            println_func("            [CONST_RESOLVE_DEBUG] INDIRECT->LOAD (fallback) of unhandled size %d." % val_size_indirect); return None
                        println_func("            [CONST_RESOLVE_DEBUG] INDIRECT->LOAD (fallback) from %#x (size %d) value: %#x" % (load_address_long_indirect, val_size_indirect, loaded_value_indirect))
                        return loaded_value_indirect & 0xFFFFFFFFFFFFFFFF
                    except Exception as e_mem_indirect_fb:
                        println_func("            [CONST_RESOLVE_DEBUG] Error reading memory for INDIRECT->LOAD (fallback): %s" % str(e_mem_indirect_fb)); return None
                else:
                    println_func("            [CONST_RESOLVE_DEBUG] INDIRECT->LOAD (fallback) address %s did not resolve." % get_varnode_representation(load_addr_vn_from_indirect, func_hf, current_prog_ref)); return None
            else:
                println_func("          [CONST_RESOLVE_DEBUG] Could not resolve INDIRECT effect for %s to a LOAD operation using fallback heuristic (actual_effect_op: %s)." % (vn_repr_for_debug, actual_effect_op.getMnemonic() if actual_effect_op else "None"))
                return None

    elif op_mnemonic == "COPY" or op_mnemonic == "CAST":
        input_vn = def_op.getInput(0)
        println_func("          [CONST_RESOLVE_DEBUG] %s from %s. Tracing input: %s" % (op_mnemonic, vn_repr_for_debug, get_varnode_representation(input_vn, func_hf, current_prog_ref)))
        return resolve_varnode_to_constant(input_vn, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve)

    elif op_mnemonic in ["INT_ADD", "PTRADD"]:
        input0_vn = def_op.getInput(0)
        input1_vn = def_op.getInput(1)
        
        # --- Enhanced Debug Prints for ADD/PTRADD inputs ---
        input0_def_op_str = str(input0_vn.getDef()) if input0_vn.getDef() else "None"
        input1_def_op_str = str(input1_vn.getDef()) if input1_vn.getDef() else "None"
        # Use the get_varnode_representation from the script for consistent HighVariable display
        # We are inside resolve_varnode_to_constant, so func_hf and current_prog_ref are in scope.
        vn_being_resolved_repr = get_varnode_representation(vn_to_resolve, func_hf, current_prog_ref)

        println_func("          [CONST_RESOLVE_DEBUG] %s for %s." % (op_mnemonic, vn_being_resolved_repr))
        println_func("              Input0 Raw VN: %s, Def: %s, HV_Rep: %s" % 
                     (input0_vn.toString(), input0_def_op_str, get_varnode_representation(input0_vn, func_hf, current_prog_ref)))
        println_func("              Input1 Raw VN: %s, Def: %s, HV_Rep: %s" % 
                     (input1_vn.toString(), input1_def_op_str, get_varnode_representation(input1_vn, func_hf, current_prog_ref)))
        # --- End Enhanced Debug Prints ---

        val0 = resolve_varnode_to_constant(input0_vn, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve.copy())
        if val0 is not None:
            val1 = resolve_varnode_to_constant(input1_vn, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve.copy())
            if val1 is not None:
                result = (val0 + val1) & 0xFFFFFFFFFFFFFFFF 
                println_func("            [CONST_RESOLVE_DEBUG] %s result for %s: (%#x) + (%#x) = %#x" % (op_mnemonic, vn_being_resolved_repr, val0, val1, result))
                return result
            else:
                println_func("            [CONST_RESOLVE_DEBUG] %s Input1 (%s) for %s did not resolve to constant." % (op_mnemonic, get_varnode_representation(input1_vn, func_hf, current_prog_ref), vn_being_resolved_repr))
        else:
            println_func("            [CONST_RESOLVE_DEBUG] %s Input0 (%s) for %s did not resolve to constant." % (op_mnemonic, get_varnode_representation(input0_vn, func_hf, current_prog_ref), vn_being_resolved_repr))
    
    elif op_mnemonic == "PTRSUB" or op_mnemonic == "INT_SUB": 
        input0_vn = def_op.getInput(0)
        input1_vn = def_op.getInput(1)
        println_func("          [CONST_RESOLVE_DEBUG] %s for %s. Input0: %s, Input1: %s" % (op_mnemonic, vn_repr_for_debug, get_varnode_representation(input0_vn, func_hf, current_prog_ref), get_varnode_representation(input1_vn, func_hf, current_prog_ref)))
        
        val0 = resolve_varnode_to_constant(input0_vn, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve.copy())
        if val0 is not None:
            val1 = resolve_varnode_to_constant(input1_vn, func_hf, current_prog_ref, println_func, max_depth - 1, _visited_vns_for_resolve.copy())
            if val1 is not None:
                if val0 == 0: # If the first operand (val0) is 0
                    result = val1 # The result is the second operand (val1) directly
                    println_func("            [CONST_RESOLVE_DEBUG] %s (0 - X mode) result for %s: %#x (using X directly)" % (op_mnemonic, vn_repr_for_debug, result))
                else: # Otherwise (if val0 is not 0), perform standard subtraction
                    result = (val0 - val1) & 0xFFFFFFFFFFFFFFFF 
                    println_func("            [CONST_RESOLVE_DEBUG] %s (A - B mode) result for %s: (%#x) - (%#x) = %#x" % (op_mnemonic, vn_repr_for_debug, val0, val1, result))
                return result
            else:
                println_func("            [CONST_RESOLVE_DEBUG] %s Input1 (%s) for %s did not resolve to constant." % (op_mnemonic, get_varnode_representation(input1_vn, func_hf, current_prog_ref), vn_repr_for_debug))
        else:
            println_func("            [CONST_RESOLVE_DEBUG] %s Input0 (%s) for %s did not resolve to constant." % (op_mnemonic, get_varnode_representation(input0_vn, func_hf, current_prog_ref), vn_repr_for_debug))
    
    println_func("        [CONST_RESOLVE_DEBUG] Unhandled op %s or non-constant inputs for %s. Returning None." % (op_mnemonic, vn_repr_for_debug) )
    return None

# --- Forward Scan for VTable Pointer Assignment ---
def find_and_report_vtable_assignment(
    obj_ptr_hv, # HighVariable of the object pointer (output of allocator CALL)
    alloc_call_op, # PcodeOp of the allocator CALL
    func_where_alloc_hf, # HighFunction where the allocation occurred
    original_target_info_for_report, # For consistent reporting
    println_func,
    current_prog_ref_of_alloc_func # Program reference for the allocator function's context
    ):
    vtable_results = []
    obj_ptr_direct_vn = obj_ptr_hv.getRepresentative() if obj_ptr_hv else None

    if not obj_ptr_direct_vn:
        println_func("      [VTABLE_SCAN] Error: Object pointer HighVariable %s has no representative Varnode. Cannot scan." % (obj_ptr_hv.getName() if obj_ptr_hv else "UnknownObjHV"))
        return vtable_results

    println_func("      [VTABLE_SCAN] Initiated for object pointer HV: %s (Initial Rep VN: %s) in function %s, starting after CALL op at Seq: %s" % (
        get_varnode_representation(obj_ptr_hv, func_where_alloc_hf, current_prog_ref_of_alloc_func),
        get_varnode_representation(obj_ptr_direct_vn, func_where_alloc_hf, current_prog_ref_of_alloc_func),
        func_where_alloc_hf.getFunction().getName(),
        alloc_call_op.getSeqnum()
    ))

    # --- Start of new recursive vtable scan logic ---
    return scan_for_vtable_store_recursive(obj_ptr_hv, alloc_call_op.getSeqnum(), func_where_alloc_hf, 
                                           original_target_info_for_report, println_func, 
                                           current_prog_ref_of_alloc_func, 0) # Start with depth 0

# --- Renamed and enhanced recursive vtable scanning function ---
MAX_VTABLE_SCAN_DEPTH = 2 # Max depth for scanning into constructors/initializers

def scan_for_vtable_store_recursive(
    current_obj_ptr_hv, # HighVariable of the object pointer being scanned
    start_after_seqnum, # PcodeOp.SeqNum after which to start scanning (e.g., after allocator or previous relevant op)
    current_scan_hf,    # HighFunction where the scan is currently happening
    original_target_info_for_report,
    println_func,
    current_prog_ref,   # Program reference for the current_scan_hf
    current_depth       # Current recursion depth
    ):
    vtable_results = []
    current_obj_ptr_direct_vn = current_obj_ptr_hv.getRepresentative() if current_obj_ptr_hv else None

    if not current_obj_ptr_direct_vn:
        println_func("      [VTABLE_SCAN_REC depth=%d] Error: Object pointer HV %s has no representative. Cannot scan in %s." % 
                     (current_depth, current_obj_ptr_hv.getName() if current_obj_ptr_hv else "<UnknownHV>", current_scan_hf.getFunction().getName()))
        return vtable_results

    if current_depth > MAX_VTABLE_SCAN_DEPTH:
        println_func("      [VTABLE_SCAN_REC depth=%d] Max scan depth reached for %s in %s. Stopping this path." % 
                     (current_depth, get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref), current_scan_hf.getFunction().getName()))
        return vtable_results

    println_func("      [VTABLE_SCAN_REC depth=%d] Scanning for obj %s in %s, after seq %s" % (
        current_depth, get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref), 
        current_scan_hf.getFunction().getName(), start_after_seqnum
    ))

    equivalent_obj_ptr_vns = {current_obj_ptr_direct_vn}
    # If current_obj_ptr_hv is from a CALL output (like initial allocation), add that output varnode too.
    # This is more relevant for the initial call to this function.
    # For deeper calls, current_obj_ptr_hv will be a parameter.
    obj_def_op = current_obj_ptr_direct_vn.getDef() if current_obj_ptr_direct_vn else None
    if obj_def_op and obj_def_op.getMnemonic() == "CALL" and obj_def_op.getOutput():
         if obj_def_op.getOutput().equals(current_obj_ptr_direct_vn):
            equivalent_obj_ptr_vns.add(obj_def_op.getOutput())
    # Also consider the HighVariable's representative itself if it's different from what might be in equivalent_obj_ptr_vns
    # This set tracks all varnodes that represent our target object pointer in the current function scope.

    ops_iterator = current_scan_hf.getPcodeOps()
    found_start_op = False if start_after_seqnum else True # If no start_after_seqnum, scan from beginning (e.g. in constructor)

    while ops_iterator.hasNext():
        pcode_op = ops_iterator.next()

        if not found_start_op:
            if pcode_op.getSeqnum().equals(start_after_seqnum):
                found_start_op = True
            continue 

        # Track aliases of the object pointer (e.g., x1 = x0 where x0 is obj_ptr)
        current_op_output_vn = pcode_op.getOutput()
        if current_op_output_vn:
            op_mnemonic_alias = pcode_op.getMnemonic()
            if op_mnemonic_alias == "COPY" or op_mnemonic_alias == "CAST":
                input_vn_for_copy_cast = pcode_op.getInput(0)
                if input_vn_for_copy_cast in equivalent_obj_ptr_vns:
                    if current_op_output_vn not in equivalent_obj_ptr_vns:
                        println_func("        [VTABLE_SCAN_REC depth=%d] Adding alias for obj_ptr: %s = %s (%s)" % 
                                     (current_depth, get_varnode_representation(current_op_output_vn, current_scan_hf, current_prog_ref), 
                                      get_varnode_representation(input_vn_for_copy_cast, current_scan_hf, current_prog_ref), op_mnemonic_alias))
                        equivalent_obj_ptr_vns.add(current_op_output_vn)
        
        # 1. Check for direct STORE to offset 0 of the object pointer
        if pcode_op.getMnemonic() == "STORE":
            stored_to_addr_vn = pcode_op.getInput(1) 
            value_stored_vn = pcode_op.getInput(2)   
            base_being_stored_to = None
            offset_from_base = 0 # We are looking for store to offset 0

            # Is it a direct store to one of our known object pointer varnodes?
            if stored_to_addr_vn in equivalent_obj_ptr_vns:
                base_being_stored_to = stored_to_addr_vn
            else:
                # Is it a store to obj_ptr + 0 ?
                addr_def_op = stored_to_addr_vn.getDef()
                if addr_def_op:
                    def_op_mnemonic = addr_def_op.getMnemonic()
                    if def_op_mnemonic == "COPY" and addr_def_op.getInput(0) in equivalent_obj_ptr_vns:
                        base_being_stored_to = addr_def_op.getInput(0)
                    elif def_op_mnemonic in ["INT_ADD", "PTRADD"]:
                        add_in0 = addr_def_op.getInput(0)
                        add_in1 = addr_def_op.getInput(1)
                        if (add_in0 in equivalent_obj_ptr_vns and add_in1.isConstant() and add_in1.getOffset() == 0):
                            base_being_stored_to = add_in0
                        elif (add_in1 in equivalent_obj_ptr_vns and add_in0.isConstant() and add_in0.getOffset() == 0):
                            base_being_stored_to = add_in1
            
            if base_being_stored_to is not None: 
                # This is a STORE to our object pointer (or obj_ptr + 0)
                vtable_ptr_candidate_repr = get_varnode_representation(value_stored_vn, current_scan_hf, current_prog_ref)
                println_func("          [VTABLE_SCAN_REC depth=%d] >>> Potential VTABLE Assignment Found at %s in %s <<<" % 
                             (current_depth, pcode_op.getSeqnum().getTarget(), current_scan_hf.getFunction().getName()))
                println_func("              STORE Op: %s" % pcode_op)
                println_func("              Object Pointer (current scan target HV): %s" % get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref))
                println_func("              Actual Addr_VN in STORE (Input 1): %s" % get_varnode_representation(stored_to_addr_vn, current_scan_hf, current_prog_ref))
                println_func("              VTable Pointer Candidate (raw): %s" % vtable_ptr_candidate_repr)

                resolved_numerical_value = resolve_varnode_to_constant(
                    value_stored_vn, current_scan_hf, current_prog_ref, dprint # Use dprint for const_resolve debug
                )
                println_func("              VTable Pointer Candidate (resolved): %#x" % resolved_numerical_value if resolved_numerical_value is not None else "              VTable Pointer Candidate (resolved): None")
                
                vtable_address_details_str = "Resolved Constant Addr: %#x" % resolved_numerical_value if resolved_numerical_value is not None else "Not a direct constant or resolvable"
                
                vtable_results.append({
                    "source_type": "VTABLE_ADDRESS_FOUND",
                    "address": pcode_op.getSeqnum().getTarget().toString(),
                    "pcode_op_str": str(pcode_op),
                    "function_name": current_scan_hf.getFunction().getName(),
                    "object_instance_repr": get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref),
                    "vtable_pointer_raw_repr": vtable_ptr_candidate_repr,
                    "vtable_address_details": vtable_address_details_str,
                    "resolved_vtable_address_value": resolved_numerical_value,
                    "details": "VTable pointer assigned to object (depth %d)." % current_depth,
                    "original_target_info": original_target_info_for_report,
                    "str_address": original_target_info_for_report.get("str_address"),
                    "str_instr": original_target_info_for_report.get("str_instr"),
                    "initial_xi_repr": original_target_info_for_report.get("initial_xi_repr")
                })
                return vtable_results # Return as soon as the first vtable assignment is found for this object in this function

        # 2. If no direct STORE found yet, check for CALLs that might be constructors/initializers
        if pcode_op.getMnemonic() in ["CALL", "CALLIND"] and not vtable_results:
            # Check if the first argument to the call is our object pointer
            if pcode_op.getNumInputs() > 1:
                first_arg_vn = pcode_op.getInput(1) # Arg0 (often 'this' pointer)
                if first_arg_vn in equivalent_obj_ptr_vns:
                    println_func("        [VTABLE_SCAN_REC depth=%d] Found CALL with obj_ptr as 1st arg: %s at %s in %s" % 
                                 (current_depth, pcode_op, pcode_op.getSeqnum().getTarget(), current_scan_hf.getFunction().getName()))
                    
                    call_target_addr_vn = pcode_op.getInput(0)
                    target_func_obj = None
                    
                    # --- MODIFIED FUNCTION RESOLUTION LOGIC ---
                    target_func_addr = call_target_addr_vn.getAddress() # Directly get the address from the Varnode

                    # Debug prints to understand the call_target_addr_vn
                    println_func("          [VTABLE_SCAN_REC depth=%d] Call Target PCodeOp Input(0) VN: %s" % (current_depth, call_target_addr_vn.toString()))
                    println_func("          [VTABLE_SCAN_REC depth=%d]   VN.isAddress(): %s, VN.isConstant(): %s, VN.isRegister(): %s, VN.isUnique(): %s" % 
                                 (current_depth, call_target_addr_vn.isAddress(), call_target_addr_vn.isConstant(), call_target_addr_vn.isRegister(), call_target_addr_vn.isUnique()))
                    if target_func_addr:
                        println_func("          [VTABLE_SCAN_REC depth=%d]   Extracted Address object: %s (Offset: %#x, Space: %s)" % 
                                     (current_depth, target_func_addr.toString(), target_func_addr.getOffset(), target_func_addr.getAddressSpace().getName()))
                    else:
                        println_func("          [VTABLE_SCAN_REC depth=%d]   call_target_addr_vn.getAddress() returned None." % current_depth)
                    # --- END MODIFIED FUNCTION RESOLUTION LOGIC ---

                    if target_func_addr: # Check if a valid Address object was obtained
                        println_func("          [VTABLE_SCAN_REC depth=%d] Attempting to get function at resolved address %s (from VN %s) in program %s" % 
                                     (current_depth, target_func_addr.toString(), call_target_addr_vn.toString(), current_prog_ref.getName()))
                        target_func_obj = current_prog_ref.getFunctionManager().getFunctionAt(target_func_addr)
                        if not target_func_obj: # Try with getFunctionContaining as a fallback
                            println_func("            [VTABLE_SCAN_REC depth=%d] getFunctionAt failed for %s. Trying getFunctionContaining..." % (current_depth, target_func_addr.toString()))
                            target_func_obj = current_prog_ref.getFunctionManager().getFunctionContaining(target_func_addr)
                            if target_func_obj:
                                println_func("            [VTABLE_SCAN_REC depth=%d] getFunctionContaining succeeded for %s: %s" % (current_depth, target_func_addr.toString(), target_func_obj.getName()))
                    
                    if target_func_obj:
                        # Ensure we are not recursing into the same function if it's a direct call to self (simple check)
                        # A more robust check would involve the full call signature if needed.
                        if target_func_obj.equals(current_scan_hf.getFunction()):
                            println_func("          Skipping recursive call to self %s for vtable scan." % target_func_obj.getName())
                        else:
                            callee_hf = get_high_function(target_func_obj, target_func_obj.getProgram()) # Use target_func_obj's program
                            if callee_hf:
                                first_param_hv_callee = None
                                callee_function_obj = callee_hf.getFunction()
                                callee_prog_ref = callee_function_obj.getProgram() # Program context for the callee

                                param_obj = None
                                if callee_function_obj.getParameterCount() > 0:
                                    param_obj = callee_function_obj.getParameter(0)
                                
                                if param_obj:
                                    println_func("            [VTABLE_SCAN_REC depth=%d] Callee %s: Found param_obj for index 0: %s (Name: %s, Type: %s)" % 
                                         (current_depth, callee_function_obj.getName(), param_obj, param_obj.getName(), param_obj.getDataType().getName()))
                                    
                                    # Attempt 1: Directly from Parameter object's HighVariable
                                    try:
                                        hv = param_obj.getHighVariable()
                                        if hv:
                                            first_param_hv_callee = hv
                                            println_func("              SUCCESS (Method 1): Got HV for %s param 0 via param_obj.getHighVariable(): %s" % 
                                                         (callee_function_obj.getName(), get_varnode_representation(first_param_hv_callee, callee_hf, callee_prog_ref)))
                                    except Exception as e_param_direct:
                                        println_func("              EXCEPTION (Method 1): param_obj.getHighVariable() failed for %s: %s" % (param_obj.getName(), str(e_param_direct)))

                                    # Attempt 2: Via Parameter object's storage
                                    if not first_param_hv_callee:
                                        println_func("              ATTEMPTING (Method 2): Get HV via param storage for %s." % param_obj.getName())
                                        try:
                                            storage = param_obj.getVariableStorage()
                                            if storage and not storage.isBadStorage() and storage.size() > 0:
                                                first_storage_vn = param_obj.getFirstStorageVarnode()
                                                if first_storage_vn:
                                                    hv_from_storage = callee_hf.getHighVariable(first_storage_vn)
                                                    if hv_from_storage:
                                                        first_param_hv_callee = hv_from_storage
                                                        println_func("                  SUCCESS (Method 2): Got HV for %s param 0 via first_storage_vn: %s" % 
                                                                     (callee_function_obj.getName(), get_varnode_representation(first_param_hv_callee, callee_hf, callee_prog_ref)))
                                        except Exception as e_param_storage:
                                            println_func("                EXCEPTION (Method 2): Error getting HV via param storage for %s: %s" % (param_obj.getName(), str(e_param_storage)))
                                    
                                    # Attempt 3: Via Parameter object's symbol
                                    if not first_param_hv_callee:
                                        println_func("              ATTEMPTING (Method 3): Get HV via param symbol for %s." % param_obj.getName())
                                        try:
                                            sym = param_obj.getSymbol()
                                            if sym:
                                                hv_from_sym = sym.getHighVariable()
                                                if hv_from_sym:
                                                    first_param_hv_callee = hv_from_sym
                                                    println_func("                SUCCESS (Method 3): Got HV for %s param 0 via symbol.getHighVariable(): %s" % 
                                                                 (callee_function_obj.getName(), get_varnode_representation(first_param_hv_callee, callee_hf, callee_prog_ref)))
                                        except Exception as e_param_sym:
                                            println_func("                EXCEPTION (Method 3): Error getting HV via param symbol for %s: %s" % (param_obj.getName(), str(e_param_sym)))
                                else: # No param_obj (either count is 0 or getParameter(0) failed)
                                    println_func("            [VTABLE_SCAN_REC depth=%d] Callee %s: No param_obj for index 0 (Count: %d). Will attempt register-based fallback." % 
                                                 (current_depth, callee_function_obj.getName(), callee_function_obj.getParameterCount()))

                                # --- Fallback logic: If all above methods failed for param_obj or if no param_obj from start ---
                                if not first_param_hv_callee:
                                    println_func("            [VTABLE_SCAN_REC depth=%d] All standard methods failed for param 0 HV in %s. Attempting register-based fallback." % 
                                                 (current_depth, callee_function_obj.getName()))
                                    default_first_param_reg_name = "x0" # Common for ARM64
                                    reg_for_fallback = callee_prog_ref.getRegister(default_first_param_reg_name)

                                    if reg_for_fallback:
                                        # Iterate through symbols in the callee's HighFunction to find a parameter symbol matching the register
                                        local_symbols_map = callee_hf.getLocalSymbolMap()
                                        symbols_iterator = local_symbols_map.getSymbols()
                                        found_fallback_hv = False
                                        while symbols_iterator.hasNext():
                                            sym_callee = symbols_iterator.next()
                                            if sym_callee.isParameter():
                                                try:
                                                    storage_callee = sym_callee.getStorage()
                                                    if storage_callee and storage_callee.isRegisterStorage() and storage_callee.getRegister().equals(reg_for_fallback):
                                                        hv_cand = sym_callee.getHighVariable()
                                                        if hv_cand:
                                                            first_param_hv_callee = hv_cand
                                                            println_func("              FALLBACK SUCCESS: Got HV for %s param 0 (via %s symbol '%s'): %s" % 
                                                                         (callee_function_obj.getName(), default_first_param_reg_name, sym_callee.getName(), get_varnode_representation(first_param_hv_callee, callee_hf, callee_prog_ref)))
                                                            found_fallback_hv = True; break
                                                except Exception as e_fallback_sym:
                                                    println_func("              FALLBACK EXCEPTION iterating symbol '%s': %s" % (sym_callee.getName(), str(e_fallback_sym)))
                                        if not found_fallback_hv:
                                             println_func("              FALLBACK FAILED: Could not find HighVariable for register %s in %s via parameter symbols." % (default_first_param_reg_name, callee_function_obj.getName()))
                                    else:
                                        println_func("              FALLBACK FAILED: Register '%s' not found in program %s. Cannot attempt fallback." % (default_first_param_reg_name, callee_prog_ref.getName()))
                                # --- End Fallback Logic ---

                                if first_param_hv_callee:
                                    println_func("          [VTABLE_SCAN_REC depth=%d] ==> Recursing into callee %s with param HV %s" % 
                                                 (current_depth, callee_hf.getFunction().getName(), get_varnode_representation(first_param_hv_callee, callee_hf, target_func_obj.getProgram())))
                                    recursive_results = scan_for_vtable_store_recursive(
                                        first_param_hv_callee, None, callee_hf, 
                                        original_target_info_for_report, println_func, 
                                        target_func_obj.getProgram(), current_depth + 1
                                    )
                                    if recursive_results: # If results found in callee, extend and return immediately
                                        println_func("            [VTABLE_SCAN_REC depth=%d] Results found in recursive call to %s. Returning them." % (current_depth, callee_hf.getFunction().getName()))
                                        vtable_results.extend(recursive_results)
                                        return vtable_results # Crucial: if found in callee, we are done for this path.
                                    else:
                                        println_func("            [VTABLE_SCAN_REC depth=%d] No results from recursive call to %s." % (current_depth, callee_hf.getFunction().getName()))
                                else:
                                    # This log is for when first_param_hv_callee is None *before* attempting recursion
                                    println_func("          [VTABLE_SCAN_REC depth=%d] FAILED to get HighVariable for first param of %s. Cannot recurse for this call." % (current_depth, callee_hf.getFunction().getName() if callee_hf else target_func_obj.getName()))
                            else:
                                println_func("          [VTABLE_SCAN_REC depth=%d] Could not decompile callee %s for recursive vtable scan." % (current_depth, target_func_obj.getName()))
                    else: # target_func_obj is None
                        println_func("          [VTABLE_SCAN_REC depth=%d] Could not resolve target function for CALL %s at %s." % (current_depth, pcode_op, pcode_op.getSeqnum().getTarget()))

    # This message should only appear if no direct STORE and no fruitful recursive calls occurred from this function level
    if not vtable_results:
        println_func("      [VTABLE_SCAN_REC depth=%d] FINAL: No vtable assignment found for object %s in %s (after seq %s, and any recursive calls from here)." % (
            current_depth,
            get_varnode_representation(current_obj_ptr_hv, current_scan_hf, current_prog_ref),
            current_scan_hf.getFunction().getName(),
            start_after_seqnum if start_after_seqnum else "<start>"
        ))
    return vtable_results

# --- Helper functions for Phase 1 (from original STR_Analyzer.py) ---
def get_register_name_from_varnode_phase1(varnode, current_program_ref): # Added current_program_ref
    if varnode is not None and varnode.isRegister():
        reg = current_program_ref.getRegister(varnode.getAddress())
        if reg is not None:
            return reg.getName()
    return None

def get_add_components_generic(add_op, high_func_ctx, current_program_ref): # Takes current_program_ref now
    if add_op is None or add_op.getOpcode() != PcodeOp.INT_ADD: # Should be PcodeOp.INT_ADD not .ADD
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
        return None, None, None
    
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
                value_stored_vn = store_op.getInput(2) # This is xi from P-code
                address_calculation_vn = store_op.getInput(1) # This leads to xj + offset

                # Parse the instruction string to get the first operand as it appears in assembly
                instruction_text = instr.toString() # e.g., "str w8, [x25, #0x1d0]"
                mnemonic_str = instr.getMnemonicString() # e.g., "str"
                first_operand_str = None
                
                # Find the part after the mnemonic
                if instruction_text.startswith(mnemonic_str):
                    operands_part = instruction_text[len(mnemonic_str):].lstrip() # "w8, [x25, #0x1d0]"
                    
                    # The first operand is before the first comma or opening bracket
                    comma_index = operands_part.find(',')
                    # For STR/STUR, the memory operand usually starts with [, but some assemblers might not have a space
                    # We are interested in the token before this memory operand delimiter.
                    # Common delimiters for the end of the first operand in STR-like instructions:
                    # 1. A comma separating it from the memory operand part
                    # 2. The opening bracket of the memory operand if there's no comma (less common for STR on ARM64 but good to consider)
                    
                    end_delimiters = []
                    if comma_index != -1:
                        end_delimiters.append(comma_index)
                    
                    # Consider a simple split by comma first, as it's most common for STR Rt, [Rn, offset]
                    # If a comma exists, the first part is our operand.
                    if comma_index != -1:
                        first_operand_str = operands_part[:comma_index].rstrip()
                    else:
                        # If no comma (unusual for standard STR syntax but to be safe),
                        # and if it's a simple instruction, the whole operands_part might be the first operand.
                        # However, for STR/STUR, a comma is expected before the memory operand.
                        # This fallback might be more relevant for non-STR instructions if this logic were generalized.
                        # For STR/STUR, if no comma, something is unusual, or it might be a variant this parsing doesn't cover perfectly.
                        # For robustness, let's assume if no comma, the operand part might be just the register if it's simple.
                        # A more robust way for non-comma cases might be needed if such STR variants exist.
                        # For now, primary focus on comma separation for STR/STUR.
                        pass # Let first_operand_str remain None if no comma, as STR/STUR typically have it.

                # Filter 1: Stores of zero (XZR/WZR or constant 0)
                is_zero_store = False
                if first_operand_str is not None and first_operand_str.lower() in ["xzr", "wzr"]: # Case-insensitive check
                    is_zero_store = True
                else: # If not directly xzr/wzr by name, check if p-code value_stored_vn is a COPY of constant 0
                    val_def_op = value_stored_vn.getDef()
                    if val_def_op is None and value_stored_vn.isUnique():
                        for k_val in range(store_op_pcode_index - 1, -1, -1):
                            prev_op_val = pcode_ops[k_val]
                            if prev_op_val.getOutput() is not None and prev_op_val.getOutput().equals(value_stored_vn):
                                val_def_op = prev_op_val; break
                    
                    if val_def_op is not None and val_def_op.getOpcode() == PcodeOp.COPY:
                        copied_from_vn = val_def_op.getInput(0)
                        if copied_from_vn.isConstant() and copied_from_vn.getOffset() == 0:
                            is_zero_store = True
                if is_zero_store:
                    # dprint("  Skipping STR at %s: Zero store (parsed operand: %s or const 0 via pcode)." % (instr.getAddress(), first_operand_str if first_operand_str else "N/A"))
                    continue

                # Filter 2: d#/w# registers for xi (parsed first operand string from assembly)
                if first_operand_str is not None:
                    parsed_op_lower = first_operand_str.lower() # Convert to lowercase for checking
                    #dprint("  [FilterDebug] Instr: %s, Parsed 1st Operand: \"%s\", Lowercase: \"%s\"" % (instr.toString(), first_operand_str, parsed_op_lower))
                    if (len(parsed_op_lower) > 1 and
                        (parsed_op_lower.startswith('d') or parsed_op_lower.startswith('w')) and
                        parsed_op_lower[1:].isdigit()):
                        #dprint("    Skipping STR at %s: Parsed source operand (%s) matches d#/w# pattern." % (instr.getAddress(), first_operand_str))
                        continue
                else: # Case where first_operand_str could not be parsed (should be rare for valid STR/STUR)
                    dprint("  [FilterDebug] Instr: %s, COULD NOT PARSE 1st Operand from instruction string." % instr.toString())

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
                        if get_register_name_from_varnode_phase1(base_reg_vn_raw, current_program_ref) == "sp": # Check if base_reg_name_raw (string) is "sp"
                            continue 
                            
                        # For logging, use the p-code based value_stored_vn as before for consistency with deeper analysis if needed
                        # but the filtering decision for d#/w# has been made based on source_assembly_reg_name.
                        pcode_based_xi_reg_name_for_log = get_register_name_from_varnode_phase1(value_stored_vn, current_program_ref)
                        final_xi_name_for_log = pcode_based_xi_reg_name_for_log if pcode_based_xi_reg_name_for_log else get_varnode_representation(value_stored_vn, None, current_program_ref)

                        raw_base_reg_addr_for_phase2 = base_reg_vn_raw.getAddress() if base_reg_vn_raw.isRegister() else None

                        found_instructions_info.append({
                            "address": instr.getAddress(), "instr_obj": instr,
                            "xi_varnode_raw": value_stored_vn, 
                            "xi_reg_name_log": final_xi_name_for_log, 
                            "xj_reg_name_raw_log": base_reg_name_raw, 
                            "raw_base_reg_addr": raw_base_reg_addr_for_phase2, 
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

# --- Main execution ---
if __name__ == "__main__":
    current_program = getCurrentProgram() 
    try:
        print("Starting script with TARGET_OFFSET_FOR_STR_SEARCH = %#x" % TARGET_OFFSET_FOR_STR_SEARCH)
        found_str_instructions = find_specific_str_instructions(TARGET_OFFSET_FOR_STR_SEARCH, current_program)

        if not found_str_instructions:
            print("\nPhase 1 found no relevant STR/STUR instructions. Skipping Phase 2.")
        else:
            print("\nStarting Phase 2: Tracing origin of `xi` and vtable for each STR instruction.")
            all_results_across_str_instrs = []
            for item_idx, item_info in enumerate(found_str_instructions):
                instr_addr = item_info["address"]
                phase1_xi_varnode_raw = item_info["xi_varnode_raw"] 
                
                # Prepare details about the current STR instruction for reporting context
                current_str_details_for_report = {
                    "str_address": instr_addr.toString(),
                    "str_instr": item_info["instr_obj"].toString(),
                    # initial_xi_repr will be added in start_interprocedural_backward_trace
                }

                print("\n--- Analyzing STR at %s (Instruction %d of %d from Phase 1) ---" % (instr_addr, item_idx + 1, len(found_str_instructions)))
                dprint("  Target STR: %s" % item_info["instr_obj"].toString())
                dprint("  Raw `xi` (from Phase 1 PCode): %s" % item_info["xi_reg_name_log"]) 

                containing_func = getFunctionContaining(instr_addr) 
                if not containing_func:
                    print("  Error: Could not find function containing address %s" % str(instr_addr))
                    continue
                
                program_of_containing_func = containing_func.getProgram()
                high_func = get_high_function(containing_func, program_of_containing_func)

                if not high_func:
                    print("  Skipping Phase 2 for STR at %s due to decompilation failure." % instr_addr)
                    continue
                
                initial_vn_to_trace_hf = None
                op_iter_hf = high_func.getPcodeOps(instr_addr)
                found_hf_store_op_for_xi = False
                while op_iter_hf.hasNext():
                    hf_pcode_op = op_iter_hf.next()
                    if hf_pcode_op.getOpcode() == PcodeOp.STORE:
                        initial_vn_to_trace_hf = hf_pcode_op.getInput(2) 
                        dprint("  Located STORE P-code op in HighFunction at address %s: %s" % (instr_addr, hf_pcode_op))
                        dprint("    Taking its input(2) as the value to trace (xi_hf): %s" % get_varnode_representation(initial_vn_to_trace_hf, high_func, program_of_containing_func))
                        found_hf_store_op_for_xi = True
                        break 
                
                if initial_vn_to_trace_hf:
                    dprint("  Starting INTER-PROCEDURAL backward trace for `xi_hf`: %s" % get_varnode_representation(initial_vn_to_trace_hf, high_func, program_of_containing_func))
                    println_for_trace = dprint 
                    
                    origins_for_this_str = start_interprocedural_backward_trace(
                        high_func, initial_vn_to_trace_hf, 
                        println_for_trace, program_of_containing_func,
                        current_str_details_for_report 
                    )
                    all_results_across_str_instrs.extend(origins_for_this_str)
                elif found_hf_store_op_for_xi: 
                     print("  Error: Located STORE P-code op in HighFunction, but could not extract value to trace (input[2] was None or invalid) for STR at %s." % instr_addr)
                else:
                    print("  Error: No STORE P-code operation found in HighFunction at address %s to analyze." % instr_addr)
            
            print_backward_analysis_results(all_results_across_str_instrs)

    except Exception as e:
        import traceback
        print("Script execution error: %s" % str(e))
        traceback.print_exc()
    finally:
        dispose_decompilers() 
        print("Script finished.")