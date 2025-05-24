# Ghidra Python Script to find indirect calls and two associated offsets (v5)
# @author YourName
# @category Analysis

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import Address
import java.lang.Long # Keep this import

# Global flag for debugging prints
ENABLE_DEBUG_PRINTS = True # Set to True to enable detailed debug prints

def dprint(s):
    if ENABLE_DEBUG_PRINTS:
        print("[DEBUG] " + str(s))

# Helper function to get the "true" defining PcodeOp, skipping COPY and CAST
def get_true_defining_op(varnode, expected_opcode_val):
    if varnode is None:
        dprint("GTDO: Varnode input is None")
        return None
    
    current_vn = varnode
    for _ in range(5): 
        defining_op = current_vn.getDef()
        if defining_op is None: 
            dprint("GTDO: Defining op for " + str(current_vn) + " (from original " + str(varnode) + ") is None.")
            return None 
        
        actual_opcode = defining_op.getOpcode()
        if actual_opcode == PcodeOp.COPY or actual_opcode == PcodeOp.CAST:
            dprint("GTDO: Skipping " + PcodeOp.getMnemonic(actual_opcode) + " for " + str(current_vn) + ". Next VN: " + str(defining_op.getInput(0)))
            current_vn = defining_op.getInput(0)
            if current_vn is None: 
                 dprint("GTDO: Next VN after COPY/CAST is None.")
                 return None
        else:
            dprint("GTDO: Varnode " + str(current_vn) + " (traced from " + str(varnode) + ") defined by " + 
                   PcodeOp.getMnemonic(actual_opcode) + " (" + str(defining_op) + "). Expecting " + PcodeOp.getMnemonic(expected_opcode_val))
            if actual_opcode == expected_opcode_val:
                return defining_op
            else:
                return None 
    
    dprint("GTDO: Exceeded depth limit or could not find non-COPY/CAST definer for " + str(varnode))
    return None


def get_constant_value(varnode):
    if varnode is not None and varnode.isConstant():
        return varnode.getOffset()
    return None

def get_add_components(add_op):
    if add_op is None or add_op.getOpcode() != PcodeOp.INT_ADD:
        return None, None
    input0 = add_op.getInput(0)
    input1 = add_op.getInput(1)
    offset_val = get_constant_value(input1)
    base_val_vn = input0
    if offset_val is None:
        offset_val = get_constant_value(input0)
        base_val_vn = input1
    if offset_val is None:
        dprint("GAC: Could not find constant offset in INT_ADD op: " + str(add_op))
        return None, None
    return base_val_vn, offset_val

def find_indirect_call_offsets(func):
    if func is None:
        print("Error: Function not found.")
        return

    print("Analyzing function: " + func.getName() + " at " + str(func.getEntryPoint()))

    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    res = ifc.decompileFunction(func, 60, monitor)
    if not res or not res.getHighFunction():
        print("Error: Could not decompile function " + func.getName())
        ifc.closeProgram()
        return

    high_func = res.getHighFunction()
    opiter = high_func.getPcodeOps()
    found_calls = []

    for callind_op in opiter:
        if callind_op.getOpcode() != PcodeOp.CALLIND:
            continue

        dprint("Found CALLIND at " + str(callind_op.getSeqnum().getTarget()))
        
        callind_input_vn = callind_op.getInput(0)
        if callind_input_vn is None:
            dprint("Step 0 FAIL: CALLIND input varnode is None.")
            continue
            
        temp_def_op = callind_input_vn.getDef()
        target_func_ptr_vn = None 

        if temp_def_op is not None and temp_def_op.getOpcode() == PcodeOp.COPY:
            target_func_ptr_vn = temp_def_op.getInput(0)
            dprint("Step 0: CALLIND input " + str(callind_input_vn) + " is from COPY. Effective target pointer VN: " + str(target_func_ptr_vn))
        else:
            target_func_ptr_vn = callind_input_vn 
            dprint("Step 0: CALLIND input " + str(callind_input_vn) + " used directly. Def: " + (PcodeOp.getMnemonic(temp_def_op.getOpcode()) if temp_def_op else "None"))

        if target_func_ptr_vn is None:
            dprint("Step 0 FAIL: Could not determine actual target_func_ptr_vn.")
            continue

        op_load_func_ptr = get_true_defining_op(target_func_ptr_vn, PcodeOp.LOAD)
        if op_load_func_ptr is None:
            dprint("Step 1 FAILED for effective target_func_ptr_vn: " + str(target_func_ptr_vn))
            continue
        addr_of_func_ptr_vn = op_load_func_ptr.getInput(1)

        op_add_offset2 = get_true_defining_op(addr_of_func_ptr_vn, PcodeOp.INT_ADD)
        if op_add_offset2 is None:
            dprint("Step 2 FAILED for addr_of_func_ptr_vn: " + str(addr_of_func_ptr_vn))
            continue
        vtable_ptr_vn, offset2_val = get_add_components(op_add_offset2)
        if offset2_val is None or vtable_ptr_vn is None:
            dprint("Step 2.1 FAILED (get_add_components) for op_add_offset2: " + str(op_add_offset2))
            continue
        dprint("Step 2 OK: offset2 = 0x" + java.lang.Long.toHexString(offset2_val) + ", vtable_ptr_vn = " + str(vtable_ptr_vn)) # Fixed here

        op_load_vtable_ptr = get_true_defining_op(vtable_ptr_vn, PcodeOp.LOAD)
        if op_load_vtable_ptr is None:
            dprint("Step 3 FAILED for vtable_ptr_vn: " + str(vtable_ptr_vn))
            continue
        addr_of_vtable_ptr_storage_vn = op_load_vtable_ptr.getInput(1)
        dprint("Step 3 OK: addr_of_vtable_ptr_storage_vn = " + str(addr_of_vtable_ptr_storage_vn))

        op_load_intermediate_ptr = get_true_defining_op(addr_of_vtable_ptr_storage_vn, PcodeOp.LOAD)
        if op_load_intermediate_ptr is None:
            dprint("Step 4 FAILED for addr_of_vtable_ptr_storage_vn (after any COPY/CAST): " + str(addr_of_vtable_ptr_storage_vn))
            continue
        addr_for_intermediate_load_vn = op_load_intermediate_ptr.getInput(1)
        dprint("Step 4 OK: addr_for_intermediate_load_vn = " + str(addr_for_intermediate_load_vn))

        op_add_offset1 = get_true_defining_op(addr_for_intermediate_load_vn, PcodeOp.INT_ADD)
        if op_add_offset1 is None:
            dprint("Step 5 FAILED for addr_for_intermediate_load_vn: " + str(addr_for_intermediate_load_vn))
            continue
        base_reg_vn, offset1_val = get_add_components(op_add_offset1)
        if offset1_val is None or base_reg_vn is None:
            dprint("Step 5.1 FAILED (get_add_components) for op_add_offset1: " + str(op_add_offset1))
            continue
        dprint("Step 5 OK: offset1 = 0x" + java.lang.Long.toHexString(offset1_val) + ", base_reg_vn = " + str(base_reg_vn)) # Fixed here
            
        base_reg_name = "Unknown"
        if base_reg_vn.isRegister():
            reg = currentProgram.getRegister(base_reg_vn.getAddress())
            if reg is not None:
                base_reg_name = reg.getName()
        elif base_reg_vn.isInput(): 
            param_index = -1
            try: # Get associated HighSymbol for parameter name
                func_sig = high_func.getFunctionPrototype()
                for i in range(func_sig.getNumParams()):
                    param_storage = func_sig.getParam(i).getStorage()
                    if param_storage.isVarnodeStorage() and param_storage.getVarnode().equals(base_reg_vn):
                        param_index = i
                        break
            except: pass # some varnodes might not map to params directly

            if param_index != -1 :
                 base_reg_name = func_sig.getParam(param_index).getName() + " (param " + str(param_index) + ")"
            elif base_reg_vn.isAddress() and currentProgram.getRegister(base_reg_vn.getAddress()) is not None:
                 base_reg_name = currentProgram.getRegister(base_reg_vn.getAddress()).getName() + " (input)"
            else: 
                 sym = high_func.getMappedSymbol(base_reg_vn) 
                 if sym : base_reg_name = sym.getName() + " (input symbol)"

        found_calls.append({
            "address": callind_op.getSeqnum().getTarget(),
            "base_reg": base_reg_name,
            "offset1": offset1_val,
            "offset2": offset2_val
        })
        dprint("SUCCESS: Found pattern for CALLIND at " + str(callind_op.getSeqnum().getTarget()))

    ifc.closeProgram()

    if found_calls:
        print("\nFound indirect calls with two offsets for function " + func.getName() + ":")
        for call_info in found_calls:
            print("  CALLIND at: " + str(call_info["address"]))
            print("    Base Register: " + str(call_info["base_reg"]))
            print("    Offset1: 0x" + java.lang.Long.toHexString(call_info["offset1"])) # Fixed here
            print("    Offset2: 0x" + java.lang.Long.toHexString(call_info["offset2"])) # Fixed here
            print("    Calculation: *(*(*(" + str(call_info["base_reg"]) + " + 0x" + java.lang.Long.toHexString(call_info["offset1"]) + ")) + 0x" + java.lang.Long.toHexString(call_info["offset2"]) + "))") # Fixed here
    else:
        print("No indirect calls matching the specific two-offset pattern found in " + func.getName())

try:
    ENABLE_DEBUG_PRINTS = True 
    target_func = getFunctionContaining(currentAddress)
    if target_func is None:
        af = currentProgram.getAddressFactory()
        func_addr_str = askString("Enter Function Address", "Enter the starting address of the function (e.g., 0x100400):")
        try:
            func_address = af.getAddress(func_addr_str)
            target_func = getFunctionAt(func_address)
            if target_func is None:
                 target_func = getFunctionContaining(func_address)
            if target_func is None:
                print("Error: Could not find function at address " + func_addr_str)
        except Exception as e:
            print("Error: Invalid address format - " + str(e))
            target_func = None
    if target_func:
        find_indirect_call_offsets(target_func)
except Exception as e:
    import traceback
    print("Script execution error: " + str(e))
    traceback.print_exc()