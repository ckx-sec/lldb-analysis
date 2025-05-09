# -*- coding: UTF-8 -*-
import sys
import time
import subprocess
import numpy as np # If not used, can be commented out
import struct    # If not used, can be commented out
import os
import json # For SBStructuredData and for dumping context
import traceback
# import inspect # For advanced debugging if needed

# --- Test Script Started --- (initial LLDB import part)
print("--- Test Script Started ---")
print("1. Attempting to import sys...")
# import sys # Already imported at the top
print("   sys imported successfully.")

lldb_python_path = "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Resources/Python" # macOS specific, adjust if needed
print(f"2. LLDB Python path to be added: {lldb_python_path}")

if lldb_python_path not in sys.path:
    if os.path.exists(lldb_python_path):
        sys.path.insert(0, lldb_python_path)
        print(f"   '{lldb_python_path}' added to sys.path.")
    else:
        print(f"   WARNING: LLDB Python path '{lldb_python_path}' does not exist. LLDB import might fail.")
else:
    print(f"   '{lldb_python_path}' already in sys.path.")

print(f"Current sys.path:")
for p in sys.path:
    print(f"  - {p}")

print("\n3. Attempting to import lldb...")
try:
    import lldb
    print("   SUCCESS: lldb imported successfully!")
    print(f"   lldb module object: {lldb}")
    if hasattr(lldb, '__file__') and lldb.__file__:
        print(f"   lldb file location: {lldb.__file__}")
    else:
        print(f"   lldb file location: Not available (module might be built-in or part of a package)")


    print("\n4. Attempting SBDebugger.Create()...")
    debugger_test = lldb.SBDebugger.Create()
    if debugger_test and debugger_test.IsValid():
       print(f"   SBDebugger.Create() successful. LLDB Version: {debugger_test.GetVersionString()}")
       lldb.SBDebugger.Destroy(debugger_test)
    else:
       print("   ERROR: Failed to create SBDebugger object or object invalid.")
except ImportError as e_import:
    print(f"   ERROR (ImportError) during 'import lldb': {e_import}")
    print(f"   Please ensure LLDB's Python module is correctly installed and accessible via sys.path.")
    traceback.print_exc()
except Exception as e_general:
    print(f"   ERROR (General Exception) during or after 'import lldb': {e_general}")
    traceback.print_exc()
print("\n--- Test Script Finished (LLDB Import Check) ---")


g_temp_blr_x8_bp_context = {}
g_blr_x8_hit_log = []
MAX_RECURSION_DEPTH = 10
g_scanned_function_starts = set()

def is_process_effectively_dead(process_obj):
    if not process_obj or not process_obj.IsValid():
        return True
    state = process_obj.GetState()
    return (state == lldb.eStateExited or
            state == lldb.eStateDetached or
            state == lldb.eStateInvalid or
            state == lldb.eStateCrashed)

def get_module_base_address_int(target, module_obj):
    if not module_obj or not module_obj.IsValid():
        return lldb.LLDB_INVALID_ADDRESS

    module_name_for_debug = module_obj.GetFileSpec().GetFilename()
    if not module_name_for_debug: module_name_for_debug = "UnknownModule"

    base_addr_sbaddr = module_obj.ResolveFileAddress(0)
    if base_addr_sbaddr and base_addr_sbaddr.IsValid():
        load_addr = base_addr_sbaddr.GetLoadAddress(target)
        if load_addr != lldb.LLDB_INVALID_ADDRESS:
            return load_addr

    min_load_addr = lldb.LLDB_INVALID_ADDRESS
    num_sections = module_obj.GetNumSections()

    if num_sections == 0:
        pass

    for i in range(num_sections):
        section = module_obj.GetSectionAtIndex(i)
        if (section.IsValid() and
            section.GetFileByteSize() > 0 and
            section.GetLoadAddress(target) != lldb.LLDB_INVALID_ADDRESS):

            load_addr = section.GetLoadAddress(target)
            if min_load_addr == lldb.LLDB_INVALID_ADDRESS or load_addr < min_load_addr:
                min_load_addr = load_addr

    if min_load_addr != lldb.LLDB_INVALID_ADDRESS:
        return min_load_addr

    #print(f"[WARN] get_module_base_address_int: Failed to determine base address for module {module_name_for_debug}")
    return lldb.LLDB_INVALID_ADDRESS


def get_process_pid_by_name(device_serial, process_name_pattern):
    print(f"[DEBUG] get_process_pid_by_name: Finding process containing '{process_name_pattern}' on device '{device_serial}'")
    try:
        cmd = ["adb", "-s", device_serial, "shell", "su", "-c", f"ps -A | grep {process_name_pattern}"]
        #print(f"[DEBUG] Executing command: {' '.join(cmd)}")
        output = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
        lines = output.strip().split("\n")

        pids_found = []
        for line in lines:
            if process_name_pattern in line:
                parts = line.split()
                if len(parts) > 1:
                    pid_str = parts[1]
                    try:
                        pid = int(pid_str)
                        command_name_candidate = parts[-1]
                        if len(parts) > 8 and process_name_pattern in parts[8]:
                             command_name_candidate = parts[8]

                        if process_name_pattern in command_name_candidate:
                            #print(f"[DEBUG] Found matching process: '{command_name_candidate}' PID: {pid}, Line: {line.strip()}")
                            pids_found.append(pid)
                    except ValueError:
                        continue

        if len(pids_found) == 1:
            print(f"[DEBUG] Unambiguously found PID: {pids_found[0]}")
            return pids_found[0]
        elif len(pids_found) > 1:
            print(f"[WARN] Multiple PIDs found for '{process_name_pattern}': {pids_found}. Returning the first one.")
            return pids_found[0]
        else:
            print(f"[DEBUG] No process found matching command column for '{process_name_pattern}'.")
            return None

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] get_process_pid_by_name: Error executing adb shell ps: {e}")
        if e.output: print(f"[ERROR] Output: {e.output}")
        return None
    except FileNotFoundError:
        print("[ERROR] get_process_pid_by_name: adb command not found. Ensure adb is in your PATH.")
        return None

def get_face_service_pid(device_serial="10ACC30KQG000MF"):
    print(f"[DEBUG] get_face_service_pid: Finding face-service on device '{device_serial}'")
    return get_process_pid_by_name(device_serial, "android.hardware.biometrics.face")

def wait_for_module_load(target, lib_name, timeout=20):
    print(f"[DEBUG] wait_for_module_load: Waiting for module '{lib_name}' to load (timeout: {timeout}s)...")
    for i in range(timeout):
        module = target.FindModule(lldb.SBFileSpec(lib_name))
        if module.IsValid():
            print(f"[DEBUG] Module '{lib_name}' loaded: {module.GetFileSpec().GetDirectory()}/{module.GetFileSpec().GetFilename()}")
            return module
        if i > 0 and i % 5 == 0:
             print(f"[DEBUG] wait_for_module_load: '{lib_name}' still not loaded ({i+1}/{timeout}s)...")
        time.sleep(1)
    print(f"[ERROR] wait_for_module_load: Timeout. Failed to load module '{lib_name}'.")
    return None

def set_breakpoints_on_all_exported_functions(debugger, target, lib_name):
    print(f"[DEBUG] set_breakpoints_on_all_exported_functions: Setting breakpoints on 'ANC_' prefixed functions in '{lib_name}'")
    module = wait_for_module_load(target, lib_name)
    if not module:
        print(f"[ERROR] Module '{lib_name}' not loaded. Cannot set breakpoints.")
        return {}

    SYMBOL_TYPE_FUNCTION = getattr(lldb, 'eSymbolTypeFunction', 5)
    SYMBOL_TYPE_CODE = getattr(lldb, 'eSymbolTypeCode', 2)
    # if SYMBOL_TYPE_FUNCTION == 5 or SYMBOL_TYPE_CODE == 2:
    #     print("[WARN] Using fallback integer values for symbol types (Function=5, Code=2). This might not be universally compatible if LLDB changes these constants.")

    breakpoints_info = {}
    functions_instrumented_count = 0
    anc_functions_found = 0
    num_symbols = module.GetNumSymbols()
    print(f"[DEBUG] Enumerating {num_symbols} symbols in '{lib_name}'...")

    for i in range(num_symbols):
        symbol = module.GetSymbolAtIndex(i)
        if not symbol.IsValid():
            continue

        symbol_type_val = symbol.GetType()
        is_function_type = (symbol_type_val == SYMBOL_TYPE_FUNCTION)
        is_code_type = (symbol_type_val == SYMBOL_TYPE_CODE)

        if symbol.IsExternal() and (is_function_type or is_code_type):
            func_name = symbol.GetName()

            if func_name and func_name.startswith("ANC_"):
                anc_functions_found += 1
                start_addr_obj = symbol.GetStartAddress()
                if not func_name:
                    func_name = f"sub_{start_addr_obj.GetFileAddress():x}" if start_addr_obj.IsValid() else "UnnamedExportedSymbol"

                if not start_addr_obj.IsValid():
                    #print(f"[WARN] Function {func_name} has invalid start address object. Skipping.")
                    continue

                load_addr_int = start_addr_obj.GetLoadAddress(target)
                if load_addr_int == lldb.LLDB_INVALID_ADDRESS:
                    #print(f"[WARN] Function {func_name} has invalid load address. Skipping.")
                    continue

                if any(bp_data["address"] == load_addr_int for bp_data in breakpoints_info.values()):
                    continue

                bp = target.BreakpointCreateByAddress(load_addr_int)
                if bp and bp.IsValid() and bp.GetNumLocations() > 0:
                    actual_bp_addr_int = bp.GetLocationAtIndex(0).GetAddress().GetLoadAddress(target)
                    #print(f"[DEBUG] Created breakpoint for ANC_ function {func_name} (0x{actual_bp_addr_int:x}), ID: {bp.GetID()}.")
                    breakpoints_info[bp.GetID()] = {
                        "name": func_name,
                        "address": actual_bp_addr_int,
                        "module_name": lib_name,
                        "symbol": symbol
                    }
                    functions_instrumented_count += 1
                else:
                    print(f"[WARN] Failed to create breakpoint for ANC_ function {lib_name}::{func_name} (0x{load_addr_int:x}). BP valid: {bp.IsValid() if bp else 'None'}, NumLoc: {bp.GetNumLocations() if bp else 'N/A'}")

        if i > 0 and i % 2000 == 0 :
             print(f"[DEBUG] Processed {i}/{num_symbols} symbols...")

    print(f"[DEBUG] Found {anc_functions_found} 'ANC_' prefixed exportable symbols.")
    print(f"[DEBUG] Successfully created breakpoints for {functions_instrumented_count} of them.")
    return breakpoints_info


def scan_and_set_blr_x8_breakpoints(target, frame, function_symbol, func_info, recursion_depth=0):
    global g_temp_blr_x8_bp_context, g_scanned_function_starts

    func_name = func_info['name']

    if not function_symbol or not function_symbol.IsValid():
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Received an invalid function_symbol object. Cannot proceed.")
        return

    func_start_addr_obj_from_symbol = function_symbol.GetStartAddress()
    if not func_start_addr_obj_from_symbol.IsValid():
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Start address from symbol is invalid. Cannot scan.")
        return
    func_start_load_addr_int = func_start_addr_obj_from_symbol.GetLoadAddress(target)
    if func_start_load_addr_int == lldb.LLDB_INVALID_ADDRESS:
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Load address for start is invalid. Cannot scan.")
        return

    if func_start_load_addr_int in g_scanned_function_starts:
        #print(f"[DEBUG] (Depth {recursion_depth}) Function {func_name} at 0x{func_start_load_addr_int:x} already scanned for branches. Skipping.")
        return

    containing_module = func_start_addr_obj_from_symbol.GetModule()
    if not containing_module or not containing_module.IsValid():
        sym_name_for_warn = function_symbol.GetName()
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} (Symbol: {sym_name_for_warn}): Could not get valid module from symbol's address object.")
        pass # Continue, module_name will be unknown

    containing_module_name = "UnknownModuleFromSymbol"
    module_base_addr_int = lldb.LLDB_INVALID_ADDRESS

    if containing_module and containing_module.IsValid():
        containing_module_name = containing_module.GetFileSpec().GetFilename()
        if not containing_module_name: containing_module_name = "UnknownModuleFromSymbol" # Fallback if GetFilename returns None
        module_base_addr_int = get_module_base_address_int(target, containing_module)
        # if module_base_addr_int == lldb.LLDB_INVALID_ADDRESS:
            #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} in module '{containing_module_name}': Could not determine module base address. Offsets might not be calculated for this scan.")
            # pass # Continue with invalid base address

    func_end_addr_obj_from_symbol = function_symbol.GetEndAddress()
    if not func_end_addr_obj_from_symbol.IsValid():
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: End address from symbol is invalid. Cannot scan for blr x8 / bl.")
        return

    func_end_load_addr_int = func_end_addr_obj_from_symbol.GetLoadAddress(target)
    if func_end_load_addr_int == lldb.LLDB_INVALID_ADDRESS:
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Load address for end is invalid. Cannot scan for blr x8 / bl.")
        return

    if func_end_load_addr_int <= func_start_load_addr_int:
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} (Abs: 0x{func_start_load_addr_int:x}): Invalid or zero size (End Abs: 0x{func_end_load_addr_int:x}). Cannot scan.")
        return

    func_size = int(func_end_load_addr_int - func_start_load_addr_int)
    #print(f"[DEBUG] (Depth {recursion_depth}) Scanning function {containing_module_name}::{func_name} (Abs: 0x{func_start_load_addr_int:x} - 0x{func_end_load_addr_int:x}, Size: {func_size} bytes) for 'blr x8' and 'bl'. Module base: {(f'0x{module_base_addr_int:x}' if module_base_addr_int != lldb.LLDB_INVALID_ADDRESS else 'N/A')}")

    # 1. 扫描 BLR X8 (使用原始的字节码扫描方式)
    error = lldb.SBError()
    instructions_data_raw = target.ReadMemory(func_start_addr_obj_from_symbol, func_size, error)

    if not error.Success():
        #print(f"[WARN] (Depth {recursion_depth}) Failed to read memory for function {func_name} for BLR X8 scan: {error.GetCString()}")
        pass
    else:
        blr_x8_sequence = b'\x00\x01\x3f\xd6'
        found_blr_x8_count = 0
        for i in range(0, func_size - 3, 4): # Iterate by 4 bytes
            instruction_bytes = instructions_data_raw[i:i+4]
            if instruction_bytes == blr_x8_sequence:
                blr_actual_load_addr_int = func_start_load_addr_int + i
                found_blr_x8_count += 1

                offset_original_func_addr_str = "N/A"
                offset_blr_instr_addr_str = "N/A"
                if module_base_addr_int != lldb.LLDB_INVALID_ADDRESS:
                    offset_original_func_addr = func_start_load_addr_int - module_base_addr_int
                    offset_blr_instr_addr = blr_actual_load_addr_int - module_base_addr_int
                    offset_original_func_addr_str = hex(offset_original_func_addr)
                    offset_blr_instr_addr_str = hex(offset_blr_instr_addr)

                #print(f"[DEBUG] (Depth {recursion_depth}) Found 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x} (Offset: +{offset_blr_instr_addr_str})")

                is_duplicate_context = False
                for existing_bp_id, existing_ctx in g_temp_blr_x8_bp_context.items():
                    if (existing_ctx.get("breakpoint_type") == "blr_x8" and
                        existing_ctx.get("module_name") == containing_module_name and
                        existing_ctx.get("original_func_name") == func_name and
                        existing_ctx.get("original_func_addr_offset") == offset_original_func_addr_str and
                        existing_ctx.get("blr_instr_addr_offset") == offset_blr_instr_addr_str):
                        #print(f"[INFO] (Depth {recursion_depth}) Duplicate 'blr x8' context. Skipping BP creation.")
                        is_duplicate_context = True
                        break
                if is_duplicate_context:
                    continue

                temp_bp = target.BreakpointCreateByAddress(blr_actual_load_addr_int)
                if temp_bp and temp_bp.IsValid():
                    bp_id = temp_bp.GetID()
                    g_temp_blr_x8_bp_context[bp_id] = {
                        "breakpoint_type": "blr_x8",
                        "module_name": containing_module_name,
                        "original_func_name": func_name,
                        "original_func_addr_offset": offset_original_func_addr_str,
                        "blr_instr_addr_offset": offset_blr_instr_addr_str,
                        "recursion_depth": recursion_depth
                    }
                    #print(f"[DEBUG] (Depth {recursion_depth}) Set PERSISTENT breakpoint ID {bp_id} for 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x} (Offset: +{offset_blr_instr_addr_str})")
                else:
                    #print(f"[WARN] (Depth {recursion_depth}) Failed to create breakpoint for 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x}")
                    pass
        # if found_blr_x8_count == 0 and error.Success() :
            #print(f"[DEBUG] (Depth {recursion_depth}) No 'blr x8' instructions found in {containing_module_name}::{func_name}.")
            # pass

    # 2. 扫描 BL 指令 (使用 LLDB 反汇编)
    instructions_list = target.ReadInstructions(func_start_addr_obj_from_symbol, func_size)
    if not instructions_list or instructions_list.GetSize() == 0:
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Failed to read instructions using target.ReadInstructions for BL scan, or no instructions found.")
        pass
    else:
        #print(f"[DEBUG] (Depth {recursion_depth}) Read {instructions_list.GetSize()} instructions for BL scan in {func_name}.")
        bl_found_count = 0
        for idx in range(instructions_list.GetSize()):
            instr = instructions_list.GetInstructionAtIndex(idx)
            if not instr or not instr.IsValid():
                continue

            instr_load_addr_int = instr.GetAddress().GetLoadAddress(target)
            instr_data_reader = instr.GetData(target)
            error_instr_data = lldb.SBError()
            raw_instr_uint32 = instr_data_reader.GetUnsignedInt32(error_instr_data, 0)

            if error_instr_data.Success() and (raw_instr_uint32 & 0xFC000000) == 0x94000000: # Check for BL
                bl_found_count += 1
                offset = raw_instr_uint32 & 0x03FFFFFF # 26-bit immediate
                # Sign extend the 26-bit immediate, which is stored as offset*4
                if (offset >> 25) & 1: # Check sign bit (bit 25 of the 26-bit immediate)
                    signed_offset_imm = offset | ~((1 << 26) -1) # Sign extend to full int width
                else:
                    signed_offset_imm = offset

                bl_target_addr_int = instr_load_addr_int + (signed_offset_imm * 4)

                #print(f"[DEBUG] (Depth {recursion_depth}) Found 'bl' in {containing_module_name}::{func_name} at 0x{instr_load_addr_int:x} targeting 0x{bl_target_addr_int:x}. Setting breakpoint and tracking.")

                bl_target_bp = target.BreakpointCreateByAddress(bl_target_addr_int)
                if bl_target_bp and bl_target_bp.IsValid() and bl_target_bp.GetNumLocations() > 0:
                    actual_bp_addr_bl_target = bl_target_bp.GetLocationAtIndex(0).GetAddress().GetLoadAddress(target)
                    bp_id_bl = bl_target_bp.GetID()

                    current_bl_instr_offset_str = "N/A"
                    original_func_offset_str = "N/A" # Offset of func_name within its module
                    if module_base_addr_int != lldb.LLDB_INVALID_ADDRESS:
                        original_func_offset = func_start_load_addr_int - module_base_addr_int
                        original_func_offset_str = hex(original_func_offset)
                        current_bl_instr_offset = instr_load_addr_int - module_base_addr_int
                        current_bl_instr_offset_str = hex(current_bl_instr_offset)

                    bl_target_module_name_ctx = "UnknownModuleAtBLTarget"
                    bl_target_func_name_ctx = f"sub_{actual_bp_addr_bl_target:x}"
                    bl_target_func_offset_ctx_str = "N/A"

                    addr_at_bl_target = target.ResolveLoadAddress(actual_bp_addr_bl_target)
                    if addr_at_bl_target and addr_at_bl_target.IsValid():
                        module_at_bl_target = addr_at_bl_target.GetModule()
                        if module_at_bl_target and module_at_bl_target.IsValid():
                            mod_name_val = module_at_bl_target.GetFileSpec().GetFilename()
                            if mod_name_val: bl_target_module_name_ctx = mod_name_val
                            else: bl_target_module_name_ctx = "UnnamedModuleAtBLTarget"

                            base_addr_bl_target_mod = get_module_base_address_int(target, module_at_bl_target)
                            if base_addr_bl_target_mod != lldb.LLDB_INVALID_ADDRESS:
                                bl_target_func_offset_ctx = actual_bp_addr_bl_target - base_addr_bl_target_mod
                                bl_target_func_offset_ctx_str = hex(bl_target_func_offset_ctx)
                            else:
                                bl_target_module_name_ctx = f"{bl_target_module_name_ctx}_(BaseNotFound)"


                        symbol_at_bl_target = addr_at_bl_target.GetSymbol()
                        if symbol_at_bl_target and symbol_at_bl_target.IsValid():
                            func_name_val = symbol_at_bl_target.GetName()
                            if func_name_val: bl_target_func_name_ctx = func_name_val

                    is_duplicate_bl_context = False
                    for _existing_bp_id, existing_ctx in g_temp_blr_x8_bp_context.items():
                        if (existing_ctx.get("breakpoint_type") == "bl_target" and
                            existing_ctx.get("bl_target_absolute_addr_val") == actual_bp_addr_bl_target and
                            existing_ctx.get("module_name") == containing_module_name and # Module of func containing BL
                            existing_ctx.get("original_func_name") == func_name and      # Func name containing BL
                            existing_ctx.get("bl_instr_addr_offset") == current_bl_instr_offset_str):
                            #print(f"[INFO] (Depth {recursion_depth}) Duplicate 'bl_target' context for target 0x{actual_bp_addr_bl_target:x} from {func_name}+{current_bl_instr_offset_str}. BP deleted.")
                            is_duplicate_bl_context = True
                            target.BreakpointDelete(bp_id_bl) # Delete the newly created temp BP
                            break

                    if not is_duplicate_bl_context:
                        g_temp_blr_x8_bp_context[bp_id_bl] = {
                            "breakpoint_type": "bl_target",
                            "module_name": containing_module_name,
                            "original_func_name": func_name,
                            "original_func_addr_offset": original_func_offset_str,
                            "bl_instr_addr_offset": current_bl_instr_offset_str,
                            "bl_target_absolute_addr_val": actual_bp_addr_bl_target,
                            "bl_target_absolute_addr_hex": hex(actual_bp_addr_bl_target),
                            "bl_target_module_name": bl_target_module_name_ctx,
                            "bl_target_func_name": bl_target_func_name_ctx,
                            "bl_target_func_offset": bl_target_func_offset_ctx_str,
                            "recursion_depth": recursion_depth
                        }
                        #print(f"[DEBUG] (Depth {recursion_depth}) Set PERSISTENT breakpoint ID {bp_id_bl} for 'bl' target at {bl_target_module_name_ctx}::{bl_target_func_name_ctx} (0x{actual_bp_addr_bl_target:x})")
                else:
                    print(f"[WARN] (Depth {recursion_depth}) Failed to create breakpoint for BL target at 0x{bl_target_addr_int:x} from {containing_module_name}::{func_name} (0x{instr_load_addr_int:x}). BP Valid: {bl_target_bp.IsValid() if bl_target_bp else 'None'}, NumLoc: {bl_target_bp.GetNumLocations() if bl_target_bp else 'N/A'}")

        # if bl_found_count == 0 and instructions_list and instructions_list.GetSize() > 0:
            #print(f"[DEBUG] (Depth {recursion_depth}) No 'bl' instructions found in {containing_module_name}::{func_name}.")
            # pass

    g_scanned_function_starts.add(func_start_load_addr_int)
    #print(f"[DEBUG] (Depth {recursion_depth}) Finished scanning {containing_module_name}::{func_name} at 0x{func_start_load_addr_int:x}. Added to scanned set.")

def attach_and_debug_remote(pid: int, target_lib_name: str, device_serial: str, connect_url="connect://localhost:1234"):
    global g_temp_blr_x8_bp_context, g_blr_x8_hit_log
    global MAX_RECURSION_DEPTH

    print("[DEBUG] --- Starting attach_and_debug_remote ---")
    print(f"[DEBUG] Params: PID={pid}, Lib='{target_lib_name}', Device='{device_serial}', URL='{connect_url}'")

    debugger = lldb.SBDebugger.Create()
    if not debugger or not debugger.IsValid():
        print("[ERROR] Failed to create a valid SBDebugger instance.")
        return None
    #print(f"[DEBUG] SBDebugger created successfully. Valid: {debugger.IsValid()}")
    debugger.SetAsync(True)
    #print("[DEBUG] SetAsync(True) called.")

    platform = debugger.GetPlatformAtIndex(0)
    if not platform or not platform.IsValid() or platform.GetName() != "remote-android":
        platform = lldb.SBPlatform("remote-android")
        if not platform.IsValid():
            print("[ERROR] 无法创建 remote-android 平台。")
            return None
        debugger.SetSelectedPlatform(platform)
        print(f"[DEBUG] 新建并选择了 remote-android 平台: {platform.GetName()}")
    else:
        print(f"[DEBUG] 使用现有平台: {platform.GetName()}")

    if device_serial:
        #print(f"[DEBUG] 准备设置 ANDROID_SERIAL=\"{device_serial}\"")
        os.environ["ANDROID_SERIAL"] = device_serial
        #print(f"[DEBUG] ANDROID_SERIAL 已设置为 \"{device_serial}\"")
    # else:
        #print("[DEBUG] 未提供 device_serial，跳过设置 ANDROID_SERIAL。")

    print(f"[DEBUG] Connecting to remote debug server: {connect_url}...")
    connect_options = lldb.SBPlatformConnectOptions(connect_url)
    error = platform.ConnectRemote(connect_options)
    if error.Fail():
        print(f"[ERROR] Failed to connect to remote-android platform ({connect_url}): {error.GetCString()}")
        lldb.SBDebugger.Destroy(debugger)
        return None
    print(f"[DEBUG] Connected to remote debug server successfully: {connect_url}")

    print("[DEBUG] Creating Target (arch: aarch64-linux-android)...")
    target = debugger.CreateTargetWithFileAndArch(None, "aarch64-linux-android")
    if not target or not target.IsValid():
        print("[ERROR] Failed to create a valid Target (aarch64-linux-android).")
        if platform.IsConnected(): platform.DisconnectRemote()
        lldb.SBDebugger.Destroy(debugger)
        return None
    #print(f"[DEBUG] Target created successfully. Valid: {target.IsValid()}")

    listener = debugger.GetListener()
    error = lldb.SBError()
    print(f"[DEBUG] Attaching to process PID: {pid}...")
    process = target.AttachToProcessWithID(listener, pid, error)

    if error.Fail() or not process or not process.IsValid():
        err_msg = error.GetCString() if error.Fail() else "Process invalid or null after attach."
        print(f"[ERROR] Failed to attach to remote process PID:{pid}: {err_msg}")
        if platform.IsConnected(): platform.DisconnectRemote()
        lldb.SBDebugger.Destroy(debugger)
        return None
    print(f"[DEBUG] Successfully attached to remote process PID: {pid}. Process Valid: {process.IsValid()}, State: {lldb.SBDebugger.StateAsCString(process.GetState())}")

    print("[DEBUG] Waiting for initial process stop event...")
    event = lldb.SBEvent()
    initial_stop_received = False
    MAX_INITIAL_STOP_WAITS = 15
    for i_wait in range(MAX_INITIAL_STOP_WAITS):
        #print(f"[DEBUG] Waiting for initial stop... (Attempt {i_wait+1}/{MAX_INITIAL_STOP_WAITS})")
        if listener.WaitForEvent(2, event): # Timeout 2 seconds
            state_from_event = lldb.SBProcess.GetStateFromEvent(event)
            #print(f"[DEBUG] Event received. State from event: {lldb.SBDebugger.StateAsCString(state_from_event)}")
            if state_from_event == lldb.eStateStopped:
                print(f"[DEBUG] Initial stop event received. Process stopped.")
                initial_stop_received = True
                break
        else: # Timeout
            current_process_state = process.GetState()
            #print(f"[DEBUG] WaitForEvent timeout. Current process state: {lldb.SBDebugger.StateAsCString(current_process_state)}")
            if current_process_state == lldb.eStateStopped:
                print("[DEBUG] Process was already stopped (checked after timeout).")
                initial_stop_received = True
                break
        if is_process_effectively_dead(process):
            print(f"[ERROR] Process died while waiting for initial stop. State: {lldb.SBDebugger.StateAsCString(process.GetState())}")
            if platform.IsConnected(): platform.DisconnectRemote()
            lldb.SBDebugger.Destroy(debugger)
            return None

    if not initial_stop_received:
        print(f"[ERROR] Did not receive initial process stop event after attach. Current state: {lldb.SBDebugger.StateAsCString(process.GetState())}")
        if process and process.IsValid(): process.Detach()
        if platform.IsConnected(): platform.DisconnectRemote()
        lldb.SBDebugger.Destroy(debugger)
        return None
    #print("[DEBUG] Initial process stop event handled.")

    print(f"[DEBUG] Setting breakpoints for library '{target_lib_name}'...")
    active_breakpoints = set_breakpoints_on_all_exported_functions(debugger, target, target_lib_name)
    if not active_breakpoints:
        print(f"[WARN] No 'ANC_' prefixed function breakpoints were set in '{target_lib_name}'.")

    # Diagnostic print for ANC breakpoints (optional)
    # if active_breakpoints:
    #     print(f"[DIAGNOSTIC] Verifying {len(active_breakpoints)} 'ANC_' breakpoints:")
    #     for bp_id_val, bp_info_val in active_breakpoints.items():
    #         bp_obj = target.FindBreakpointByID(bp_id_val)
    #         if bp_obj and bp_obj.IsValid():
    #             print(f"  BP ID {bp_id_val} ({bp_info_val['name']} @ 0x{bp_info_val['address']:x}): "
    #                   f"Enabled={bp_obj.IsEnabled()}, Locations={bp_obj.GetNumLocations()}, HitCount={bp_obj.GetHitCount()}")
    #         else:
    #             print(f"  [ERROR] BP ID {bp_id_val} ({bp_info_val['name']}): Not found or invalid after creation.")


    print("[DEBUG] Continuing process execution (after initial setup)...")
    error = process.Continue()
    if error.Fail():
        print(f"[ERROR] Failed to continue process: {error.GetCString()}")
        if process and process.IsValid(): process.Detach()
        if platform.IsConnected(): platform.DisconnectRemote()
        lldb.SBDebugger.Destroy(debugger)
        return None
    print("[DEBUG] Process continued. Listening for events (breakpoints, etc.)...")

    event = lldb.SBEvent()
    try:
        while True:
            if listener.WaitForEvent(1, event): # 1 second timeout for event
                state_from_event = lldb.SBProcess.GetStateFromEvent(event)

                if state_from_event == lldb.eStateStopped:
                    stopped_thread = process.GetThreadAtIndex(1) # Often thread 1 is the main one, but check others
                    if not stopped_thread or not stopped_thread.IsValid() or stopped_thread.GetStopReason() == lldb.eStopReasonNone:
                        for i_thread in range(process.GetNumThreads()):
                            iter_thread = process.GetThreadAtIndex(i_thread)
                            if iter_thread.IsValid() and iter_thread.GetStopReason() != lldb.eStopReasonNone:
                                stopped_thread = iter_thread
                                break

                    if not stopped_thread or not stopped_thread.IsValid():
                        #print("[WARN] Process stopped but no valid thread found with a stop reason. Continuing if possible.")
                        if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                        continue

                    stop_reason = stopped_thread.GetStopReason()
                    current_frame_main_loop = stopped_thread.GetFrameAtIndex(0)

                    if stop_reason == lldb.eStopReasonBreakpoint:
                        bp_id_hit = stopped_thread.GetStopReasonDataAtIndex(0) # LLDB's reported BP ID for this hit
                        pc_address_of_stop_int = 0
                        pc_module_at_stop = None
                        pc_module_name_at_stop = "UnknownModuleAtPC"
                        pc_module_base_at_stop_int = lldb.LLDB_INVALID_ADDRESS
                        stored_bp_id_for_log = bp_id_hit # Default to LLDB reported, might be updated if resolved by PC

                        if current_frame_main_loop.IsValid():
                           pc_address_of_stop_int = current_frame_main_loop.GetPCAddress().GetLoadAddress(target)
                           pc_module_at_stop = current_frame_main_loop.GetModule()
                           if pc_module_at_stop and pc_module_at_stop.IsValid():
                               pc_mod_filespec = pc_module_at_stop.GetFileSpec()
                               if pc_mod_filespec:
                                   pc_module_name_at_stop = pc_mod_filespec.GetFilename()
                                   if not pc_module_name_at_stop: pc_module_name_at_stop = "UnnamedModuleAtPC"
                               pc_module_base_at_stop_int = get_module_base_address_int(target, pc_module_at_stop)

                        context_for_hit = None
                        # Try to find context using LLDB's reported bp_id_hit first
                        if bp_id_hit != 0 and bp_id_hit in g_temp_blr_x8_bp_context:
                            context_for_hit = g_temp_blr_x8_bp_context[bp_id_hit]
                            stored_bp_id_for_log = bp_id_hit
                            #print(f"[DEBUG] Breakpoint context found by LLDB reported ID {bp_id_hit} at Abs Addr: 0x{pc_address_of_stop_int:x}")
                        # If not found by ID (e.g. ID changed or 0), try to resolve by PC
                        elif pc_address_of_stop_int != 0:
                            # Check BLR X8 by PC offset
                            if pc_module_base_at_stop_int != lldb.LLDB_INVALID_ADDRESS:
                                offset_pc = pc_address_of_stop_int - pc_module_base_at_stop_int
                                pc_offset_hex = hex(offset_pc)
                                for temp_id, temp_ctx in g_temp_blr_x8_bp_context.items():
                                    if (temp_ctx.get("breakpoint_type") == "blr_x8" and
                                        temp_ctx.get("module_name") == pc_module_name_at_stop and
                                        temp_ctx.get("blr_instr_addr_offset") == pc_offset_hex):
                                        context_for_hit = temp_ctx
                                        stored_bp_id_for_log = temp_id
                                        #print(f"[DEBUG] Identified blr_x8 breakpoint by PC: {pc_module_name_at_stop}+{pc_offset_hex} (Abs: 0x{pc_address_of_stop_int:x}, Stored BP ID {temp_id})")
                                        break
                            # Check BL Target by absolute address
                            if not context_for_hit:
                                for temp_id, temp_ctx in g_temp_blr_x8_bp_context.items():
                                    if (temp_ctx.get("breakpoint_type") == "bl_target" and
                                        temp_ctx.get("bl_target_absolute_addr_val") == pc_address_of_stop_int):
                                        context_for_hit = temp_ctx
                                        stored_bp_id_for_log = temp_id
                                        #print(f"[DEBUG] Identified bl_target breakpoint by PC (absolute address): 0x{pc_address_of_stop_int:x} (Stored BP ID {temp_id})")
                                        break

                        # Case 1: ANC_ function hit
                        if bp_id_hit in active_breakpoints:
                            bp_info = active_breakpoints[bp_id_hit]
                            print(f"\n[HIT_ANC_FUNC] Entry: {bp_info['module_name']}::{bp_info['name']} (Abs Addr: 0x{bp_info['address']:x})")
                            function_symbol_from_bp_info = bp_info.get("symbol")

                            scan_symbol = None
                            if function_symbol_from_bp_info and function_symbol_from_bp_info.IsValid():
                                scan_symbol = function_symbol_from_bp_info
                            else:
                                symbol_from_frame = current_frame_main_loop.GetSymbol()
                                if symbol_from_frame and symbol_from_frame.IsValid() and \
                                   symbol_from_frame.GetStartAddress().GetLoadAddress(target) == bp_info['address']:
                                    scan_symbol = symbol_from_frame
                                else: # Fallback to PC address symbol
                                    pc_addr_obj = current_frame_main_loop.GetPCAddress()
                                    if pc_addr_obj and pc_addr_obj.IsValid():
                                        sym_at_pc = pc_addr_obj.GetSymbol()
                                        if sym_at_pc and sym_at_pc.IsValid() and \
                                           sym_at_pc.GetStartAddress().GetLoadAddress(target) == bp_info['address']:
                                            scan_symbol = sym_at_pc

                            if scan_symbol:
                                scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, scan_symbol, bp_info, recursion_depth=0)
                            else:
                                pass
                                #print(f"[WARN] No valid symbol for ANC function {bp_info['name']} at 0x{bp_info['address']:x}. Cannot scan for branches.")

                            #print(f"[INFO] ANC Function {bp_info['name']} processing finished. Auto-continuing...")
                            if process.IsValid() and not is_process_effectively_dead(process):
                                error_continue = process.Continue()
                                if error_continue.Fail(): print(f"[ERROR] Failed to continue after ANC_ BP hit: {error_continue.GetCString()}"); break
                            else: print("[INFO] Process no longer active after ANC_ BP hit. Exiting loop."); break
                            continue

                        # Case 2: Tracked breakpoint from g_temp_blr_x8_bp_context (BLR_X8 or BL_TARGET)
                        elif context_for_hit:
                            hit_bp_type = context_for_hit.get("breakpoint_type")

                            if hit_bp_type == "blr_x8":
                                ctx_module_name = context_for_hit["module_name"]
                                ctx_orig_func_name = context_for_hit["original_func_name"]
                                ctx_orig_func_addr_offset_hex = context_for_hit["original_func_addr_offset"]
                                ctx_blr_instr_addr_offset_hex = context_for_hit["blr_instr_addr_offset"]
                                ctx_recursion_depth = context_for_hit["recursion_depth"]

                                x8_reg = current_frame_main_loop.FindRegister("x8")
                                x8_value_int = 0; x8_read_success = False
                                x8_target_module_name_final = "NOT_APPLICABLE_OR_INVALID"; x8_target_offset_hex_final = "N/A"; x8_target_absolute_hex_final = "0x0"

                                if x8_reg.IsValid():
                                    x8_value_int = x8_reg.GetValueAsUnsigned()
                                    x8_read_success = True
                                    x8_target_absolute_hex_final = hex(x8_value_int)
                                    if x8_value_int != 0:
                                        address_at_x8 = target.ResolveLoadAddress(x8_value_int)
                                        if address_at_x8 and address_at_x8.IsValid():
                                            module_for_x8_target = address_at_x8.GetModule()
                                            if module_for_x8_target and module_for_x8_target.IsValid():
                                                x8_target_module_name_final = module_for_x8_target.GetFileSpec().GetFilename()
                                                if not x8_target_module_name_final: x8_target_module_name_final = "UnnamedModule"
                                                base_addr_for_x8_module = get_module_base_address_int(target, module_for_x8_target)
                                                if base_addr_for_x8_module != lldb.LLDB_INVALID_ADDRESS:
                                                    x8_target_offset_hex_final = hex(x8_value_int - base_addr_for_x8_module)
                                                else: x8_target_module_name_final += "_(BaseNotFound)"; x8_target_offset_hex_final = "OFFSET_UNKNOWN"
                                            else: x8_target_module_name_final = "TARGET_ADDRESS_NO_MODULE"
                                        else: x8_target_module_name_final = "INVALID_TARGET_ADDRESS"
                                    else: x8_target_module_name_final = "NULL_POINTER"
                                else: x8_target_absolute_hex_final = "ERROR_READING_X8"

                                #print(f"\n[BLR_X8_HIT] (Depth {ctx_recursion_depth}) From: {ctx_module_name}::{ctx_orig_func_name}+{ctx_orig_func_addr_offset_hex}")
                                #print(f"  BLR X8 instruction at: +{ctx_blr_instr_addr_offset_hex}")
                                #print(f"  X8 Target: Abs {x8_target_absolute_hex_final} ({x8_target_module_name_final}{'+'+x8_target_offset_hex_final if x8_target_offset_hex_final != 'N/A' else ''})")

                                hit_record = {
                                    "hit_type": "blr_x8", "hit_breakpoint_id": stored_bp_id_for_log, "timestamp": time.time(),
                                    "module_name": ctx_module_name, "original_func_name": ctx_orig_func_name,
                                    "original_func_addr_offset": ctx_orig_func_addr_offset_hex, "blr_instr_addr_offset": ctx_blr_instr_addr_offset_hex,
                                    "x8_target_absolute_address": x8_target_absolute_hex_final, "x8_target_module_name": x8_target_module_name_final,
                                    "x8_target_address_offset": x8_target_offset_hex_final, "recursion_depth_at_hit": ctx_recursion_depth
                                }
                                log_this_hit = not (g_blr_x8_hit_log and {k:v for k,v in hit_record.items() if k!="timestamp"} == {k:v for k,v in g_blr_x8_hit_log[-1].items() if k!="timestamp"})
                                if log_this_hit: g_blr_x8_hit_log.append(hit_record)

                                if x8_read_success and x8_value_int != 0 and ctx_recursion_depth < MAX_RECURSION_DEPTH:
                                    address_at_x8_for_recursion = target.ResolveLoadAddress(x8_value_int)
                                    symbol_at_x8 = address_at_x8_for_recursion.GetSymbol()
                                    if symbol_at_x8 and symbol_at_x8.IsValid() and symbol_at_x8.GetStartAddress().GetLoadAddress(target) == x8_value_int:
                                        target_func_name_rec = symbol_at_x8.GetName() or f"sub_0x{x8_value_int:x}"

                                        # --- CORRECTED PART ---
                                        sb_address_at_x8_start = symbol_at_x8.GetStartAddress()
                                        mod_for_rec_sym = None
                                        if sb_address_at_x8_start and sb_address_at_x8_start.IsValid():
                                            mod_for_rec_sym = sb_address_at_x8_start.GetModule()
                                        # --- END CORRECTED PART ---
                                        
                                        mod_name_rec_info = (mod_for_rec_sym.GetFileSpec().GetFilename() if mod_for_rec_sym and mod_for_rec_sym.IsValid() else None) or "UnknownModuleForX8Target"
                                        #print(f"  [RECURSIVE_SCAN_FROM_X8] Target 0x{x8_value_int:x} ({mod_name_rec_info}::{target_func_name_rec}). Next depth: {ctx_recursion_depth + 1}")
                                        recursive_func_info = {"name": target_func_name_rec, "address": x8_value_int, "module_name": mod_name_rec_info}
                                        scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, symbol_at_x8, recursive_func_info, ctx_recursion_depth + 1)
                                    # else:
                                        #print(f"  [RECURSIVE_SCAN_FROM_X8] Target 0x{x8_value_int:x} not a function start or no symbol. Skipping scan.")
                                # elif x8_value_int != 0 and ctx_recursion_depth >= MAX_RECURSION_DEPTH:
                                    #print(f"  [MAX_DEPTH_REACHED_X8] Max recursion depth {MAX_RECURSION_DEPTH} for X8 target 0x{x8_value_int:x}. No further scan.")

                                if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                                else: break
                                continue

                            elif hit_bp_type == "bl_target":
                                ctx_bl_target_module = context_for_hit["bl_target_module_name"]
                                ctx_bl_target_func = context_for_hit["bl_target_func_name"]
                                ctx_bl_target_abs_addr_val = context_for_hit["bl_target_absolute_addr_val"]
                                ctx_bl_target_abs_addr_hex = context_for_hit["bl_target_absolute_addr_hex"]
                                ctx_orig_func_for_bl = context_for_hit["original_func_name"]
                                ctx_orig_module_for_bl = context_for_hit["module_name"]
                                ctx_bl_instr_offset = context_for_hit["bl_instr_addr_offset"]
                                ctx_depth_at_bl_set = context_for_hit["recursion_depth"] # Depth of function containing BL

                                #print(f"\n[BL_TARGET_HIT] (Original scan depth {ctx_depth_at_bl_set})")
                                #print(f"  Target: {ctx_bl_target_module}::{ctx_bl_target_func} (Abs Addr: {ctx_bl_target_abs_addr_hex})")
                                #print(f"  BL was in: {ctx_orig_module_for_bl}::{ctx_orig_func_for_bl} at instr offset +{ctx_bl_instr_offset}")

                                hit_record = {
                                    "hit_type": "bl_target", "hit_breakpoint_id": stored_bp_id_for_log, "timestamp": time.time(),
                                    "bl_source_module": ctx_orig_module_for_bl, "bl_source_func": ctx_orig_func_for_bl,
                                    "bl_instr_offset": ctx_bl_instr_offset, "bl_target_abs_addr": ctx_bl_target_abs_addr_hex,
                                    "bl_target_module": ctx_bl_target_module, "bl_target_func": ctx_bl_target_func,
                                    "recursion_depth_at_hit": ctx_depth_at_bl_set # Depth of the function containing the BL
                                }
                                log_this_hit = not (g_blr_x8_hit_log and {k:v for k,v in hit_record.items() if k!="timestamp"} == {k:v for k,v in g_blr_x8_hit_log[-1].items() if k!="timestamp"})
                                if log_this_hit: g_blr_x8_hit_log.append(hit_record)

                                if ctx_depth_at_bl_set < MAX_RECURSION_DEPTH:
                                    symbol_at_bl_target_pc = current_frame_main_loop.GetSymbol()
                                    if symbol_at_bl_target_pc and symbol_at_bl_target_pc.IsValid() and \
                                       symbol_at_bl_target_pc.GetStartAddress().GetLoadAddress(target) == pc_address_of_stop_int and \
                                       pc_address_of_stop_int == ctx_bl_target_abs_addr_val: # Verify we are at the expected function start

                                        #print(f"  [RECURSIVE_SCAN_FROM_BL_TARGET] Function {ctx_bl_target_module}::{ctx_bl_target_func}. Next depth: {ctx_depth_at_bl_set + 1}")
                                        # Use context values for func_info as they were resolved when BP was set
                                        func_info_for_bl_scan = {
                                            "name": ctx_bl_target_func,
                                            "address": ctx_bl_target_abs_addr_val,
                                            "module_name": ctx_bl_target_module
                                        }
                                        scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, symbol_at_bl_target_pc, func_info_for_bl_scan, ctx_depth_at_bl_set + 1)
                                    # else:
                                        #print(f"  [RECURSIVE_SCAN_FROM_BL_TARGET] PC 0x{pc_address_of_stop_int:x} not at expected BL target symbol start ({ctx_bl_target_module}::{ctx_bl_target_func} at 0x{ctx_bl_target_abs_addr_val:x}). Skipping scan.")
                                # elif ctx_depth_at_bl_set >= MAX_RECURSION_DEPTH:
                                    #print(f"  [MAX_DEPTH_REACHED_BL_TARGET] Max recursion depth for BL target {ctx_bl_target_abs_addr_hex}. No further scan.")

                                if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                                else: break
                                continue

                        # Case 3: Untracked breakpoint
                        else:
                            #print(f"[WARN] Hit untracked breakpoint (Reported BP ID: {bp_id_hit}, PC: 0x{pc_address_of_stop_int:x} in {pc_module_name_at_stop}). Auto-continuing...")
                            if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                            else: break
                            continue

                    elif stop_reason == lldb.eStopReasonException or stop_reason == lldb.eStopReasonSignal:
                        stop_desc = stopped_thread.GetStopDescription(256)
                        print(f"[WARN] Process stopped due to signal/exception (Enum: {stop_reason}): {stop_desc}. Auto-continuing...")
                        if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                        else: break # Stop if process died
                        continue
                    else: # Other stop reasons
                        stop_desc_other = stopped_thread.GetStopDescription(256)
                        print(f"[INFO] Process stopped (Reason Enum: {stop_reason}, Description: {stop_desc_other}). Breaking event loop.")
                        if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                        else: break # Stop if process died
                        #break # Exit loop for other reasons

                elif state_from_event == lldb.eStateExited: print("[INFO] Process exited. Script ending."); break
                elif state_from_event == lldb.eStateDetached: print("[INFO] Process detached. Script ending."); break
                elif state_from_event == lldb.eStateCrashed: print("[ERROR] Process crashed. Script ending."); break
                elif state_from_event == lldb.eStateInvalid: print("[ERROR] Process state invalid. Script ending."); break
                # else:
                    #print(f"[DEBUG] Non-stopping event or unhandled state: {lldb.SBDebugger.StateAsCString(state_from_event)}")

            else: # WaitForEvent timed out
                if is_process_effectively_dead(process):
                    print(f"[INFO] Process no longer alive (State: {lldb.SBDebugger.StateAsCString(process.GetState())}). Event loop ending.")
                    break
                # else:
                    #print("[DEBUG] WaitForEvent timeout, process still alive. Continuing loop.")

    except KeyboardInterrupt:
        print("\n[INFO] User interrupt (Ctrl+C). Cleaning up...")
    except Exception as e:
        print(f"[FATAL_ERROR] Unhandled exception in event loop: {e}")
        traceback.print_exc()
    finally:
        print("[DEBUG] Entering 'finally' block for cleanup...")
        if process and process.IsValid():
            if not is_process_effectively_dead(process):
                print("[DEBUG] Detaching from process...")
                error = process.Detach()
                if error.Fail(): print(f"[ERROR] Failed to detach process: {error.GetCString()}")
                #else: print("[DEBUG] Process detached successfully.")
            #else:
                #print("[DEBUG] Process already dead or detached. No explicit detach needed.")

        if platform and platform.IsConnected():
            print("[DEBUG] Disconnecting remote platform...")
            platform.DisconnectRemote()

        if debugger:
            #print("[DEBUG] Destroying SBDebugger instance.")
            lldb.SBDebugger.Destroy(debugger)
            debugger = None

        print("[DEBUG] attach_and_debug_remote finished.")
    return process


if __name__ == "__main__":
    print("[DEBUG] --- main execution block started ---")

    if 'lldb' not in sys.modules or not hasattr(lldb, 'SBDebugger'):
        print("[FATAL] LLDB module not properly imported or initialized. Exiting.")
        sys.exit(1)

    lldb.SBDebugger.Initialize()

    ANDROID_DEVICE_SERIAL = "10ACC30KQG000MF" # Replace with your device serial or comment out if only one device
    LLDB_SERVER_URL = "connect://localhost:1234" # Default for lldb-server on device forwarded to localhost
    TARGET_PID = None # Set this to a specific PID to bypass auto-detection
    # TARGET_PID = 12345 # Example

    pid_to_use = TARGET_PID
    if not pid_to_use:
        print(f"[INFO] PID not manually specified. Attempting to find PID for 'face_service' on device {ANDROID_DEVICE_SERIAL}.")
        pid_to_use = get_face_service_pid(ANDROID_DEVICE_SERIAL)

    if pid_to_use:
        TARGET_LIBRARY_NAME = "libulk_ancbase.so" # Replace with your target library
        print(f"[INFO] Using PID: {pid_to_use}. Target library for ANC_ functions: {TARGET_LIBRARY_NAME}")
        attach_and_debug_remote(pid_to_use, TARGET_LIBRARY_NAME, ANDROID_DEVICE_SERIAL, LLDB_SERVER_URL)
    else:
        print(f"[ERROR] Failed to obtain target PID for 'face_service' or manually specified PID. "
              f"Please check device connection, adb setup, process name, root access for 'ps', or manually set TARGET_PID.")

    output_filename = "blr_x8_bl_analysis_dump.json"
    print(f"\n[INFO] Attempting to write analysis data to '{output_filename}'...")

    final_dump_data = {
        "breakpoint_definitions_and_context": g_temp_blr_x8_bp_context,
        "instruction_hit_log": g_blr_x8_hit_log
    }

    if g_temp_blr_x8_bp_context:
        print(f"\n[INFO] Summary of g_temp_blr_x8_bp_context ({len(g_temp_blr_x8_bp_context)} items):")
        count = 0
        for k, v_ctx in g_temp_blr_x8_bp_context.items():
            bp_type = v_ctx.get('breakpoint_type', 'unknown')
            if bp_type == "blr_x8":
                print(f"  BP_ID {k} (blr_x8): mod='{v_ctx.get('module_name', 'N/A')}', "
                      f"orig_func='{v_ctx.get('original_func_name', 'N/A')}+{v_ctx.get('original_func_addr_offset', 'N/A')}', "
                      f"blr_instr='+{v_ctx.get('blr_instr_addr_offset', 'N/A')}', depth={v_ctx.get('recursion_depth', -1)}")
            elif bp_type == "bl_target":
                print(f"  BP_ID {k} (bl_target): target='{v_ctx.get('bl_target_module_name', 'N/A')}::{v_ctx.get('bl_target_func_name', 'N/A')}' "
                      f"({v_ctx.get('bl_target_absolute_addr_hex', 'N/A')}), "
                      f"source_bl='{v_ctx.get('module_name', 'N/A')}::{v_ctx.get('original_func_name', 'N/A')}+{v_ctx.get('bl_instr_addr_offset', 'N/A')}', "
                      f"set_depth={v_ctx.get('recursion_depth', -1)}")
            else:
                print(f"  BP_ID {k} (unknown_type): {v_ctx}")
            count += 1
            if count >= 5 and len(g_temp_blr_x8_bp_context) > 5 :
                print(f"  ... and {len(g_temp_blr_x8_bp_context) - 5} more definition items.")
                break
    else:
        print("[INFO] g_temp_blr_x8_bp_context (definitions) is empty.")

    if g_blr_x8_hit_log:
        print(f"\n[INFO] Summary of g_blr_x8_hit_log ({len(g_blr_x8_hit_log)} items):")
        count = 0
        for hit in g_blr_x8_hit_log:
            try:
                timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hit.get('timestamp')))
            except (TypeError, ValueError):
                timestamp_str = "Invalid Timestamp"

            hit_type = hit.get('hit_type', 'unknown')
            if hit_type == "blr_x8":
                x8_target_module = hit.get('x8_target_module_name', 'N/A')
                x8_target_offset = hit.get('x8_target_address_offset', 'N/A')
                x8_target_absolute = hit.get('x8_target_absolute_address', 'N/A')

                x8_display_str = f"Abs:{x8_target_absolute}"
                if x8_target_module not in ["NOT_APPLICABLE_OR_INVALID", "INVALID_TARGET_ADDRESS", "TARGET_ADDRESS_NO_MODULE", "NULL_POINTER", "ERROR_READING_X8"] and \
                   x8_target_offset not in ["N/A", "OFFSET_UNKNOWN"]:
                    x8_display_str += f" ({x8_target_module}+{x8_target_offset})"
                elif x8_target_module not in ["NOT_APPLICABLE_OR_INVALID", "ERROR_READING_X8"]:
                    x8_display_str += f" ({x8_target_module})"

                print(f"  Hit @ {timestamp_str} (blr_x8): "
                      f"BP_ID {hit.get('hit_breakpoint_id', 'N/A')}, In: {hit.get('module_name', 'N/A')}::{hit.get('original_func_name', 'N/A')}, "
                      f"BLR at +{hit.get('blr_instr_addr_offset', 'N/A')}, x8->{x8_display_str}, depth_hit={hit.get('recursion_depth_at_hit', -1)}")
            elif hit_type == "bl_target":
                print(f"  Hit @ {timestamp_str} (bl_target): "
                      f"BP_ID {hit.get('hit_breakpoint_id', 'N/A')}, Target: {hit.get('bl_target_module', 'N/A')}::{hit.get('bl_target_func', 'N/A')} ({hit.get('bl_target_abs_addr', 'N/A')}), "
                      f"From BL in: {hit.get('bl_source_module', 'N/A')}::{hit.get('bl_source_func', 'N/A')}+{hit.get('bl_instr_offset', 'N/A')}, depth_scan={hit.get('recursion_depth_at_hit', -1)}")
            else:
                print(f"  Hit @ {timestamp_str} (unknown_type): {hit}")
            count += 1
            if count >= 5 and len(g_blr_x8_hit_log) > 5:
                print(f"  ... and {len(g_blr_x8_hit_log) - 5} more hit items.")
                break
    else:
        print("[INFO] g_blr_x8_hit_log is empty.")

    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(final_dump_data, f, indent=4, ensure_ascii=False, default=lambda o: "<not serializable>")
        print(f"[SUCCESS] Successfully wrote analysis data to {output_filename}")
    except Exception as e:
        print(f"[ERROR] Failed to write analysis data to {output_filename}: {e}")
        traceback.print_exc()

    lldb.SBDebugger.Terminate()
    print("[DEBUG] --- Script execution finished ---")