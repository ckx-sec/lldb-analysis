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
MAX_RECURSION_DEPTH = 3
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

    print(f"[WARN] get_module_base_address_int: Failed to determine base address for module {module_name_for_debug}")
    return lldb.LLDB_INVALID_ADDRESS


def get_process_pid_by_name(device_serial, process_name_pattern):
    print(f"[DEBUG] get_process_pid_by_name: Finding process containing '{process_name_pattern}' on device '{device_serial}'")
    try:
        cmd = ["adb", "-s", device_serial, "shell", "su", "-c", f"ps -A | grep {process_name_pattern}"]
        print(f"[DEBUG] Executing command: {' '.join(cmd)}")
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
                            print(f"[DEBUG] Found matching process: '{command_name_candidate}' PID: {pid}, Line: {line.strip()}")
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
    if SYMBOL_TYPE_FUNCTION == 5 or SYMBOL_TYPE_CODE == 2: 
        print("[WARN] Using fallback integer values for symbol types (Function=5, Code=2). This might not be universally compatible if LLDB changes these constants.")

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
                    print(f"[WARN] Function {func_name} has invalid start address object. Skipping.")
                    continue

                load_addr_int = start_addr_obj.GetLoadAddress(target)
                if load_addr_int == lldb.LLDB_INVALID_ADDRESS:
                    print(f"[WARN] Function {func_name} has invalid load address. Skipping.")
                    continue

                if any(bp_data["address"] == load_addr_int for bp_data in breakpoints_info.values()):
                    continue

                bp = target.BreakpointCreateByAddress(load_addr_int)
                if bp and bp.IsValid() and bp.GetNumLocations() > 0:
                    actual_bp_addr_int = bp.GetLocationAtIndex(0).GetAddress().GetLoadAddress(target)
                    print(f"[DEBUG] Created breakpoint for ANC_ function {func_name} (0x{actual_bp_addr_int:x}), ID: {bp.GetID()}.")
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


# def scan_and_set_blr_x8_breakpoints(target, frame, function_symbol, func_info, recursion_depth=0):
#     global g_temp_blr_x8_bp_context

#     func_name = func_info['name']
    
#     if not function_symbol or not function_symbol.IsValid():
#         #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Received an invalid function_symbol object. Cannot proceed.")
#         return
        
#     symbol_address_obj = function_symbol.GetStartAddress()
    
#     containing_module = None
#     if symbol_address_obj and symbol_address_obj.IsValid():
#         containing_module = symbol_address_obj.GetModule()

#     if not containing_module or not containing_module.IsValid():
#         sym_name_for_warn = function_symbol.GetName() 
#         #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} (Symbol: {sym_name_for_warn}): Could not get valid module from symbol's address object. Cannot calculate offsets.")
#         return
        
#     containing_module_name = containing_module.GetFileSpec().GetFilename()
#     if not containing_module_name: containing_module_name = "UnknownModuleFromSymbol"

#     module_base_addr_int = get_module_base_address_int(target, containing_module)
#     if module_base_addr_int == lldb.LLDB_INVALID_ADDRESS:
#         #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} in module '{containing_module_name}': Could not determine module base address. Offsets will not be calculated for this scan.")
#         return 

#     func_start_addr_obj_from_symbol = function_symbol.GetStartAddress() 
#     func_end_addr_obj_from_symbol = function_symbol.GetEndAddress()

#     if not (func_start_addr_obj_from_symbol.IsValid() and func_end_addr_obj_from_symbol.IsValid()):
#         #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Start or end address from symbol is invalid. Cannot scan for blr x8.")
#         return

#     func_start_load_addr_int = func_start_addr_obj_from_symbol.GetLoadAddress(target)
#     func_end_load_addr_int = func_end_addr_obj_from_symbol.GetLoadAddress(target)

#     if func_start_load_addr_int == lldb.LLDB_INVALID_ADDRESS or func_end_load_addr_int == lldb.LLDB_INVALID_ADDRESS:
#         #print(f"[WARN] (Depth {recursion_depth}) Function {func_name}: Load address for start/end is invalid. Cannot scan for blr x8.")
#         return

#     if func_end_load_addr_int <= func_start_load_addr_int:
#         #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} (Abs: 0x{func_start_load_addr_int:x}): Invalid or zero size (End Abs: 0x{func_end_load_addr_int:x}). Cannot scan for blr x8.")
#         return

#     func_size = int(func_end_load_addr_int - func_start_load_addr_int)
#     #print(f"[DEBUG] (Depth {recursion_depth}) Scanning function {containing_module_name}::{func_name} (Abs: 0x{func_start_load_addr_int:x} - 0x{func_end_load_addr_int:x}, Size: {func_size} bytes) for 'blr x8'. Module base: 0x{module_base_addr_int:x}")

#     error = lldb.SBError()
#     instructions_data = target.ReadMemory(func_start_addr_obj_from_symbol, func_size, error)

#     if not error.Success():
#         #print(f"[WARN] (Depth {recursion_depth}) Failed to read memory for function {func_name}: {error.GetCString()}")
#         return

#     blr_x8_sequence = b'\x00\x01\x3f\xd6'
#     found_count = 0

#     for i in range(0, func_size - 3, 4):
#         instruction_bytes = instructions_data[i:i+4]
#         if instruction_bytes == blr_x8_sequence:
#             blr_actual_load_addr_int = func_start_load_addr_int + i
#             found_count += 1
            
#             offset_original_func_addr = func_start_load_addr_int - module_base_addr_int
#             offset_blr_instr_addr = blr_actual_load_addr_int - module_base_addr_int

#             #print(f"[DEBUG] (Depth {recursion_depth}) Found 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x} (Offset: +{hex(offset_blr_instr_addr)})")

#             is_duplicate_context = False
#             current_orig_func_offset_hex = hex(offset_original_func_addr)
#             current_blr_instr_offset_hex = hex(offset_blr_instr_addr)

#             for existing_bp_id, existing_ctx in g_temp_blr_x8_bp_context.items():
#                 if (existing_ctx.get("module_name") == containing_module_name and 
#                     existing_ctx.get("original_func_name") == func_name and
#                     existing_ctx.get("original_func_addr_offset") == current_orig_func_offset_hex and
#                     existing_ctx.get("blr_instr_addr_offset") == current_blr_instr_offset_hex):
#                     #print(f"[INFO] (Depth {recursion_depth}) Duplicate 'blr x8' context: Mod: {containing_module_name}, Func: {func_name}+{current_orig_func_offset_hex}, BLR: +{current_blr_instr_offset_hex}. Already tracked. Skipping.")
#                     is_duplicate_context = True
#                     break
            
#             if is_duplicate_context:
#                 continue

#             temp_bp = target.BreakpointCreateByAddress(blr_actual_load_addr_int) 
#             if temp_bp and temp_bp.IsValid():
#                 bp_id = temp_bp.GetID()
#                 g_temp_blr_x8_bp_context[bp_id] = {
#                     "module_name": containing_module_name,
#                     "original_func_name": func_name,
#                     "original_func_addr_offset": current_orig_func_offset_hex, 
#                     "blr_instr_addr_offset": current_blr_instr_offset_hex,   
#                     "recursion_depth": recursion_depth
#                 }
#                 #print(f"[DEBUG] (Depth {recursion_depth}) Set PERSISTENT breakpoint ID {bp_id} for 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x} (Offset: +{current_blr_instr_offset_hex})")
#             else:
#                 #print(f"[WARN] (Depth {recursion_depth}) Failed to create breakpoint for 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x}")
#                 pass
#     if found_count == 0:
#         #print(f"[DEBUG] (Depth {recursion_depth}) No 'blr x8' instructions found in {containing_module_name}::{func_name}.")
#         pass


def scan_and_set_blr_x8_breakpoints(target, frame, function_symbol, func_info, recursion_depth=0):
    global g_temp_blr_x8_bp_context, g_scanned_function_starts # <--- 引用新增的全局变量

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

    # 检查是否已扫描过此函数，避免重复工作
    if func_start_load_addr_int in g_scanned_function_starts:
        #print(f"[DEBUG] (Depth {recursion_depth}) Function {func_name} at 0x{func_start_load_addr_int:x} already scanned for branches. Skipping.")
        return

    containing_module = func_start_addr_obj_from_symbol.GetModule()
    if not containing_module or not containing_module.IsValid():
        sym_name_for_warn = function_symbol.GetName()
        #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} (Symbol: {sym_name_for_warn}): Could not get valid module from symbol's address object.")
        # We can still proceed if we have a valid func_start_load_addr_int and size, module info is for context.
        # However, module_base_addr_int calculation will fail.
        # For BLR X8 offset calculation, module base is important. For BL target resolution, not directly.
        # Let's allow proceeding but be aware that offset calculations might be affected for BLR X8.
        pass # Allow scan if module determination fails but addresses are fine

    containing_module_name = "UnknownModuleFromSymbol"
    module_base_addr_int = lldb.LLDB_INVALID_ADDRESS

    if containing_module and containing_module.IsValid():
        containing_module_name = containing_module.GetFileSpec().GetFilename()
        if not containing_module_name: containing_module_name = "UnknownModuleFromSymbol"
        module_base_addr_int = get_module_base_address_int(target, containing_module)
        if module_base_addr_int == lldb.LLDB_INVALID_ADDRESS:
            #print(f"[WARN] (Depth {recursion_depth}) Function {func_name} in module '{containing_module_name}': Could not determine module base address. Offsets for BLR X8 might not be calculated for this scan.")
            pass
            # continue with scan, but blr x8 context might lack offsets

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
        for i in range(0, func_size - 3, 4): # ARM64 instructions are 4 bytes
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
                    if (existing_ctx.get("module_name") == containing_module_name and
                        existing_ctx.get("original_func_name") == func_name and
                        existing_ctx.get("original_func_addr_offset") == offset_original_func_addr_str and # Use stringified hex offset
                        existing_ctx.get("blr_instr_addr_offset") == offset_blr_instr_addr_str):
                        #print(f"[INFO] (Depth {recursion_depth}) Duplicate 'blr x8' context: Mod: {containing_module_name}, Func: {func_name}+{offset_original_func_addr_str}, BLR: +{offset_blr_instr_addr_str}. Already tracked. Skipping.")
                        is_duplicate_context = True
                        break
                if is_duplicate_context:
                    continue

                temp_bp = target.BreakpointCreateByAddress(blr_actual_load_addr_int)
                if temp_bp and temp_bp.IsValid():
                    bp_id = temp_bp.GetID()
                    g_temp_blr_x8_bp_context[bp_id] = {
                        "module_name": containing_module_name,
                        "original_func_name": func_name,
                        "original_func_addr_offset": offset_original_func_addr_str,
                        "blr_instr_addr_offset": offset_blr_instr_addr_str,
                        "recursion_depth": recursion_depth # Depth at which this blr x8 was found
                    }
                    #print(f"[DEBUG] (Depth {recursion_depth}) Set PERSISTENT breakpoint ID {bp_id} for 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x} (Offset: +{offset_blr_instr_addr_str})")
                else:
                    #print(f"[WARN] (Depth {recursion_depth}) Failed to create breakpoint for 'blr x8' in {containing_module_name}::{func_name} at Abs: 0x{blr_actual_load_addr_int:x}")
                    pass
        if found_blr_x8_count == 0 and error.Success() : # Only print if memory read was successful
            #print(f"[DEBUG] (Depth {recursion_depth}) No 'blr x8' instructions found in {containing_module_name}::{func_name}.")
            pass

    # 2. 扫描 BL 指令 (使用 LLDB 反汇编)
    # SBAddress object for the start of the function is func_start_addr_obj_from_symbol
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
            # 检查是否是 BL 指令 (opcode: 100101xx...)
            # 获取指令的原始字节数据
            instr_data_reader = instr.GetData(target)
            error_instr_data = lldb.SBError()
            raw_instr_uint32 = instr_data_reader.GetUnsignedInt32(error_instr_data, 0)

            if error_instr_data.Success() and (raw_instr_uint32 & 0xFC000000) == 0x94000000:
                bl_found_count += 1
                # 是 BL 指令, 计算跳转目标地址
                # 26-bit signed immediate, scaled by 4
                offset = raw_instr_uint32 & 0x03FFFFFF  # Extract 26-bit immediate
                # Sign extend from 26 bits
                if (offset >> 25) & 1:  # Check the 25th bit (sign bit of the 26-bit immediate)
                    # Python handles large negative numbers automatically with bitwise ops if needed,
                    # but direct arithmetic after conversion to signed is cleaner.
                    # Convert to signed 26-bit value
                    if offset & (1 << 25): # If sign bit is set
                        signed_offset = offset - (1 << 26)
                    else:
                        signed_offset = offset
                else: # Already positive
                    signed_offset = offset

                bl_target_addr_int = instr_load_addr_int + (signed_offset * 4)

                #print(f"[DEBUG] (Depth {recursion_depth}) Found 'bl' in {containing_module_name}::{func_name} at 0x{instr_load_addr_int:x} targeting 0x{bl_target_addr_int:x}")

                if recursion_depth < MAX_RECURSION_DEPTH:
                    target_addr_sbaddr = target.ResolveLoadAddress(bl_target_addr_int)
                    if not target_addr_sbaddr or not target_addr_sbaddr.IsValid():
                        #print(f"[DEBUG] (Depth {recursion_depth}) BL target 0x{bl_target_addr_int:x} is not a valid load address. Skipping recursive scan.")
                        continue

                    target_symbol = target_addr_sbaddr.GetSymbol()

                    if target_symbol and target_symbol.IsValid() and \
                       target_symbol.GetStartAddress().GetLoadAddress(target) == bl_target_addr_int:
                        # 目标是另一个函数的起始点
                        target_func_name_rec = target_symbol.GetName()
                        if not target_func_name_rec: target_func_name_rec = f"sub_{bl_target_addr_int:x}"

                        target_module_obj = target_addr_sbaddr.GetModule()
                        target_module_name_rec = "UnknownTargetModule"
                        if target_module_obj and target_module_obj.IsValid():
                            target_module_name_rec = target_module_obj.GetFileSpec().GetFilename()
                            if not target_module_name_rec: target_module_name_rec = "UnnamedTargetModule"

                        #print(f"[DEBUG] (Depth {recursion_depth}) 'bl' target 0x{bl_target_addr_int:x} is start of function: {target_module_name_rec}::{target_func_name_rec}. Recursive scan (depth {recursion_depth + 1}).")

                        recursive_func_info = {
                            "name": target_func_name_rec,
                            "address": bl_target_addr_int, # Absolute load address
                            "module_name": target_module_name_rec
                        }
                        # 递归调用自身进行扫描
                        scan_and_set_blr_x8_breakpoints(target, frame, target_symbol, recursive_func_info, recursion_depth + 1)
                    else:
                        s_name = target_symbol.GetName() if target_symbol and target_symbol.IsValid() else "NoSymbol"
                        s_start = target_symbol.GetStartAddress().GetLoadAddress(target) if target_symbol and target_symbol.IsValid() and target_symbol.GetStartAddress().IsValid() else "N/A"
                        #print(f"[DEBUG] (Depth {recursion_depth}) 'bl' target 0x{bl_target_addr_int:x} is not a function start (Symbol: {s_name}, Starts at: {s_start if isinstance(s_start, int) else s_start}). Skipping recursive scan.")
                        pass
                elif recursion_depth >= MAX_RECURSION_DEPTH:
                    #print(f"[DEBUG] (Depth {recursion_depth}) Max recursion depth reached for 'bl' target 0x{bl_target_addr_int:x} from 0x{instr_load_addr_int:x}. Stopping this path.")
                    pass

        if bl_found_count == 0 and instructions_list and instructions_list.GetSize() > 0:
            #print(f"[DEBUG] (Depth {recursion_depth}) No 'bl' instructions found in {containing_module_name}::{func_name}.")
            pass

    # 标记此函数已扫描
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
    print(f"[DEBUG] SBDebugger created successfully. Valid: {debugger.IsValid()}")
    debugger.SetAsync(True)
    print("[DEBUG] SetAsync(True) called.")

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
        print(f"[DEBUG] 准备设置 ANDROID_SERIAL=\"{device_serial}\"") 
        os.environ["ANDROID_SERIAL"] = device_serial
        print(f"[DEBUG] ANDROID_SERIAL 已设置为 \"{device_serial}\"") 
    else:
        print("[DEBUG] 未提供 device_serial，跳过设置 ANDROID_SERIAL。") 

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
    print(f"[DEBUG] Target created successfully. Valid: {target.IsValid()}")

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
        print(f"[DEBUG] Waiting for initial stop... (Attempt {i_wait+1}/{MAX_INITIAL_STOP_WAITS})")
        if listener.WaitForEvent(2, event):
            state_from_event = lldb.SBProcess.GetStateFromEvent(event)
            print(f"[DEBUG] Event received. State from event: {lldb.SBDebugger.StateAsCString(state_from_event)}")
            if state_from_event == lldb.eStateStopped:
                print(f"[DEBUG] Initial stop event received. Process stopped.")
                initial_stop_received = True
                break
        else:
            current_process_state = process.GetState()
            print(f"[DEBUG] WaitForEvent timeout. Current process state: {lldb.SBDebugger.StateAsCString(current_process_state)}")
            if current_process_state == lldb.eStateStopped:
                print("[DEBUG] Process was already stopped.")
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
    print("[DEBUG] Initial process stop event handled.")

    print(f"[DEBUG] Setting breakpoints for library '{target_lib_name}'...")
    active_breakpoints = set_breakpoints_on_all_exported_functions(debugger, target, target_lib_name)
    if not active_breakpoints:
        print(f"[WARN] No 'ANC_' prefixed function breakpoints were set in '{target_lib_name}'.")
    
    if active_breakpoints:
        print(f"[DIAGNOSTIC] Verifying {len(active_breakpoints)} 'ANC_' breakpoints:")
        for bp_id_val, bp_info_val in active_breakpoints.items():
            bp_obj = target.FindBreakpointByID(bp_id_val)
            if bp_obj and bp_obj.IsValid():
                print(f"  BP ID {bp_id_val} ({bp_info_val['name']} @ 0x{bp_info_val['address']:x}): "
                      f"Enabled={bp_obj.IsEnabled()}, Locations={bp_obj.GetNumLocations()}, HitCount={bp_obj.GetHitCount()}")
            else:
                print(f"  [ERROR] BP ID {bp_id_val} ({bp_info_val['name']}): Not found or invalid after creation.")


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
            if listener.WaitForEvent(1, event):
                state_from_event = lldb.SBProcess.GetStateFromEvent(event)

                if state_from_event == lldb.eStateStopped:
                    stopped_thread = process.GetThreadAtIndex(1) 
                    if not stopped_thread or not stopped_thread.IsValid() or stopped_thread.GetStopReason() == lldb.eStopReasonNone:
                        for i_thread in range(process.GetNumThreads()):
                            iter_thread = process.GetThreadAtIndex(i_thread)
                            if iter_thread.IsValid() and iter_thread.GetStopReason() != lldb.eStopReasonNone:
                                stopped_thread = iter_thread
                                break
                    
                    if not stopped_thread or not stopped_thread.IsValid():
                        print("[WARN] Process stopped but no valid thread found with a stop reason. Continuing if possible.")
                        if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                        continue

                    stop_reason = stopped_thread.GetStopReason()
                    current_frame_main_loop = stopped_thread.GetFrameAtIndex(0)

                    if stop_reason == lldb.eStopReasonBreakpoint:
                        bp_id_hit = stopped_thread.GetStopReasonDataAtIndex(0)
                        pc_address_of_stop_int = 0
                        pc_module_at_stop = None
                        pc_module_name_at_stop = "UnknownModuleAtPC"
                        pc_module_base_at_stop_int = lldb.LLDB_INVALID_ADDRESS

                        if current_frame_main_loop.IsValid():
                           pc_address_of_stop_int = current_frame_main_loop.GetPCAddress().GetLoadAddress(target)
                           pc_module_at_stop = current_frame_main_loop.GetModule()
                           if pc_module_at_stop and pc_module_at_stop.IsValid():
                               pc_module_name_at_stop = pc_module_at_stop.GetFileSpec().GetFilename()
                               if not pc_module_name_at_stop: pc_module_name_at_stop = "UnnamedModuleAtPC" 
                               pc_module_base_at_stop_int = get_module_base_address_int(target, pc_module_at_stop)
                        
                        blr_x8_context_to_process = None
                        actual_bp_id_for_blr_x8_logic = None

                        if bp_id_hit in active_breakpoints:
                            bp_info = active_breakpoints[bp_id_hit] 
                            print(f"\n[HIT] ANC Function Entry: {bp_info['module_name']}::{bp_info['name']} (Abs Addr: 0x{bp_info['address']:x})")
                            function_symbol_from_bp_info = bp_info.get("symbol")

                            if function_symbol_from_bp_info and function_symbol_from_bp_info.IsValid():
                                scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, function_symbol_from_bp_info, bp_info, recursion_depth=0)
                            else: 
                                #print(f"[DEBUG] function_symbol_from_bp_info (Name: {bp_info['name']}) is None or invalid. Attempting to get symbol from frame.")
                                symbol_from_frame = current_frame_main_loop.GetSymbol() 
                                if symbol_from_frame.IsValid() and \
                                   symbol_from_frame.GetStartAddress().GetLoadAddress(target) == bp_info['address']:
                                    #print("[DEBUG] Using symbol from current frame for 'blr x8' scan.")
                                    scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, symbol_from_frame, bp_info, recursion_depth=0)
                                else:
                                    pc_at_bp_hit_addr = current_frame_main_loop.GetPCAddress() 
                                    symbol_at_pc = pc_at_bp_hit_addr.GetSymbol() if pc_at_bp_hit_addr and pc_at_bp_hit_addr.IsValid() else None 
                                    if symbol_at_pc and symbol_at_pc.IsValid() and \
                                       symbol_at_pc.GetStartAddress().GetLoadAddress(target) == bp_info['address']:
                                        #print("[DEBUG] Using symbol from PC Address for 'blr x8' scan.")
                                        scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, symbol_at_pc, bp_info, recursion_depth=0)
                                    else:
                                        s_from_frame_name = symbol_from_frame.GetName() if symbol_from_frame and symbol_from_frame.IsValid() else 'None/Invalid'
                                        s_at_pc_name = symbol_at_pc.GetName() if symbol_at_pc and symbol_at_pc.IsValid() else 'None/Invalid'
                                        fnc_sym_from_bp_info_type = type(function_symbol_from_bp_info) if function_symbol_from_bp_info is not None else 'NoneType'
                                        # print(f"[WARN] No valid symbol for function {bp_info['name']} at 0x{bp_info['address']:x}. "
                                        #       f"Symbol from bp_info (type): {fnc_sym_from_bp_info_type}. "
                                        #       f"Symbol from frame: {s_from_frame_name}. "
                                        #       f"Symbol at PC: {s_at_pc_name}. "
                                        #       "Cannot scan for 'blr x8'.")


                            print(f"[INFO] ANC Function {bp_info['name']} processing finished. Auto-continuing...")
                            if process.IsValid() and not is_process_effectively_dead(process):
                                error_continue = process.Continue() 
                                if error_continue.Fail():
                                    print(f"[ERROR] Failed to continue after ANC_ BP hit: {error_continue.GetCString()}")
                                    break 
                            else:
                                print("[INFO] Process no longer active after ANC_ BP hit. Exiting event loop.")
                                break
                            continue 

                        if bp_id_hit != 0 and bp_id_hit in g_temp_blr_x8_bp_context:
                            actual_bp_id_for_blr_x8_logic = bp_id_hit
                            blr_x8_context_to_process = g_temp_blr_x8_bp_context[actual_bp_id_for_blr_x8_logic]
                            #print(f"[DEBUG] Identified blr x8 breakpoint by reported ID {bp_id_hit} at Abs Addr: 0x{pc_address_of_stop_int:x}")
                        elif pc_address_of_stop_int != 0 and pc_module_base_at_stop_int != lldb.LLDB_INVALID_ADDRESS: 
                            offset_pc = pc_address_of_stop_int - pc_module_base_at_stop_int
                            pc_offset_hex = hex(offset_pc)
                            for temp_id, temp_ctx in g_temp_blr_x8_bp_context.items():
                                if (temp_ctx.get("module_name") == pc_module_name_at_stop and
                                    temp_ctx.get("blr_instr_addr_offset") == pc_offset_hex):
                                    actual_bp_id_for_blr_x8_logic = temp_id
                                    blr_x8_context_to_process = temp_ctx
                                    #print(f"[DEBUG] Identified blr x8 breakpoint by PC: {pc_module_name_at_stop}+{pc_offset_hex} (Abs: 0x{pc_address_of_stop_int:x}, Orig BP ID {temp_id}, LLDB rept ID {bp_id_hit})")
                                    break
                        
                        if blr_x8_context_to_process and actual_bp_id_for_blr_x8_logic is not None:
                            context = blr_x8_context_to_process
                            ctx_module_name = context["module_name"]
                            ctx_orig_func_name = context["original_func_name"]
                            ctx_orig_func_addr_offset_hex = context["original_func_addr_offset"]
                            ctx_blr_instr_addr_offset_hex = context["blr_instr_addr_offset"]
                            ctx_recursion_depth = context["recursion_depth"]

                            x8_reg = current_frame_main_loop.FindRegister("x8")
                            x8_value_int = 0
                            x8_read_success = False
                            
                            x8_target_module_name_final = "NOT_APPLICABLE_OR_INVALID" 
                            x8_target_offset_hex_final = "N/A"
                            x8_target_absolute_hex_final = "0x0"


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
                                                offset_for_x8_target = x8_value_int - base_addr_for_x8_module
                                                x8_target_offset_hex_final = hex(offset_for_x8_target)
                                            else: # Base address for x8 target module not found
                                                x8_target_module_name_final = f"{x8_target_module_name_final}_(BaseAddrNotFound)"
                                                x8_target_offset_hex_final = "OFFSET_UNKNOWN"
                                        else: # Address is valid but does not belong to any known module
                                             x8_target_module_name_final = "TARGET_ADDRESS_NO_MODULE"
                                             x8_target_offset_hex_final = "N/A" # Offset is not applicable
                                    else: # x8 value points to an invalid/unmapped address
                                        x8_target_module_name_final = "INVALID_TARGET_ADDRESS"
                                        x8_target_offset_hex_final = "N/A"
                                elif x8_value_int == 0 : # x8 is 0x0
                                     x8_target_module_name_final = "NULL_POINTER"


                                #print(f"\n[BLR_X8_HIT_MAIN_LOOP] (Depth {ctx_recursion_depth}) Context: {ctx_module_name}::{ctx_orig_func_name}+{ctx_orig_func_addr_offset_hex}")
                                #print(f"  Instruction: blr x8 at {ctx_module_name}+{ctx_blr_instr_addr_offset_hex}")
                                #print(f"  Register x8 points to: Abs {x8_target_absolute_hex_final} ({x8_target_module_name_final}+{x8_target_offset_hex_final if x8_target_offset_hex_final != 'N/A' else ''})")

                            else: # x8_reg not valid
                                #print(f"\n[BLR_X8_HIT_MAIN_LOOP] (Depth {ctx_recursion_depth}) Context: {ctx_module_name}::{ctx_orig_func_name}+{ctx_orig_func_addr_offset_hex}")
                                #print(f"  Instruction: blr x8 at {ctx_module_name}+{ctx_blr_instr_addr_offset_hex}")
                                #print(f"  [ERROR] Failed to read register x8.")
                                x8_target_absolute_hex_final = "ERROR_READING_X8" # Update for hit_record
                            
                            hit_record = {
                                "hit_breakpoint_id": actual_bp_id_for_blr_x8_logic,
                                "timestamp": time.time(),
                                "module_name": ctx_module_name,
                                "original_func_name": ctx_orig_func_name,
                                "original_func_addr_offset": ctx_orig_func_addr_offset_hex,
                                "blr_instr_addr_offset": ctx_blr_instr_addr_offset_hex,
                                "x8_target_absolute_address": x8_target_absolute_hex_final,
                                "x8_target_module_name": x8_target_module_name_final,     
                                "x8_target_address_offset": x8_target_offset_hex_final,   
                                "recursion_depth_at_hit": ctx_recursion_depth
                            }
                            log_this_hit = True
                            if g_blr_x8_hit_log: # 仅当日志非空时才比较
                                previous_hit = g_blr_x8_hit_log[-1]
                                
                                # 创建用于比较的字典副本，排除 'timestamp'
                                current_hit_comparable = {k: v for k, v in hit_record.items() if k != "timestamp"}
                                previous_hit_comparable = {k: v for k, v in previous_hit.items() if k != "timestamp"}

                                if current_hit_comparable == previous_hit_comparable:
                                    log_this_hit = False
                                    # 可以选择性地在这里加一个 print 语句来调试，表明跳过了记录
                                    # print(f"[DEBUG] Skipping duplicate blr_x8_hit_log entry for {ctx_orig_func_name} at {ctx_blr_instr_addr_offset_hex}")
                            
                            if log_this_hit:
                                g_blr_x8_hit_log.append(hit_record)

                            if not x8_read_success: 
                                if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                                continue 

                            if x8_value_int != 0 and ctx_recursion_depth < MAX_RECURSION_DEPTH:
                                #print(f"  Attempting recursive scan from x8 target 0x{x8_value_int:x} (next depth: {ctx_recursion_depth + 1})")
                                address_at_x8_for_recursion = target.ResolveLoadAddress(x8_value_int) 
                                symbol_at_x8 = address_at_x8_for_recursion.GetSymbol()

                                if symbol_at_x8 and symbol_at_x8.IsValid():
                                    symbol_start_addr_int = symbol_at_x8.GetStartAddress().GetLoadAddress(target)
                                    if symbol_start_addr_int == x8_value_int: 
                                        target_func_name_rec = symbol_at_x8.GetName()
                                        if not target_func_name_rec: target_func_name_rec = f"sub_0x{x8_value_int:x}"
                                        
                                        # Get module for symbol_at_x8 to pass to scan_and_set
                                        # module_name_rec will be derived inside scan_and_set_blr_x8_breakpoints from symbol_at_x8
                                        # but we can pre-fetch for func_info if needed, though scan_and_set primarily uses the symbol object.
                                        # For func_info, the module_name is mostly informational.
                                        temp_addr_for_mod_get = symbol_at_x8.GetStartAddress()
                                        temp_mod_for_rec = None
                                        if temp_addr_for_mod_get and temp_addr_for_mod_get.IsValid():
                                            temp_mod_for_rec = temp_addr_for_mod_get.GetModule()
                                        
                                        module_name_rec_for_info = "UnknownModuleForX8TargetFuncInfo"
                                        if temp_mod_for_rec and temp_mod_for_rec.IsValid():
                                            module_name_rec_for_info = temp_mod_for_rec.GetFileSpec().GetFilename()
                                            if not module_name_rec_for_info : module_name_rec_for_info = "UnnamedModuleForX8TargetFuncInfo"
                                        

                                        #print(f"  [RECURSIVE_MAIN_LOOP] x8 target 0x{x8_value_int:x} is start of function: {module_name_rec_for_info}::{target_func_name_rec}. Proceeding with scan.")
                                        
                                        recursive_func_info = { 
                                            "name": target_func_name_rec,
                                            "address": x8_value_int, 
                                            "module_name": module_name_rec_for_info # Informational for func_info
                                        }
                                        scan_and_set_blr_x8_breakpoints(target, current_frame_main_loop, symbol_at_x8, recursive_func_info, ctx_recursion_depth + 1)
                                    else:
                                        #print(f"  [RECURSIVE_MAIN_LOOP] x8 (0x{x8_value_int:x}) points into middle of symbol {symbol_at_x8.GetName()} (starts 0x{symbol_start_addr_int:x}). Skipping.")
                                        pass
                                else:
                                    #print(f"  [RECURSIVE_MAIN_LOOP] No valid symbol found at 0x{x8_value_int:x} or address not a function start. Skipping.")
                                    pass
                            elif x8_value_int != 0 and ctx_recursion_depth >= MAX_RECURSION_DEPTH:
                                #print(f"  [MAX_DEPTH_REACHED_MAIN_LOOP] Max recursion depth {MAX_RECURSION_DEPTH} for target 0x{x8_value_int:x}. Stopping.")
                                pass
                            
                            #print("-" * 30)
                            if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                            continue 
                        
                        else: 
                            print(f"[WARN] Hit truly untracked breakpoint (Reported ID: {bp_id_hit}, Abs Addr: 0x{pc_address_of_stop_int:x}). Auto-continuing...")
                            if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                            continue
                    
                    elif stop_reason == lldb.eStopReasonException or stop_reason == lldb.eStopReasonSignal:
                        stop_desc = stopped_thread.GetStopDescription(256) 
                        print(f"[WARN] Process stopped due to signal/exception (Enum: {stop_reason}): {stop_desc}. Auto-continuing...")
                        if process.IsValid() and not is_process_effectively_dead(process): process.Continue()
                        continue
                    else: 
                        stop_desc_other = stopped_thread.GetStopDescription(256) 
                        print(f"[INFO] Process stopped (Reason Enum: {stop_reason}, Description: {stop_desc_other}). Breaking event loop.")
                        break 
                
                elif state_from_event == lldb.eStateExited: print("[INFO] Process exited. Script ending."); break
                elif state_from_event == lldb.eStateDetached: print("[INFO] Process detached. Script ending."); break
                elif state_from_event == lldb.eStateCrashed: print("[ERROR] Process crashed. Script ending."); break
                elif state_from_event == lldb.eStateInvalid: print("[ERROR] Process state invalid. Script ending."); break
            
            else: 
                if is_process_effectively_dead(process):
                    print(f"[INFO] Process no longer alive (State: {lldb.SBDebugger.StateAsCString(process.GetState())}). Event loop ending.")
                    break
                
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
                else: print("[DEBUG] Process detached successfully.")
            else:
                print("[DEBUG] Process already dead or detached. No explicit detach needed.")
        
        if platform and platform.IsConnected(): 
            print("[DEBUG] Disconnecting remote platform...")
            platform.DisconnectRemote()
        
        if debugger: 
            print("[DEBUG] Destroying SBDebugger instance.")
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

    ANDROID_DEVICE_SERIAL = "10ACC30KQG000MF"  
    LLDB_SERVER_URL = "connect://localhost:1234" 
    TARGET_PID = None 
    # TARGET_PID = 12345 

    pid_to_use = TARGET_PID
    if not pid_to_use:
        print(f"[INFO] PID not manually specified. Attempting to find PID for 'face_service' on device {ANDROID_DEVICE_SERIAL}.")
        pid_to_use = get_face_service_pid(ANDROID_DEVICE_SERIAL)

    if pid_to_use:
        TARGET_LIBRARY_NAME = "libulk_ancbase.so" 
        print(f"[INFO] Using PID: {pid_to_use}. Target library for ANC_ functions: {TARGET_LIBRARY_NAME}")
        attach_and_debug_remote(pid_to_use, TARGET_LIBRARY_NAME, ANDROID_DEVICE_SERIAL, LLDB_SERVER_URL)
    else:
        print(f"[ERROR] Failed to obtain target PID for 'face_service' or manually specified PID. "
              f"Please check device connection, adb setup, process name, root access for 'ps', or manually set TARGET_PID.")
    
    output_filename = "blr_x8_analysis_dump.json"
    print(f"[INFO] Attempting to write analysis data to '{output_filename}'...")

    final_dump_data = {
        "blr_x8_breakpoint_definitions": g_temp_blr_x8_bp_context,
        "blr_x8_hits_log": g_blr_x8_hit_log
    }

    if g_temp_blr_x8_bp_context:
        print(f"[DEBUG] Content of g_temp_blr_x8_bp_context (definitions - first few items if large):")
        count = 0
        for k, v_ctx in g_temp_blr_x8_bp_context.items(): 
            print(f"  BP_ID {k}: module='{v_ctx.get('module_name', 'N/A')}', "
                  f"orig_func='{v_ctx.get('original_func_name', 'N/A')}+{v_ctx.get('original_func_addr_offset', 'N/A')}', "
                  f"blr_instr='+{v_ctx.get('blr_instr_addr_offset', 'N/A')}', depth={v_ctx.get('recursion_depth', -1)}")
            count += 1
            if count >= 5:
                if len(g_temp_blr_x8_bp_context) > 5:
                    print(f"  ... and {len(g_temp_blr_x8_bp_context) - 5} more definition items.")
                break
    else:
        print("[INFO] g_temp_blr_x8_bp_context (definitions) is empty.")

    if g_blr_x8_hit_log:
        print(f"[DEBUG] Content of g_blr_x8_hit_log (first few items if large):")
        count = 0
        for hit in g_blr_x8_hit_log:
            try:
                timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hit.get('timestamp')))
            except (TypeError, ValueError): 
                timestamp_str = "Invalid Timestamp"
            
            x8_target_module = hit.get('x8_target_module_name', 'N/A')
            x8_target_offset = hit.get('x8_target_address_offset', 'N/A')
            x8_target_absolute = hit.get('x8_target_absolute_address', 'N/A')
            
            x8_display_str = f"Abs:{x8_target_absolute}"
            if x8_target_module not in ["NOT_APPLICABLE_OR_INVALID", "INVALID_TARGET_ADDRESS", "TARGET_ADDRESS_NO_MODULE", "NULL_POINTER"] and \
               x8_target_offset != "N/A" and x8_target_offset != "OFFSET_UNKNOWN":
                x8_display_str += f" ({x8_target_module}+{x8_target_offset})"
            elif x8_target_module != "NOT_APPLICABLE_OR_INVALID": # Display module if known, even if offset is not
                x8_display_str += f" ({x8_target_module})"


            print(f"  Hit @ {timestamp_str}: "
                  f"BP_ID {hit.get('hit_breakpoint_id', 'N/A')}, Mod: {hit.get('module_name', 'N/A')}, "
                  f"BLR at +{hit.get('blr_instr_addr_offset', 'N/A')}, x8->{x8_display_str}")
            count += 1
            if count >= 5:
                if len(g_blr_x8_hit_log) > 5:
                    print(f"  ... and {len(g_blr_x8_hit_log) - 5} more hit items.")
                break
    else:
        print("[INFO] g_blr_x8_hit_log is empty.")
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(final_dump_data, f, indent=4, ensure_ascii=False) 
        print(f"[SUCCESS] Successfully wrote analysis data to {output_filename}")
    except Exception as e:
        print(f"[ERROR] Failed to write analysis data to {output_filename}: {e}")
        traceback.print_exc()
    
    lldb.SBDebugger.Terminate()
    print("[DEBUG] --- Script execution finished ---")