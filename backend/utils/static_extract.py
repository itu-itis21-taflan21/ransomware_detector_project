import hashlib
import pefile
import os
import re
from collections import Counter
from math import log2
# This file would be backend/utils/static_extract.py
# It contains the low-level PE parsing functions adapted from the user's script.

# --- Functions from user's static_extract.py (modified for individual use) ---

def calculate_hashes(file_path):
    """Calculate MD5 and SHA256 hashes."""
    with open(file_path, 'rb') as f:
        file_data = f.read()
        sha256 = hashlib.sha256(file_data).hexdigest()
        md5 = hashlib.md5(file_data).hexdigest()
    return sha256, md5

def extract_imports(file_path):
    """Extract imported functions for each DLL."""
    imports = {}
    try:
        pe = pefile.PE(file_path, fast_load=True)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imports[dll_name] = []
                for imp in entry.imports:
                    imports[dll_name].append(imp.name.decode('utf-8', errors='ignore') if imp.name else None)
    except Exception: # Broad exception for pefile errors
        pass # Imports will be empty
    finally:
        if 'pe' in locals() and pe:
            pe.close()
    return imports

def extract_exports(file_path):
    """Extract exported function names only."""
    exports = []
    try:
        pe = pefile.PE(file_path, fast_load=True)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8', errors='ignore'))
    except Exception:
        pass
    finally:
        if 'pe' in locals() and pe:
            pe.close()
    return exports

def find_entry_section(pe):
    """Identify the section containing the entry point."""
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        section_start = section.VirtualAddress
        section_end = section_start + section.Misc_VirtualSize
        if section_start <= entry_point < section_end:
            return section.Name.decode('utf-8', errors='replace').rstrip('\x00')
    return None

def extract_section_props(characteristics):
    """Decode section characteristics into human-readable properties."""
    props = []
    flags = {
        0x00000020: "CNT_CODE", 0x00000040: "CNT_INITIALIZED_DATA",
        0x00000080: "CNT_UNINITIALIZED_DATA", 0x02000000: "MEM_DISCARDABLE",
        0x04000000: "MEM_NOT_CACHED", 0x08000000: "MEM_NOT_PAGED",
        0x10000000: "MEM_SHARED", 0x20000000: "MEM_EXECUTE",
        0x40000000: "MEM_READ", 0x80000000: "MEM_WRITE",
    }
    for flag, name in flags.items():
        if characteristics & flag:
            props.append(name)
    return props

def decode_characteristics(characteristics, flags_map):
    props = []
    for flag, name in flags_map.items():
        if characteristics & flag:
            props.append(name)
    return props

def extract_pe_features(file_path):
    """Extract PE features using pefile."""
    general, header, section_details = {}, {}, {}
    try:
        pe = pefile.PE(file_path, fast_load=True)
        general = {
            'size': os.path.getsize(file_path),
            'vsize': pe.OPTIONAL_HEADER.SizeOfImage,
            'has_debug': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress),
            'exports': len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            'imports': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'has_relocations': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress),
            'has_resources': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress),
            'has_signature': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress),
            'has_tls': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress),
            'symbols': pe.FILE_HEADER.NumberOfSymbols,
        }
        machine_types = {0x014c: "I386", 0x0200: "IA64", 0x8664: "AMD64"}
        coff_characteristics_flags = {
            0x0001: "RELOCS_STRIPPED", 0x0002: "EXECUTABLE_IMAGE", 0x0004: "LINE_NUMS_STRIPPED",
            0x0008: "LOCAL_SYMS_STRIPPED", 0x0010: "AGGRESSIVE_WS_TRIM", 0x0020: "LARGE_ADDRESS_AWARE",
            0x0100: "BYTES_REVERSED_LO", 0x0200: "32BIT_MACHINE", 0x0400: "DEBUG_STRIPPED",
            0x0800: "REMOVABLE_RUN_FROM_SWAP", 0x1000: "NET_RUN_FROM_SWAP", 0x2000: "SYSTEM",
            0x4000: "DLL", 0x8000: "UP_SYSTEM_ONLY", 0x01000000: "BYTES_REVERSED_HI",
        }
        dll_characteristics_flags = {
            0x0040: "DYNAMIC_BASE", 0x0100: "NX_COMPAT", 0x0200: "NO_SEH", 0x0800: "TERMINAL_SERVER_AWARE",
        }
        subsystem_names = {
            1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS/2_CUI", 7: "POSIX_CUI",
            9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
            12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "BOOT_APPLICATION",
        }
        header = {
            'coff': {
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'machine': machine_types.get(pe.FILE_HEADER.Machine, "UNKNOWN"),
                'characteristics': decode_characteristics(pe.FILE_HEADER.Characteristics, coff_characteristics_flags),
            },
            'optional': {
                'subsystem': subsystem_names.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                'dll_characteristics': decode_characteristics(pe.OPTIONAL_HEADER.DllCharacteristics, dll_characteristics_flags),
                'magic': "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20b else "PE32",
                'major_image_version': pe.OPTIONAL_HEADER.MajorImageVersion,
                'minor_image_version': pe.OPTIONAL_HEADER.MinorImageVersion,
                'sizeof_code': pe.OPTIONAL_HEADER.SizeOfCode,
                'sizeof_headers': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'sizeof_heap_commit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                'major_linker_version': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'minor_linker_version': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'major_operating_system_version': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'minor_operating_system_version': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'major_subsystem_version': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'minor_subsystem_version': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            }
        }
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            sections.append({
                'name': name, 'vsize': section.Misc_VirtualSize, 'size': section.SizeOfRawData,
                'entropy': section.get_entropy(), 'props': extract_section_props(section.Characteristics)
            })
        section_details = {"entry": find_entry_section(pe), "sections": sections}
    except Exception: # Broad exception for pefile errors
        pass # Features will be empty or partially filled
    finally:
        if 'pe' in locals() and pe:
            pe.close()
    return general, header, section_details

def extract_data_directories(file_path):
    directory_data = []
    try:
        pe = pefile.PE(file_path, fast_load=True)
        # Using the pefile.DIRECTORY_ENTRY_NAMES list for consistent naming
        # Example: pefile.DIRECTORY_ENTRY_NAMES[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']] == 'IMAGE_DIRECTORY_ENTRY_IMPORT'
        
        target_dir_indices = [
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'], # Note: CERTIFICATE is often same index
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_ARCHITECTURE'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_GLOBALPTR'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'],
            # pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME_HEADER'] # If needed
        ]

        for idx in target_dir_indices:
            dir_name_const = pefile.DIRECTORY_ENTRY_NAMES[idx] # Get the constant string name
            if idx < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                directory_data.append({
                    "name": dir_name_const, 
                    "virtual_address": entry.VirtualAddress or 0,
                    "size": entry.Size or 0
                })
            else: # Should not happen if idx is from DIRECTORY_ENTRY map and pefile is consistent
                 directory_data.append({ "name": dir_name_const, "virtual_address": 0, "size": 0 })

    except AttributeError: # Handle cases where pefile.DIRECTORY_ENTRY might be missing some keys for older pefile versions
        print("Warning: pefile.DIRECTORY_ENTRY might be incomplete or PE structure is unusual.")
        # Fallback to manual name list if needed, but less robust
        # For now, we'll just let it pass if some constants are missing.
    except Exception as e:
        print(f"Error extracting data directories: {e}")
        pass # directory_data might be partially filled or empty
    finally:
        if 'pe' in locals() and pe:
            pe.close()
    return directory_data


def extract_strings(file_path):
    """Extract printable strings from a binary file."""
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        # Regex for printable ASCII strings (char codes 32-126) of length >= 4
        found_strings = re.findall(rb"[ !\"#\$%&\'\(\)\*\+,-\./0-9:;<=>\?@A-Z\[\\\]\^_`a-z\{\|\}~]{4,}", data)
        strings = [s.decode('ascii', errors='ignore') for s in found_strings] # Use ASCII for strict printable
    except Exception:
        pass
    return strings

def calculate_byte_entropy(data): # Takes data bytes, not file_path
    """Calculate the entropy of bytes."""
    if not data: return 0.0
    byte_count = Counter(data)
    total_bytes = len(data)
    entropy = -sum((count / total_bytes) * log2(count / total_bytes)
                   for count in byte_count.values() if count > 0)
    return entropy

def calculate_byte_histogram(data): # Takes data bytes, not file_path
    """Calculate the histogram of bytes."""
    histogram = [0] * 256
    for byte_val in data: # Iterate over integer byte values
        histogram[byte_val] += 1
    return histogram

def extract_byte_header(file_path):
    """Extract a main header with byte entropy and histogram."""
    byte_entropy_val = 0.0
    byte_histogram_val = [0] * 256
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if data:
            byte_entropy_val = calculate_byte_entropy(data)
            byte_histogram_val = calculate_byte_histogram(data)
    except Exception:
        pass
    return byte_histogram_val, byte_entropy_val

def compute_string_features(strings_list): # Takes list of strings
    """Compute features from extracted strings, aligning with pipeline's `printabledist`."""
    numstrings = len(strings_list)
    avlength = sum(len(s) for s in strings_list) / numstrings if numstrings > 0 else 0
    
    concatenated_strings = "".join(strings_list)
    printables_len = len(concatenated_strings) # Total length of all printable chars in strings

    entropy = 0.0
    if printables_len > 0:
        char_counts_for_entropy = Counter(concatenated_strings)
        entropy = -sum((count / printables_len) * log2(count / printables_len)
                       for count in char_counts_for_entropy.values() if count > 0)
        
    paths = sum(1 for s in strings_list if re.search(r'[a-zA-Z]:\\', s) or re.search(r'/[a-zA-Z0-9_.\-]+',s))
    urls = sum(1 for s in strings_list if re.search(r'https?://', s))
    registry = sum(1 for s in strings_list if re.search(r'HKEY_', s))
    mz_count = sum(1 for s in strings_list if "MZ" in s)

    # `printabledist` in your pipeline's `compute_string_features` (from static_extract.py main script)
    # creates `char_counts = [0] * 96` for ASCII 32 to 127.
    char_dist_pipeline = [0] * 96 # For ASCII 32 to 127 (ord(char) - 32)
    for s in strings_list:
        for char_val in s: # Iterate over characters
            char_ord = ord(char_val)
            if 32 <= char_ord < 128: # Printable ASCII
                char_dist_pipeline[char_ord - 32] += 1
    
    return {
        'numstrings': numstrings,
        'avlength': avlength,
        'printables': printables_len, 
        'entropy': entropy,
        'paths': paths,
        'urls': urls,
        'registry': registry,
        'MZ': mz_count,
        'printabledist': char_dist_pipeline, 
    }