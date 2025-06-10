# backend/app.py
import os
import tempfile
import asyncio
import uuid
import shutil
import subprocess
import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from string import printable # For static feature engineering
from collections import Counter # For static feature engineering
import re # For static feature engineering

# Assuming your static_extract.py is in a 'utils' subdirectory
from utils.static_extract import (
    calculate_hashes, extract_pe_features, extract_data_directories,
    extract_strings, compute_string_features, extract_imports, extract_exports,
    extract_byte_header
)

# --- Configuration ---
MODELS_DIR = Path(__file__).parent / 'models' # Path relative to app.py
STATIC_MODEL_PATH = MODELS_DIR / 'static_model.pkl'
STATIC_SCALER_PATH = MODELS_DIR / 'static_scaler.pkl'
STATIC_PCA_PATH = MODELS_DIR / 'static_pca.pkl'
STATIC_DISCOVERED_FEATURES_PATH = MODELS_DIR / 'discovered_static_features.json'
# CRITICAL: This file MUST be created during your training pipeline.
# It should contain the list of column names of the data fed to the static_scaler.
STATIC_TRAINING_COLUMNS_PATH = MODELS_DIR / 'static_training_columns.pkl'


DYNAMIC_MODEL_PATH = MODELS_DIR / 'dynamic_tfidf_tuned_rf_model.joblib' # From your pipeline script
DYNAMIC_VECTORIZER_PATH = MODELS_DIR / 'dynamic_tfidf_vectorizer.joblib' # From your pipeline script
DYNAMIC_N_GRAM_SIZE = 3 # Must match training

CONFIDENCE_THRESHOLD = 0.70
CUCKOO_API_BASE_URL = os.getenv('CUCKOO_API_BASE_URL', 'http://192.168.0.21:4444') # User's Cuckoo port
CUCKOO_API_TOKEN = os.getenv('CUCKOO_API_TOKEN', 'wKKZELJ8IIeuWfGz8RtGBA') # User's token
CUCKOO_TASK_TIMEOUT = os.getenv('CUCKOO_TASK_TIMEOUT', '20') # Cuckoo analysis timeout for the task itself

# Ensure models directory exists
MODELS_DIR.mkdir(parents=True, exist_ok=True)


app = FastAPI(title='RansomwareDetectorAPI')

# CORS for Chrome extension
# REPLACE 'YOUR_EXTENSION_ID_HERE' with your actual Chrome extension ID once known
CHROME_EXT_ID = os.getenv("CHROME_EXT_ID", "YOUR_EXTENSION_ID_HERE") # Make it configurable
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"chrome-extension://{CHROME_EXT_ID}", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load Models and Preprocessors ---
static_model = None
static_scaler = None
static_pca = None
discovered_static_features = None
static_training_columns = None # For ensuring correct feature order for scaler
dynamic_model = None
dynamic_vectorizer = None

def load_artifacts():
    global static_model, static_scaler, static_pca, discovered_static_features, static_training_columns
    global dynamic_model, dynamic_vectorizer
    print("Loading all artifacts...")
    try:
        if STATIC_MODEL_PATH.exists():
            static_model = joblib.load(STATIC_MODEL_PATH)
            print(f"Static model loaded from {STATIC_MODEL_PATH}")
        else: print(f"Warning: Static model not found at {STATIC_MODEL_PATH}")

        if STATIC_SCALER_PATH.exists():
            static_scaler = joblib.load(STATIC_SCALER_PATH)
            print(f"Static scaler loaded from {STATIC_SCALER_PATH}")
        else: print(f"Warning: Static scaler not found at {STATIC_SCALER_PATH}")

        if STATIC_PCA_PATH.exists():
            static_pca = joblib.load(STATIC_PCA_PATH)
            print(f"Static PCA model loaded from {STATIC_PCA_PATH}")
        else: print(f"Warning: Static PCA model not found at {STATIC_PCA_PATH}")

        if STATIC_DISCOVERED_FEATURES_PATH.exists():
            with open(STATIC_DISCOVERED_FEATURES_PATH, 'r') as f:
                discovered_static_features = json.load(f)
            print(f"Discovered static features loaded from {STATIC_DISCOVERED_FEATURES_PATH}")
        else: print(f"Warning: Discovered static features not found at {STATIC_DISCOVERED_FEATURES_PATH}")

        if STATIC_TRAINING_COLUMNS_PATH.exists():
            static_training_columns = joblib.load(STATIC_TRAINING_COLUMNS_PATH)
            print(f"Static training columns loaded from {STATIC_TRAINING_COLUMNS_PATH}")
        elif hasattr(static_scaler, 'feature_names_in_') and static_scaler.feature_names_in_ is not None:
             static_training_columns = list(static_scaler.feature_names_in_) # Ensure it's a list
             print("Static training columns derived from scaler.feature_names_in_")
        else:
            print(f"CRITICAL Warning: Static training columns file not found at {STATIC_TRAINING_COLUMNS_PATH} and scaler has no feature_names_in_. Static analysis may fail or be incorrect.")


        if DYNAMIC_MODEL_PATH.exists():
            dynamic_model = joblib.load(DYNAMIC_MODEL_PATH)
            print(f"Dynamic model loaded from {DYNAMIC_MODEL_PATH}")
        else: print(f"Warning: Dynamic model not found at {DYNAMIC_MODEL_PATH}")

        if DYNAMIC_VECTORIZER_PATH.exists():
            dynamic_vectorizer = joblib.load(DYNAMIC_VECTORIZER_PATH)
            print(f"Dynamic TF-IDF vectorizer loaded from {DYNAMIC_VECTORIZER_PATH}")
        else: print(f"Warning: Dynamic TF-IDF vectorizer not found at {DYNAMIC_VECTORIZER_PATH}")
    except Exception as e:
        print(f"Error loading artifacts: {e}")


# --- Static Feature Engineering (Adapted from user's pipeline) ---
def extract_histogram_features_api(histogram): # From user's pipeline script
    if not histogram or len(histogram) != 256: hist_array = np.zeros(256)
    else: hist_array = np.array(histogram)
    if np.sum(hist_array) == 0: hist_array = np.zeros(256)
    hist_array = np.nan_to_num(hist_array)
    mean=np.mean(hist_array); median=np.median(hist_array); std_dev=np.std(hist_array); variance=np.var(hist_array)
    min_value=np.min(hist_array); max_value=np.max(hist_array); range_value=max_value-min_value; sum_value=np.sum(hist_array)
    try: percentile_25, percentile_50, percentile_75 = np.percentile(hist_array, [25, 50, 75])
    except IndexError: percentile_25, percentile_50, percentile_75 = 0, 0, 0
    mode_val = 0
    if hist_array.size > 0 and np.any(hist_array):
        # Ensure all values are non-negative for bincount
        clamped_hist_array = np.maximum(hist_array.astype(int), 0)
        counts = np.bincount(clamped_hist_array)
        if counts.size > 0:
            mode_val = np.argmax(counts)

    features = {"histogram_mean": mean, "histogram_median": median, "histogram_std_dev": std_dev,"histogram_variance": variance, "histogram_min": min_value, "histogram_max": max_value,"histogram_range": range_value, "histogram_sum": sum_value,"histogram_percentile_25": percentile_25, "histogram_percentile_50": percentile_50,"histogram_percentile_75": percentile_75, "histogram_mode": mode_val,}
    return features

def extract_printabledist_features_api(printabledist): # From user's pipeline script
    features = {}
    # User pipeline's compute_string_features generates a printabledist of length 96.
    default_dist_len = 96
    if not printabledist or len(printabledist) != default_dist_len or sum(printabledist) == 0: printabledist = [0] * default_dist_len

    printabledist_arr = np.array([x if isinstance(x, (int, float)) else 0 for x in printabledist])
    
    features["string_dist_min_freq"]=np.min(printabledist_arr)
    features["string_dist_max_freq"]=np.max(printabledist_arr)
    features["string_dist_mean_freq"]=np.mean(printabledist_arr)
    features["string_dist_variance_freq"]=np.var(printabledist_arr)
    features["string_dist_std_dev_freq"]=np.std(printabledist_arr)
    features["string_dist_median_freq"]=np.median(printabledist_arr)
    features["string_dist_range_freq"]=features["string_dist_max_freq"]-features["string_dist_min_freq"]
    features["string_dist_pos_max_freq"]=np.argmax(printabledist_arr) if printabledist_arr.size > 0 else 0
    features["string_dist_pos_min_freq"]=np.argmin(printabledist_arr) if printabledist_arr.size > 0 else 0
    features["string_dist_non_zero_count"]=np.count_nonzero(printabledist_arr)
    features["string_dist_proportion_non_zero"]=(
        features["string_dist_non_zero_count"]/len(printabledist_arr) if len(printabledist_arr) > 0 else 0
    )
    # The ASCII ranges part from user's pipeline `extract_printabledist_features` is complex
    # and requires the `printabledist` to be structured in a specific way (e.g., length 256 for full ASCII).
    # Since `compute_string_features` (utils) generates a `char_dist` of 96 (ASCII 32-127),
    # the specific group sums (letters, digits etc.) as in pipeline's `extract_printabledist_features`
    # would need careful reimplementation here if they are critical and were used in training.
    # For now, this simplified version is used. If those features are essential, align this.
    return features


def engineer_single_static_sample_api(sample_dict, discovered_features_loaded):
    # This is an adaptation of `engineer_features_for_sample` from user's pipeline
    engineered_sample = {}
    engineered_sample["identifier"]=sample_dict.get("sha256", "unknown_identifier")

    general = sample_dict.get("general", {})
    for key, value in general.items():
        feature_name = f"general_{key}"
        if isinstance(value, bool): engineered_sample[feature_name] = int(value)
        elif isinstance(value, (int, float)): engineered_sample[feature_name] = value
        else: engineered_sample[feature_name] = 0 

    hist_features = extract_histogram_features_api(sample_dict.get("histogram", []))
    engineered_sample.update(hist_features)

    header = sample_dict.get("header", {}); coff = header.get("coff", {}); optional = header.get("optional", {})
    current_machine = coff.get("machine")
    for machine_type in discovered_features_loaded.get("header_machines", []):
        safe_feature_name = re.sub(r'\W|^(?=\d)', '_', str(machine_type).strip())
        engineered_sample[f"header_machine_{safe_feature_name}"] = 1 if current_machine == machine_type else 0

    current_characteristics = set(c for c in coff.get("characteristics", []) if c)
    for char in discovered_features_loaded.get("header_characteristics", []):
        safe_feature_name = re.sub(r'\W|^(?=\d)', '_', str(char).strip())
        engineered_sample[f"header_characteristics_{safe_feature_name}"] = 1 if char in current_characteristics else 0

    current_subsystem = optional.get("subsystem")
    for subsystem in discovered_features_loaded.get("header_optional_subsystems", []):
        safe_feature_name = re.sub(r'\W|^(?=\d)', '_', str(subsystem).strip())
        engineered_sample[f"header_subsystem_{safe_feature_name}"] = 1 if current_subsystem == subsystem else 0

    current_dll_chars = set(d for d in optional.get("dll_characteristics", []) if d)
    for dll_char in discovered_features_loaded.get("header_optional_dll_characteristics", []):
        safe_feature_name = re.sub(r'\W|^(?=\d)', '_', str(dll_char).strip())
        engineered_sample[f"header_dll_characteristics_{safe_feature_name}"] = 1 if dll_char in current_dll_chars else 0

    sections_data = sample_dict.get("section", {}).get("sections", [])
    section_entropies, section_sizes = [], []

    for section_name_iter in discovered_features_loaded.get("sections", []):
        safe_section_name = re.sub(r'\W|^(?=\d)', '_', str(section_name_iter).strip())
        if not safe_section_name: continue
        engineered_sample[f'section_{safe_section_name}_present']=0
        engineered_sample[f'section_{safe_section_name}_size']=0
        engineered_sample[f'section_{safe_section_name}_entropy']=0
        engineered_sample[f'section_{safe_section_name}_vsize']=0
        for prop in discovered_features_loaded.get("section_props", []):
            safe_prop_name = re.sub(r'\W|^(?=\d)', '_', str(prop).strip())
            engineered_sample[f'section_{safe_section_name}_prop_{safe_prop_name}'] = 0

    for section in sections_data:
        name = section.get("name")
        if name and name in discovered_features_loaded.get("sections", []):
            safe_section_name = re.sub(r'\W|^(?=\d)', '_', str(name).strip())
            if not safe_section_name: continue
            engineered_sample[f'section_{safe_section_name}_present'] = 1
            size = section.get('size', 0); entropy = section.get('entropy', 0); vsize = section.get('vsize', 0)
            engineered_sample[f'section_{safe_section_name}_size'] = size if isinstance(size, (int, float)) else 0
            engineered_sample[f'section_{safe_section_name}_entropy'] = entropy if isinstance(entropy, (int, float)) else 0
            engineered_sample[f'section_{safe_section_name}_vsize'] = vsize if isinstance(vsize, (int, float)) else 0
            if isinstance(entropy, (int, float)): section_entropies.append(entropy)
            if isinstance(size, (int, float)): section_sizes.append(size)
            current_props = set(p for p in section.get('props', []) if p)
            for prop in discovered_features_loaded.get("section_props", []):
                safe_prop_name = re.sub(r'\W|^(?=\d)', '_', str(prop).strip())
                if not safe_prop_name: continue
                if prop in current_props:
                    engineered_sample[f'section_{safe_section_name}_prop_{safe_prop_name}'] = 1

    engineered_sample['section_count'] = len(sections_data)
    engineered_sample['section_total_size'] = sum(section_sizes)
    engineered_sample['section_avg_entropy'] = np.mean(section_entropies) if section_entropies else 0

    strings_data = sample_dict.get("strings", {}) # This comes from compute_string_features
    for key in ["numstrings","avlength","printables","entropy","paths","urls","registry","MZ"]:
        val = strings_data.get(key,0)
        engineered_sample[f"string_{key}"] = val if isinstance(val,(int,float)) else 0

    printabledist = strings_data.get("printabledist", []) # This is the 96-element list
    string_dist_features = extract_printabledist_features_api(printabledist)
    engineered_sample.update(string_dist_features)

    data_directories = sample_dict.get("data_directories", [])
    # Names from pefile.DIRECTORY_ENTRY_NAMES (e.g., "IMAGE_DIRECTORY_ENTRY_EXPORT")
    # The pipeline's `common_dirs` uses simplified names ("EXPORT").
    # `extract_data_directories` in utils now returns full constant names.
    # We need to map them to the feature names used in training.
    # Assuming training used simplified names for features.
    
    # Expected simplified names for feature construction (must match training)
    expected_simple_dir_names = ["EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG","ARCHITECTURE","GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","COM_DESCRIPTOR"]

    for simple_dir_name_for_feat in expected_simple_dir_names:
        safe_feat_name = re.sub(r'\W|^(?=\d)', '_', simple_dir_name_for_feat.strip())
        engineered_sample[f"datadirectory_{safe_feat_name}_virtual_address"]=0
        engineered_sample[f"datadirectory_{safe_feat_name}_size"]=0

    for directory in data_directories:
        dir_name_const = directory.get("name") # e.g., "IMAGE_DIRECTORY_ENTRY_EXPORT"
        if dir_name_const:
            # Convert constant name to simple name used for feature keys
            simple_name = dir_name_const.replace("IMAGE_DIRECTORY_ENTRY_", "")
            if simple_name in expected_simple_dir_names: # Check if this simple name is one we track
                safe_feat_name = re.sub(r'\W|^(?=\d)', '_', simple_name.strip())
                va=directory.get("virtual_address",0); size_val=directory.get("size",0)
                engineered_sample[f"datadirectory_{safe_feat_name}_virtual_address"] = va if isinstance(va,(int,float)) else 0
                engineered_sample[f"datadirectory_{safe_feat_name}_size"] = size_val if isinstance(size_val,(int,float)) else 0


    imports = sample_dict.get("imports", {}); sample_libs, sample_apis = set(), set()
    if imports:
        for lib, funcs in imports.items():
            if lib:
                lib_name = lib.lower()
                if lib_name in discovered_features_loaded.get("frequent_libraries", []):
                    sample_libs.add(lib_name)
                    if funcs:
                        for func in funcs:
                            if func:
                                func_name = func.lower()
                                if func_name in discovered_features_loaded.get("frequent_api_calls", []):
                                    sample_apis.add(func_name)
    engineered_sample["_libraries"] = list(sample_libs)
    engineered_sample["_api_calls"] = list(sample_apis)

    exports = sample_dict.get("exports", []); sample_exports = set()
    if exports:
        for ex in exports:
            if ex:
                ex_name = ex.lower()
                if ex_name in discovered_features_loaded.get("exports", []):
                    sample_exports.add(ex_name)
    engineered_sample["_exports"] = list(sample_exports)

    for key, value in engineered_sample.items():
        if key not in ["identifier", "_libraries", "_api_calls", "_exports"]:
            if not isinstance(value, (int, float, np.number)):
                try:
                    numeric_value = float(value)
                    engineered_sample[key] = 0 if np.isnan(numeric_value) or np.isinf(numeric_value) else numeric_value
                except (ValueError, TypeError): engineered_sample[key] = 0
            elif isinstance(value, (float, np.floating)) and (np.isnan(value) or np.isinf(value)):
                engineered_sample[key] = 0
    return engineered_sample


def create_feature_df_for_single_sample_api(engineered_sample_dict, discovered_features_loaded, training_feature_cols_list):
    if training_feature_cols_list is None:
        raise ValueError("`training_feature_cols_list` (columns before scaling) must be provided and loaded.")

    base_features_data = {k:v for k,v in engineered_sample_dict.items() if not k.startswith('_') and k != 'identifier'}

    one_hot_data = {}
    for lib in discovered_features_loaded.get("frequent_libraries", []):
        safe_lib_name=re.sub(r'\W|^(?=\d)','_',lib.strip())
        one_hot_data[f'lib_{safe_lib_name}'] = 1 if lib in engineered_sample_dict.get('_libraries', []) else 0
    for api in discovered_features_loaded.get("frequent_api_calls", []):
        safe_api_name=re.sub(r'\W|^(?=\d)','_',api.strip())
        one_hot_data[f'api_{safe_api_name}'] = 1 if api in engineered_sample_dict.get('_api_calls', []) else 0
    for ex in discovered_features_loaded.get("exports", []):
        safe_ex_name=re.sub(r'\W|^(?=\d)','_',ex.strip())
        one_hot_data[f'export_{safe_ex_name}'] = 1 if ex in engineered_sample_dict.get('_exports', []) else 0

    combined_features = {**base_features_data, **one_hot_data}
    single_sample_df = pd.DataFrame([combined_features])

    for col in training_feature_cols_list:
        if col not in single_sample_df.columns:
            single_sample_df[col] = 0 
    single_sample_df = single_sample_df[training_feature_cols_list] 

    single_sample_df = single_sample_df.fillna(0).replace([np.inf, -np.inf], 0)
    bool_cols = single_sample_df.select_dtypes(include='boolean').columns
    if not bool_cols.empty: single_sample_df[bool_cols] = single_sample_df[bool_cols].astype(int)

    return single_sample_df


def extract_raw_static_features_from_file(file_path: str) -> dict:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Sample file not found: {file_path}")

    imports = extract_imports(file_path)
    exports = extract_exports(file_path)
    byte_histogram, byte_entropy = extract_byte_header(file_path)
    sha256, md5 = calculate_hashes(file_path)
    general, header, section_details = extract_pe_features(file_path)
    directories = extract_data_directories(file_path)
    strings_list = extract_strings(file_path)
    string_features = compute_string_features(strings_list) # This will contain 'printabledist'

    return {
        "imports": imports, "exports": exports, "sha256": sha256, "md5": md5,
        "histogram": byte_histogram, "byteentropy": byte_entropy,
        "general": general, "header": header, "section": section_details,
        "data_directories": directories, "strings": string_features,
    }

def prepare_static_features_for_model(raw_static_data: dict):
    if not all([discovered_static_features, static_scaler, static_pca, static_training_columns]):
        missing = [name for name, var in [
            ("discovered_static_features", discovered_static_features),
            ("static_scaler", static_scaler), ("static_pca", static_pca),
            ("static_training_columns", static_training_columns)
        ] if var is None]
        raise RuntimeError(f"Static analysis artifacts not loaded properly. Missing: {', '.join(missing)}")

    engineered_single = engineer_single_static_sample_api(raw_static_data, discovered_static_features)
    feature_df_single = create_feature_df_for_single_sample_api(engineered_single, discovered_static_features, static_training_columns)

    scaled_features = static_scaler.transform(feature_df_single)
    pca_features = static_pca.transform(scaled_features)
    return pca_features

# --- Dynamic Feature Preparation ---
def parse_cuckoo_report_for_api_calls(cuckoo_report_json_str: str) -> list:
    try:
        report = json.loads(cuckoo_report_json_str)
        api_calls = []
        if 'behavior' in report and 'processes' in report['behavior']:
            for process in report['behavior']['processes']:
                if 'calls' in process:
                    for call in process['calls']:
                        if 'api' in call: api_calls.append(call['api'])
        if not api_calls: print("Warning: Could not extract API call sequence from Cuckoo report (behavior.processes.calls).")
        return api_calls
    except json.JSONDecodeError: print("Error: Could not decode Cuckoo JSON report."); return []
    except Exception as e: print(f"Error parsing Cuckoo report for API calls: {e}"); return []

def extract_ngrams_as_string_api(sequence: list, n: int):
    if not sequence or len(sequence) < n: return ""
    ngrams = ["_".join(sequence[i:i+n]) for i in range(len(sequence)-n+1)]
    return " ".join(ngrams)

def prepare_dynamic_features_for_model(cuckoo_report_json_str: str):
    if not dynamic_vectorizer: raise RuntimeError("Dynamic TF-IDF vectorizer not loaded properly.")
    api_sequence = parse_cuckoo_report_for_api_calls(cuckoo_report_json_str)
    ngram_doc = extract_ngrams_as_string_api(api_sequence, DYNAMIC_N_GRAM_SIZE)
    dynamic_features = dynamic_vectorizer.transform([ngram_doc])
    return dynamic_features

# --- Cuckoo Interaction ---
async def run_cuckoo_analysis(sample_path: str) -> str:
    task_create_url = f"{CUCKOO_API_BASE_URL}/tasks/create/file"
    auth_headers = {}
    if CUCKOO_API_TOKEN: auth_headers['Authorization'] = f'Bearer {CUCKOO_API_TOKEN}'

    cmd_submit_list = ['curl', '-s']
    for key, value in auth_headers.items(): cmd_submit_list.extend(['-H', f'{key}: {value}'])
    cmd_submit_list.extend(['-F', f'file=@{sample_path}'])
    cmd_submit_list.extend(['-F', f'timeout={CUCKOO_TASK_TIMEOUT}'])
    cmd_submit_list.extend(['-F', 'enforce_timeout=true'])
    cmd_submit_list.append(task_create_url)
    print(f"Submitting to Cuckoo: {' '.join(cmd_submit_list)}") # For debug

    proc_submit = await asyncio.to_thread(subprocess.run, cmd_submit_list, capture_output=True, text=True, check=False)

    if proc_submit.returncode != 0 or not proc_submit.stdout:
        err_msg = f"Cuckoo task submission failed. Code: {proc_submit.returncode}. Stderr: {proc_submit.stderr or 'N/A'}. Stdout: {proc_submit.stdout or 'N/A'}"
        print(err_msg)
        raise RuntimeError(err_msg)

    try:
        response_json = json.loads(proc_submit.stdout)
        task_id = response_json.get('task_id')
        if not task_id: raise ValueError(f"task_id not found in Cuckoo submission response: {proc_submit.stdout}")
    except (json.JSONDecodeError, ValueError) as e:
        err_msg = f"Could not get task_id from Cuckoo response: {proc_submit.stdout}. Error: {e}"
        print(err_msg)
        raise RuntimeError(err_msg)

    print(f"Cuckoo task created with ID: {task_id}")
    task_report_url = f"{CUCKOO_API_BASE_URL}/tasks/report/{task_id}/json"

    for attempt in range(20): # Max 200s polling + Cuckoo task timeout
        await asyncio.sleep(10)
        print(f"Fetching Cuckoo report for task {task_id}, attempt {attempt + 1} from {task_report_url}")
        cmd_report_list = ['curl', '-s']
        for key, value in auth_headers.items(): cmd_report_list.extend(['-H', f'{key}: {value}'])
        cmd_report_list.append(task_report_url)
        
        proc_report = await asyncio.to_thread(subprocess.run, cmd_report_list, capture_output=True, text=True, check=False)

        if proc_report.returncode == 0 and proc_report.stdout:
            try:
                report_data_try = json.loads(proc_report.stdout)
                # Check for a key that indicates a full, valid report (e.g. 'target' or 'behavior')
                if "target" in report_data_try and "info" in report_data_try:
                    print(f"Cuckoo report for task {task_id} obtained.")
                    return proc_report.stdout
                else:
                    status = report_data_try.get("message", "Report not complete or in unexpected format.")
                    print(f"Cuckoo report for {task_id} partial/not ready. Message: {status}")
            except json.JSONDecodeError:
                if "not found" in proc_report.stdout.lower() or "pending" in proc_report.stdout.lower() or "still processing" in proc_report.stdout.lower():
                    print(f"Cuckoo report for {task_id} not ready yet (non-JSON): {proc_report.stdout[:100]}")
                    continue
                else: print(f"Cuckoo report for {task_id} was not valid JSON and not a known pending message: {proc_report.stdout[:200]}")
        else:
            print(f"Cuckoo report fetch attempt failed for {task_id}. Code:{proc_report.returncode} Stdout: {proc_report.stdout[:100]}, Stderr: {proc_report.stderr[:100]}")
            if proc_report.returncode == 0 and ("not found" in proc_report.stdout.lower()): # Sometimes 200 OK with "not found"
                 print(f"Cuckoo report for {task_id} not found yet (200 OK but content indicates not ready).")

    raise RuntimeError(f'Cuckoo analysis timeout or persistent error for task_id {task_id}')

# --- API Endpoints ---
@app.on_event("startup")
async def startup_event():
    load_artifacts()
    if not all([static_model, static_scaler, static_pca, discovered_static_features, static_training_columns]):
        print("WARNING: Not all static analysis artifacts loaded. Static analysis may fail.")
    if not all([dynamic_model, dynamic_vectorizer]):
        print("WARNING: Not all dynamic analysis artifacts loaded. Dynamic analysis may fail.")

@app.get("/")
async def root(): return {"message": "Ransomware Detection API is running."}

@app.post('/scan')
async def scan_file(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    if not file.filename: raise HTTPException(status_code=400, detail="No file provided.")
    if not (file.filename.lower().endswith('.exe') or file.filename.lower().endswith('.dll')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .exe or .dll supported.")

    temp_dir = tempfile.mkdtemp(prefix="ransomscan_")
    temp_file_path = os.path.join(temp_dir, file.filename)
    try:
        with open(temp_file_path, 'wb') as tmp: shutil.copyfileobj(file.file, tmp)
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Could not save uploaded file: {e}")
    finally: file.file.close()

    print(f"File saved to: {temp_file_path}")
    verdict, confidence_malicious, stage, analysis_error_detail = 'unknown', 0.0, 'static', None

    if all([static_model, static_scaler, static_pca, discovered_static_features, static_training_columns]):
        try:
            print("Performing static analysis...")
            raw_static_data = extract_raw_static_features_from_file(temp_file_path)
            static_features_vec = prepare_static_features_for_model(raw_static_data)
            confidence_malicious = float(static_model.predict_proba(static_features_vec)[0][1])
            if confidence_malicious >= CONFIDENCE_THRESHOLD: verdict = 'malicious'
            elif confidence_malicious <= (1.0 - CONFIDENCE_THRESHOLD): verdict = 'benign'
            else: verdict = 'low_confidence_static'
            print(f"Static result: {verdict}, Confidence(malicious): {confidence_malicious:.4f}")
        except Exception as e:
            print(f"Error during static analysis: {e}"); import traceback; traceback.print_exc()
            analysis_error_detail = f"Static analysis failed: {str(e)}"; verdict = 'error_static'
    else:
        analysis_error_detail = "Static model/preprocessors not fully available."
        print(f"Skipping static analysis: {analysis_error_detail}"); verdict = 'error_static_unavailable'

    if verdict in ['low_confidence_static', 'error_static'] and all([dynamic_model, dynamic_vectorizer]):
        job_id = str(uuid.uuid4())
        background_tasks.add_task(run_dynamic_analysis_pipeline, temp_file_path, job_id, temp_dir)
        print(f"Static outcome '{verdict}'. Queued for dynamic analysis (Job ID: {job_id})")
        return JSONResponse(status_code=202, content={
            'status': 'queued_for_dynamic', 'job_id': job_id,
            'static_confidence_malicious': confidence_malicious if verdict != 'error_static' else None,
            'static_verdict_pre_dynamic': verdict,
            'message': 'File queued for dynamic analysis. Check result later.'})
    else:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if verdict.startswith('error_'):
            return JSONResponse(status_code=500, content={'status': 'error', 
            'message': 'Analysis incomplete or failed at static stage.', 
            'detail': analysis_error_detail, 'final_verdict': 'unknown'})
        return JSONResponse(status_code=200, content={'status': 'completed_static', 
            'verdict': verdict, 'confidence_malicious': confidence_malicious, 'stage': stage})

JOB_RESULTS = {}

async def run_dynamic_analysis_pipeline(sample_path: str, job_id: str, temp_dir_to_clean: str):
    print(f"BG Task: Dynamic analysis for job {job_id}, sample {sample_path}")
    JOB_RESULTS[job_id] = {'status': 'processing_dynamic', 'message': 'Dynamic analysis in progress...'}
    try:
        cuckoo_report_json_str = await run_cuckoo_analysis(sample_path)
        JOB_RESULTS[job_id].update({'message': 'Cuckoo report received, preparing features...'})
        dynamic_features_vec = prepare_dynamic_features_for_model(cuckoo_report_json_str)
        dynamic_confidence_mal = float(dynamic_model.predict_proba(dynamic_features_vec)[0][1])
        dynamic_verdict = 'malicious' if dynamic_confidence_mal >= CONFIDENCE_THRESHOLD else 'benign'
        JOB_RESULTS[job_id] = {'status': 'completed_dynamic', 'verdict': dynamic_verdict, 
                               'confidence_malicious': dynamic_confidence_mal, 'stage': 'dynamic'}
        print(f"Dynamic analysis for job {job_id} OK. Verdict: {dynamic_verdict}, Conf(mal): {dynamic_confidence_mal:.4f}")
    except Exception as e:
        err_msg = f"Error in dynamic pipeline for job {job_id}: {str(e)}"; import traceback; traceback.print_exc()
        print(err_msg); JOB_RESULTS[job_id] = {'status': 'error_dynamic', 'error_message': err_msg, 'verdict':'unknown'}
    finally:
        shutil.rmtree(temp_dir_to_clean, ignore_errors=True)
        print(f"Cleaned temp dir: {temp_dir_to_clean} for job {job_id}")

@app.get('/result/{job_id}')
async def get_analysis_result(job_id: str):
    result = JOB_RESULTS.get(job_id)
    if not result: raise HTTPException(status_code=404, detail="Job ID not found.")
    return JSONResponse(content=result)

if __name__ == '__main__':
    import uvicorn
    print("Starting Uvicorn server for Ransomware Detection API...")
    if not STATIC_TRAINING_COLUMNS_PATH.exists() and not (static_scaler and hasattr(static_scaler, 'feature_names_in_') and static_scaler.feature_names_in_ is not None):
         print(f"CRITICAL: {STATIC_TRAINING_COLUMNS_PATH} not found and scaler has no feature_names_in_."
               "Static analysis WILL LIKELY FAIL. Please generate this file during training.")
    uvicorn.run(app, host="0.0.0.0", port=8000)