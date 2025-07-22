
#!/usr/bin/env python3
# @title Optimized Compute Optimizer Workflow

# ==============================================================================
# --- CRITICAL USER CONFIGURATION & !!! SEVERE SECURITY WARNING !!! ---
# ==============================================================================
# Your GitHub username.
GITHUB_USERNAME = "SAMOTHEDEVLOPER"

# !!! SEVERE SECURITY RISK !!!
# HARDCODING A PERSONAL ACCESS TOKEN (PAT) IS EXTREMELY DANGEROUS.
# If this script is ever made public, anyone can use this token to access
# and control your GitHub account and repositories.
#
# RECOMMENDED SAFER ALTERNATIVES:
# 1. Google Colab Secrets: In Colab, click the key icon on the left, add a
#    new secret named 'GITHUB_PAT', and paste your token there. Then access
#    it in the script with:
#    from google.colab import userdata
#    GITHUB_PAT = userdata.get('GITHUB_PAT')
#
# 2. Environment Variables: A more standard approach for local or server use.
#    Set the variable in your shell before running the script:
#    export GITHUB_PAT="ghp_YourActualPatTokenHere"
#
# This script will proceed with the hardcoded value as requested, but you
# have been strongly warned of the risks.
GITHUB_PAT = "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"

# The "owner/repository_name" for your private tool repository.
REPO_OWNER_AND_NAME = "SAMOTHEDEVLOPER/SearchModel"

# The name of the executable file that the 'make' command will produce.
CUSTOM_TOOL_NAME = "SearchModel"

# --- GPU WORKLOAD OPTIMIZATION PARAMETERS ---
TARGET_THREADS_PER_BLOCK = 512
TARGET_NUM_BLOCKS = 2560

# --- INPUT & PROCESSING PARAMETERS ---
# The target hash160 of the address you are searching for.
INPUT_TARGET_VERIFICATION_HASH = "105b7f253f0ebd7843adaebbd805c944bfb863e4"
# The full target address.
INPUT_TARGET_ADDRESS_IDENTIFIER = "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"
# The processing mode for the tool. Only "sequential" is implemented in this script.
PROCESSING_MODE = "sequential"
# The start and end of the key space to search, in hexadecimal.
INPUT_RANGE_START_HEX = "173C794974f00000000"
INPUT_RANGE_END_HEX   = "173c794FFFFFFFFFFFF"
# ==============================================================================
# --- END OF CONFIGURATION ---
# ==============================================================================

import os
import subprocess
import shutil
import binascii
import base58
import time
from pathlib import Path

# --- DERIVED CONFIGURATION & CONSTANTS (Derived from user settings above) ---
# Using pathlib.Path for robust and clean path manipulation.
BASE_DIR = Path("/content")
REPO_DIR = BASE_DIR / f"{CUSTOM_TOOL_NAME}-Cuda"
EXECUTABLE_PATH = REPO_DIR / CUSTOM_TOOL_NAME
OUTPUT_DATA_FILENAME = "computation_results.txt"
MATCH_INDICATOR_FILENAME = "result_indicator.found"
GPU_WORKLOAD_PARAMS = f"{TARGET_NUM_BLOCKS},{TARGET_THREADS_PER_BLOCK}"

# --- HELPER FUNCTIONS ---

def print_separator(title: str = ""):
    """Prints a formatted separator with an optional title."""
    print("\n" + "="*70)
    if title:
        print(f"--- {title} ---")
    print("="*70)

def run_command(command: list, cwd: Path = None, check: bool = True):
    """A helper to run shell commands and print their output."""
    print(f"Executing: {' '.join(command)}")
    if cwd:
        print(f"In directory: {cwd}")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
            cwd=cwd
        )
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(f"STDERR:\n{result.stderr.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Command failed with return code {e.returncode}")
        if e.stdout:
            print(f"STDOUT:\n{e.stdout.strip()}")
        if e.stderr:
            print(f"STDERR:\n{e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print(f"ERROR: Command not found: {command[0]}")
        return None

def get_gpu_ccap() -> str:
    """Detects GPU and returns its CUDA Compute Capability (CCAP)."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=gpu_name", "--format=csv,noheader"],
            capture_output=True, text=True, check=True
        )
        gpu_name = result.stdout.strip()
        print(f"  Detected GPU: {gpu_name}")

        if "A100" in gpu_name: return "80"
        if "A10G" in gpu_name: return "86"
        if "RTX 30" in gpu_name: return "86"
        if "L4" in gpu_name: return "89"
        if "T4" in gpu_name: return "75"
        if "RTX 20" in gpu_name: return "75"
        if "V100" in gpu_name: return "70"
        if "P100" in gpu_name: return "60"
        if "P4" in gpu_name: return "61"
        if "K80" in gpu_name: return "37"

        default_ccap = "75"
        print(f"  INFO: GPU '{gpu_name}' not in a specific map. Falling back to default CCAP {default_ccap}.")
        return default_ccap
    except Exception as e:
        default_ccap_on_error = "75"
        print(f"  WARNING: Could not determine GPU CCAP dynamically: {e}. Falling back to CCAP {default_ccap_on_error}.")
        return default_ccap_on_error

# --- WORKFLOW FUNCTIONS ---

def setup_environment():
    """Installs required system packages and Python libraries."""
    print_separator("Step 1: Installing System Prerequisites")
    run_command(["apt-get", "update", "-qq"])
    run_command(["apt-get", "install", "-y", "-qq", "libgmp-dev", "build-essential", "git"])
    run_command(["pip", "install", "-q", "base58"])
    print("System prerequisites installed.")

def clone_repository() -> Path | None:
    """Clones the specified git repository into a clean directory."""
    print_separator(f"Step 2: Acquiring Source Code for {CUSTOM_TOOL_NAME}")

    if REPO_DIR.exists():
        print(f"Removing existing directory: {REPO_DIR}")
        shutil.rmtree(REPO_DIR)

    # Construct the appropriate URL
    if not GITHUB_PAT or GITHUB_PAT == "ghp_REPLACE_THIS_WITH_YOUR_PAT":
        print("WARNING: GITHUB_PAT is not set. Attempting clone via public URL.")
        repo_url = f"https://github.com/{REPO_OWNER_AND_NAME}.git"
    else:
        repo_url = f"https://{GITHUB_USERNAME}:{GITHUB_PAT}@github.com/{REPO_OWNER_AND_NAME}.git"
        print(f"Cloning from private repository. URL: {repo_url.replace(GITHUB_PAT, '***PAT_REDACTED***')}")

    # Clone directly into the target directory
    result = run_command(["git", "clone", repo_url, str(REPO_DIR)], check=False)

    if result and result.returncode == 0:
        if not any(REPO_DIR.iterdir()):
             print(f"CRITICAL WARNING: Cloned directory '{REPO_DIR}' is empty.")
             return None
        print(f"Successfully cloned repository to: {REPO_DIR}")
        return REPO_DIR
    else:
        print(f"ERROR: git clone failed.")
        return None

def build_tool(repo_path: Path) -> Path | None:
    """Builds the executable from source using the Makefile."""
    print_separator(f"Step 3: Building {CUSTOM_TOOL_NAME}")

    # --- UPDATED LOGIC TO HANDLE NESTED SOURCE DIRECTORY ---
    # The source code and Makefile are in a subdirectory, not the repo root.
    source_subdir_name = "SearchModel-Cuda"
    source_dir = repo_path / source_subdir_name

    if not source_dir.is_dir():
        print(f"CRITICAL ERROR: Expected source subdirectory not found at: {source_dir}")
        return None

    makefile_path = source_dir / "Makefile"
    if not makefile_path.exists():
        print(f"CRITICAL ERROR: Makefile not found at the expected path: {makefile_path}.")
        return None

    nvcc_path = shutil.which("nvcc")
    if not nvcc_path:
        print("CRITICAL ERROR: 'nvcc' (NVIDIA CUDA Compiler) not found. Cannot build for GPU.")
        return None

    cuda_base_path = Path(nvcc_path).parent.parent
    ccap = get_gpu_ccap()
    print(f"Using CUDA from: {cuda_base_path}")
    print(f"Using Compute Capability (CCAP): {ccap}")

    # We run 'make' from within the source subdirectory, so we don't need a complex path for the -f flag.
    # 'make' will automatically find the 'Makefile' in its current directory.
    make_command = [
        "make", f"CUDA={cuda_base_path}", "gpu=1", f"CCAP={ccap}", "all"
    ]

    # Run the build command inside the source subdirectory
    result = run_command(make_command, cwd=source_dir, check=False)

    if result and result.returncode == 0:
        # The executable is built inside the source subdirectory.
        built_executable_path = source_dir / CUSTOM_TOOL_NAME

        if built_executable_path.exists():
            print(f"Build successful. Moving '{built_executable_path.name}' to '{repo_path}'.")
            # Move the executable up to the parent directory where the rest of the script expects it.
            shutil.move(str(built_executable_path), str(EXECUTABLE_PATH))

            print(f"SUCCESS. Executable is now at: {EXECUTABLE_PATH}")
            # Ensure it is executable
            EXECUTABLE_PATH.chmod(EXECUTABLE_PATH.stat().st_mode | 0o111)
            return EXECUTABLE_PATH
        else:
            print(f"ERROR: Build reported success, but executable '{built_executable_path.name}' not found in source directory.")
            return None
    else:
        print("ERROR: Build failed.")
        return None


def run_optimizer(executable: Path) -> bool:
    """Runs the compiled tool and monitors its output for a match."""
    print_separator(f"Step 4: Running {CUSTOM_TOOL_NAME} ({PROCESSING_MODE.upper()})")

    # Verify input parameters
    try:
        decoded_bytes = base58.b58decode_check(INPUT_TARGET_ADDRESS_IDENTIFIER)
        hash_from_addr = binascii.hexlify(decoded_bytes[1:]).decode('ascii')
        if hash_from_addr != INPUT_TARGET_VERIFICATION_HASH:
            print(f"WARNING: Hash mismatch! Addr hash '{hash_from_addr}' != Expected hash '{INPUT_TARGET_VERIFICATION_HASH}'.")
    except Exception as e:
        print(f"ERROR: Could not verify input address '{INPUT_TARGET_ADDRESS_IDENTIFIER}': {e}")
        return False

    # Prepare for the run
    run_directory = executable.parent
    output_file = run_directory / OUTPUT_DATA_FILENAME
    indicator_file = run_directory / MATCH_INDICATOR_FILENAME

    if output_file.exists(): output_file.unlink()
    if indicator_file.exists(): indicator_file.unlink()

    # Construct the command
    command = [
        "stdbuf", "-oL", f"./{executable.name}",
        "-g", "--gpui", "0", "--gpux", GPU_WORKLOAD_PARAMS,
        "-m", "address",
        "--range", f"{INPUT_RANGE_START_HEX}:{INPUT_RANGE_END_HEX}",
        "-o", OUTPUT_DATA_FILENAME,
        INPUT_TARGET_ADDRESS_IDENTIFIER
    ]

    print(f"Executing: {' '.join(command)}")
    print(f"In directory: {run_directory}")

    proc = subprocess.Popen(
        command,
        cwd=run_directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    potential_match_found = False
    match_keywords = ["PivK :", "Priv (WIF):", "Priv (HEX):"]

    # Process stdout in real-time
    if proc.stdout:
        for line in iter(proc.stdout.readline, ''):
            line_stripped = line.strip()
            print(line_stripped)  # Print all output for live monitoring

            if any(kw in line_stripped for kw in match_keywords):
                print("\n" + "!"*20 + " MATCH INDICATOR FOUND IN STDOUT! " + "!"*20)
                potential_match_found = True
                # Create indicator file immediately
                indicator_file.write_text(f"INDICATOR_IN_STDOUT_LINE: {line_stripped}")
                print(f"Created indicator file: {indicator_file}")

    stderr_output = proc.stderr.read() if proc.stderr else ""
    proc.wait() # Wait for the process to finish

    if stderr_output.strip() and "warning" not in stderr_output.lower():
        print(f"\n--- STDERR from process ---\n{stderr_output.strip()}")

    print(f"{PROCESSING_MODE.capitalize()} process finished with return code {proc.returncode}.")

    # Final check on the output file, in case stdout was missed
    if output_file.exists() and output_file.stat().st_size > 0:
        print(f"INFO: Output file '{output_file.name}' is not empty.")
        if not indicator_file.exists():
            indicator_file.write_text("INDICATOR_FROM_NON_EMPTY_OUTPUT_FILE")
            print(f"Created indicator file due to non-empty output: {indicator_file}")
        potential_match_found = True

    return potential_match_found


def review_results(run_had_match: bool):
    """Reviews output files and prints a final conclusion."""
    print_separator("Step 5: Reviewing Output")

    output_file = REPO_DIR / OUTPUT_DATA_FILENAME
    indicator_file = REPO_DIR / MATCH_INDICATOR_FILENAME

    match_by_indicator = indicator_file.exists()
    match_by_output_content = False

    if output_file.exists() and output_file.stat().st_size > 0:
        print(f"INFO: Output data file '{output_file}' is not empty. Contents:")
        content = output_file.read_text(encoding='utf-8', errors='ignore')
        print(content)
        match_by_output_content = True
    else:
        print(f"INFO: Output data file '{output_file}' is empty or does not exist.")

    print("\n--- CONCLUSION ---")
    if run_had_match or match_by_indicator or match_by_output_content:
        print(f"✅ SUCCESS: A potential match was found for '{INPUT_TARGET_ADDRESS_IDENTIFIER}'.")
        print("   Please review the output above and in the file 'computation_results.txt' carefully.")
    else:
        print(f"❌ No definitive match indicators were found for '{INPUT_TARGET_ADDRESS_IDENTIFIER}'.")
    print(f"=== {CUSTOM_TOOL_NAME} Workflow Concluded ===")


# --- MAIN EXECUTION BLOCK ---

def main():
    """Main function to orchestrate the entire workflow."""
    print_separator("Verifying Processing Unit (GPU) Availability")
    run_command(["nvidia-smi"], check=False)

    setup_environment()

    repo_path = clone_repository()
    if not repo_path:
        print("Halting workflow due to repository cloning failure.")
        return

    executable = build_tool(repo_path)
    if not executable:
        print("Halting workflow due to build failure.")
        return

    match_found = run_optimizer(executable)

    review_results(match_found)

if __name__ == "__main__":
    main()
