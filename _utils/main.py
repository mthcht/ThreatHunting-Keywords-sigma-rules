import subprocess

# List of python scripts to run in order
scripts = ["download_hunting_keywords.py","create_json_files.py","create_sigma_rules.py"]

for script in scripts:
    print(f"Running {script}...")
    result = subprocess.run(['python', script])
    if result.returncode != 0:
        print(f"Script {script} failed with return code {result.returncode}. Stopping execution.")
        break
    else:
        print(f"Script {script} executed successfully.")