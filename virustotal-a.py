import sys
import vt
import os
import time
import hashlib
import json


# Load API key from config.json
def load_api_key():
    config_file = os.path.join(
        os.getenv("APPDATA"), "VirusTotal Scanner", "config.json"
    )

    # If the config.json file does not exist, create it with a placeholder
    if not os.path.exists(config_file):
        default_config = {"api_key": "YOUR_API_KEY_HERE"}
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=4)

    # Load the configuration
    with open(config_file, "r") as f:
        config = json.load(f)

    # Check if the API key is the placeholder and prompt the user to enter their API key
    if config.get("api_key") == "YOUR_API_KEY_HERE":
        print("API key not found. Please enter your VirusTotal API key.")
        api_key = input("Enter your API key: ").strip()

        # Update the config.json file with the provided API key
        config["api_key"] = api_key
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)

        print("API key saved successfully.")

    return config.get("api_key")


# Assign API_KEY
API_KEY = load_api_key()

MAX_WAIT_TIME = 600  # Maximum time to wait for the scan result


# Function to calculate SHA-256 hash of a file
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Function to scan the file with VirusTotal API
def scan_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: The file {file_path} does not exist.")
        return

    file_sha256 = calculate_sha256(file_path)
    print(f"Calculated file SHA-256: {file_sha256}")

    with vt.Client(API_KEY) as client:
        print(f"Uploading and scanning file: {file_path}")

        try:
            with open(file_path, "rb") as f:
                analysis = client.scan_file(f)

            print("File uploaded successfully. Waiting for analysis to complete...")

            start_time = time.time()
            while True:
                if time.time() - start_time > MAX_WAIT_TIME:
                    print("Error: Analysis is taking too long. Exiting.")
                    return

                analysis = client.get_object(f"/analyses/{analysis.id}")
                print(f"Current analysis status: {analysis.status}")

                if analysis.status == "completed":
                    print("Analysis complete!")
                    break
                else:
                    print("Analysis in progress, checking again in 10 seconds...")
                    time.sleep(10)

            file_report = client.get_object(f"/files/{file_sha256}")

            print(f"\nScan results for: {file_path}")
            print(f"Scan ID: {analysis.id}")
            print(f"Permalink: https://www.virustotal.com/gui/file/{file_sha256}")
            print(
                f"Detection ratio: {file_report.last_analysis_stats.get('malicious', 0)}/{sum(file_report.last_analysis_stats.values())}"
            )

            # Sort the results: Malicious on top, then alphabetically
            results = file_report.last_analysis_results.items()
            malicious_results = []
            undetected_results = []

            for engine, result in results:
                detection = result.get("result", "N/A")
                if result.get("category") == "malicious":
                    malicious_results.append((engine, detection))
                else:
                    undetected_results.append((engine, detection))

            malicious_results.sort(key=lambda x: x[0])
            undetected_results.sort(key=lambda x: x[0])

            print("\nDetailed scan results:")
            for engine, detection in malicious_results:
                print(f"- {engine}: {detection} (Malicious)")

            for engine, detection in undetected_results:
                print(f"- {engine}: {detection} (Undetected)")

        except vt.error.APIError as e:
            print(f"API error: {e}")
        except Exception as e:
            print(f"Error during file scan: {e}")


# Main function to trigger the scanning and keep window open
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python virustotal.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    scan_file(file_path)

    # Wait for the user to press 'Q' before exiting
    while True:
        exit_key = input("Press 'Q' to exit: ").strip().lower()
        if exit_key == "q":
            break
