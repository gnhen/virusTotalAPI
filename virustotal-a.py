import sys
import vt
import os
import time
import hashlib
import json


def load_api_key():
    config_file = os.path.join(
        os.getenv("APPDATA"), "VirusTotal Scanner", "config.json"
    )
    if os.path.exists(config_file):
        with open(config_file) as f:
            config = json.load(f)
        return config.get("api_key")
    else:
        print("API key not found. Please set it in config.json.")
        return None


API_KEY = load_api_key()

# Load API key
api_key = load_api_key()
if not api_key:
    print("API key not found. Please set it in config.json.")
    exit(1)

MAX_WAIT_TIME = 600  # Maximum time to wait for the scan result


# Function to calculate SHA-256 hash of a file
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


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
                # Submit the file for scanning
                analysis = client.scan_file(f)

            print("File uploaded successfully. Waiting for analysis to complete...")

            start_time = time.time()
            while True:
                if time.time() - start_time > MAX_WAIT_TIME:
                    print("Error: Analysis is taking too long. Exiting.")
                    return

                # Fetch the analysis status
                analysis = client.get_object(f"/analyses/{analysis.id}")
                print(f"Current analysis status: {analysis.status}")

                if analysis.status == "completed":
                    print("Analysis complete!")
                    break
                else:
                    print("Analysis in progress, checking again in 10 seconds...")
                    time.sleep(10)

            # Fetch the file report using the calculated sha256
            file_report = client.get_object(f"/files/{file_sha256}")

            print(f"\nScan results for: {file_path}")
            print(f"Scan ID: {analysis.id}")
            print(f"Permalink: https://www.virustotal.com/gui/file/{file_sha256}")
            print(
                f"Detection ratio: {file_report.last_analysis_stats.get('malicious', 0)}/{sum(file_report.last_analysis_stats.values())}"
            )

            # Sort the results: Malicious on top, then alphabetically
            results = file_report.last_analysis_results.items()

            # Separate malicious and undetected results
            malicious_results = []
            undetected_results = []
            for engine, result in results:
                detection = result.get("result", "N/A")
                if result.get("category") == "malicious":
                    malicious_results.append((engine, detection))
                else:
                    undetected_results.append((engine, detection))

            # Sort alphabetically
            malicious_results.sort(key=lambda x: x[0])
            undetected_results.sort(key=lambda x: x[0])

            print("\nDetailed scan results:")
            # First, print malicious results
            for engine, detection in malicious_results:
                print(f"- {engine}: {detection} (Malicious)")

            # Then, print undetected results
            for engine, detection in undetected_results:
                print(f"- {engine}: {detection} (Undetected)")

        except vt.error.APIError as e:
            print(f"API error: {e}")
        except Exception as e:
            print(f"Error during file scan: {e}")


while True:
    exit_key = input("Press 'Q' to exit: ").strip().lower()
    if exit_key == "q":
        break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python virustotal.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    scan_file(file_path)
