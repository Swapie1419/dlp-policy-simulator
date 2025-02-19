import re
import os
import logging

# Configure logging
logging.basicConfig(filename="dlp_alerts.log", level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

def detect_sensitive_data(content):
    """Detect sensitive data like credit card numbers, emails, and SSNs."""
    patterns = {
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b"
    }
    detected = {}
    
    for label, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            detected[label] = matches
    
    return detected

def scan_file(file_path):
    """Scan a file for sensitive data."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
            violations = detect_sensitive_data(content)
            if violations:
                logging.warning(f"Policy Violation in {file_path}: {violations}")
                print(f"Alert: Sensitive data detected in {file_path}")
    except Exception as e:
        logging.error(f"Error scanning {file_path}: {str(e)}")

def scan_email(content, sender, receiver):
    """Simulate email content scanning."""
    violations = detect_sensitive_data(content)
    if violations:
        logging.warning(f"Email Policy Violation: From {sender} To {receiver}: {violations}")
        print(f"Alert: Sensitive data detected in email from {sender} to {receiver}")

def monitor_directory(directory):
    """Monitor a directory for new or modified files."""
    print(f"Monitoring directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            scan_file(os.path.join(root, file))

# Example Usage
if __name__ == "__main__":
    # Scan a sample file
    sample_file = "test.txt"
    scan_file(sample_file)
    
    # Simulate an email scan
    sample_email_content = "Hello, my SSN is 123-45-6789 and my email is example@test.com."
    scan_email(sample_email_content, "user1@example.com", "user2@example.com")
    
    # Monitor a directory
    monitor_directory("./test_files")
