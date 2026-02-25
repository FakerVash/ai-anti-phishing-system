from logger import log_analysis
import datetime

test_data_1 = {
    "url": "http://test-update.com",
    "status": "safe",
    "reason": "Initial scan",
    "timestamp": datetime.datetime.now().isoformat()
}

test_data_2 = {
    "url": "http://test-update.com",
    "status": "phishing",
    "reason": "Rescan detected phishing",
    "timestamp": datetime.datetime.now().isoformat()
}

print("Testing logger update...")
log_analysis(test_data_1)
print("Logged initial entry.")
log_analysis(test_data_2)
print("Logged update entry.")
print("Please check the log file manually to verify there is only one entry for 'http://test-update.com' with status 'phishing'.")
