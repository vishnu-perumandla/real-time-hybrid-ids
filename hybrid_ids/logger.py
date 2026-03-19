from datetime import datetime
from config import LOG_FILE


def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"

    print(log_message)

    with open(LOG_FILE, "a") as file:
        file.write(log_message + "\n")