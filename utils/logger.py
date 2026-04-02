import logging
import os
from datetime import datetime

def setup_logger():
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"reports/ss7shield_{timestamp}.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("SS7Shield"), log_file

def log_finding(logger, severity, finding, details):
    msg = f"[{severity}] {finding} | {details}"
    if severity == "CRITICAL":
        logger.critical(msg)
    elif severity == "HIGH":
        logger.error(msg)
    elif severity == "MEDIUM":
        logger.warning(msg)
    else:
        logger.info(msg)