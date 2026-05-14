import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    filename="/tmp/subv.log",
    level=logging.DEBUG,
)

def get_logger(name: str) -> logging.Logger:
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)

    date_str = datetime.now().strftime('%Y-%m-%d')
    log_file = log_dir / f"scan_{date_str}.log"

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    return logger