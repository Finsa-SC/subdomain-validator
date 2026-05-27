import logging
import shutil
from pathlib import Path
from datetime import datetime

def get_logger(name: str) -> logging.Logger:
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)

    date_str = datetime.now().strftime('%Y-%m-%d')
    log_file = log_dir / f"scan_{date_str}.log"
    log_latest = log_dir / 'latest.log'

    if not log_file.exists():
        log_file.touch()

    if log_latest.exists() or log_latest.is_symlink():
        try:
            log_latest.unlink()
        except:
            pass
    try:
        log_latest.symlink_to(log_file.name)
    except (OSError, NotImplementedError):
        try:
            shutil.copy(log_file, log_latest)
        except:
            pass

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    logging.raiseExceptions = False

    return logger