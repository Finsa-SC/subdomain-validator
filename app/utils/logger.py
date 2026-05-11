import logging

logging.basicConfig(
    filename="/tmp/subv.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)