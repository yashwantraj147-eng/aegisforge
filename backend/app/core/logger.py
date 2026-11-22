import logging
import sys

def setup_logging(default_level: int = logging.INFO) -> logging.Logger:
    """
    Configures structured console logging for the AegisForge framework.
    """
    logger = logging.getLogger("aegisforge")
    if not logger.handlers:
        logger.setLevel(default_level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(default_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    return logger

logger = setup_logging()

def get_logger(module_name: str) -> logging.Logger:
    """
    Returns a child logger scoped to a specific engine or submodule.
    """
    return logging.getLogger(f"aegisforge.{module_name}")
