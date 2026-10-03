import logging
import os


def setup(name: str) -> logging.Logger:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format=f"%(asctime)s [{name}] %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    return logging.getLogger(name)
