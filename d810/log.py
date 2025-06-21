import logging
import logging.config
import shutil
from pathlib import Path

LOG_CONFIG_FILENAME = "log.ini"
LOG_FILENAME = "d810.log"
Z3_TEST_FILENAME = "z3_check_instructions_substitution.py"


def clear_logs(log_dir):
    shutil.rmtree(log_dir, ignore_errors=True)


def configure_loggers(log_dir):
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_main_file = Path(log_dir) / LOG_FILENAME
    z3_test_file = Path(log_dir) / Z3_TEST_FILENAME
    log_conf_file = Path(__file__).resolve().parent / LOG_CONFIG_FILENAME
    logging.config.fileConfig(
        log_conf_file.as_posix(),
        defaults={
            "default_log_filename": log_main_file.as_posix(),
            "z3_log_filename": z3_test_file.as_posix(),
        },
    )
    z3_file_logger = logging.getLogger("D810.z3_test")
    z3_file_logger.info(
        "from z3 import BitVec, BitVecVal, UDiv, URem, LShR, UGT, UGE, ULT, ULE, prove\n\n"
    )
