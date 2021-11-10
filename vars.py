import os.path
import ctypes
from ctypes.wintypes import MAX_PATH
import logging
from logging.handlers import RotatingFileHandler

working_dir = ""
remaining_files = None
remaining_files_int = 0
start_files = 0
root = None
default_config_file = "config.ini"
illegal_paths = []
forbidden_paths = []
changed = 0
current_file = None
loaded_config = None
loaded_config_file = None
loaded_config_filename = ""
short_config_desc_len = 30
current_version = "v1.4.0"
remaining_time = -1
time_update_timer = 0
time_update_interval = 5
os.path.expandvars(r'%MYDOCUMENTS%\PythonBackup')


def find_documents():
    """ find documents folder """
    global working_dir
    dll = ctypes.windll.shell32
    buf = ctypes.create_unicode_buffer(MAX_PATH + 1)
    if dll.SHGetSpecialFolderPathW(None, buf, 0x0005, False):
        working_dir = buf.value + r"\PythonBackup"
    else:
        logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
                            handlers=[RotatingFileHandler(filename='backup_crash.log', mode="a", maxBytes=1024 * 1024, backupCount=1, encoding=None, delay=True)])
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        exit(0)
