from tkinter import *

remaining_files = None
remaining_files_int = 0
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
