import os
import shutil
import os.path
import logging
import configparser
from datetime import date
from tkinter import filedialog
from tkinter import ttk
import tkinter as tk
import tkinter.messagebox
import vars as v
import ttkbootstrap as ttks
import requests
import webbrowser
from logging.handlers import RotatingFileHandler
import time
import math

# locate windows documents folder
v.find_documents()

# create working directory if it does not exist
if not os.path.isdir(v.working_dir):
    os.mkdir(v.working_dir)
if not os.path.isdir(v.config_dir):
    os.mkdir(v.config_dir)

# config logging
logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
                    handlers=[RotatingFileHandler(filename=v.working_dir + "\\" + 'backup.log', mode="a", maxBytes=1024 * 1024, backupCount=1, encoding=None, delay=False)])
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

src_list = []
dst_list = []


def read_config(config_file: str, new_file=False, check_remaining=True):
    global src_list
    global dst_list

    if any(c in config_file for c in ["/", "\\", "?", "|", '"', ":", "*", "<", ">"]):
        tkinter.messagebox.showerror(title="Error", message='Filename cannot contain /, \\, ?, |, ", :, *, <, >')
        return

    config_path = get_path_for_config(config_file)

    # create log file if not exists
    if not os.path.isfile(config_path):
        try:
            config_file_handler = open(config_path, "w")
        except OSError:
            tkinter.messagebox.showerror(title="Error", message="Invalid filename")
            return
        config_file_handler.write("[PARAMETERS]\n")
        config_file_handler.write("SaveInterval = 1\n")
        config_file_handler.write("\n[FOLDERS]\n")
        config_file_handler.write("Src = \n")
        config_file_handler.write("Dst = \n")
        config_file_handler.close()
    elif new_file:
        tkinter.messagebox.showerror(title="Error", message="Config file {} already exists.".format(config_file))
        return

    config_parser = configparser.ConfigParser()
    config_parser.read(config_path)

    # update loaded config
    v.loaded_config_filename = config_file
    config_file = config_file.replace(".ini", "")
    if config_file != "config":
        v.loaded_config_file.set("Loaded config: {}".format(config_file))
        logger.info("Loaded config: {}".format(config_file))
    else:
        v.loaded_config_file.set("Loaded config: config (default)")
        logger.info("Loaded config: config (default)")
    v.root.update()

    src_list = string_to_folder_list(config_parser["FOLDERS"]["src"])
    dst_list = string_to_folder_list(config_parser["FOLDERS"]["dst"])

    if check_remaining:
        check_remaining_files()

    v.loaded_config = config_parser


def read_interval_from_config(config_file: str):
    config_file += ".ini"
    config_path = get_path_for_config(config_file)
    config_parser = configparser.ConfigParser()
    config_parser.read(config_path)
    return config_parser["PARAMETERS"]["saveinterval"]


def read_description_from_config(config_file: str):
    if ".ini" not in config_file:
        config_file += ".ini"
    config_path = get_path_for_config(config_file)
    config_parser = configparser.ConfigParser()
    config_parser.read(config_path)
    try:
        desc = config_parser["PARAMETERS"]["description"]
        return desc
    except KeyError:
        logger.info("No description found for config {}. Adding empty description.".format(config_file))
        config_parser["PARAMETERS"]["description"] = ""
        write_config(config_file, config_parser)
        return read_description_from_config(config_file)


def string_to_folder_list(string: str):
    return string.split("|") if string else []


def folder_list_to_string(folder_list: list):
    return "|".join(folder_list)


def write_config(file_name=None, cfg=None):
    """ Saves buffered configuration to file """
    if file_name is None:
        file_name = v.loaded_config_filename
    if cfg is None:
        cfg = v.loaded_config
    config_path = get_path_for_config(file_name)
    io_stream = open(config_path, "w")
    cfg.write(io_stream)
    io_stream.close()


def size_if_newer(source, target):
    """ If newer it returns size, otherwise it returns False """

    logger.info("Checking if {} is changed from {}".format(source, target))

    if not os.access(source, os.R_OK):
        logger.error("No read access to {}.".format(source))
        v.forbidden_paths += source
        return None

    src_stat = os.stat(source)
    try:
        target_ts = os.stat(target).st_mtime
    except FileNotFoundError:
        try:
            target_ts = os.stat(target + '.gz').st_mtime
        except FileNotFoundError:
            target_ts = 0

    # The time difference of one second is necessary since subsecond accuracy of os.st_mtime is stripped by copy2
    if src_stat.st_mtime - target_ts > 1:
        v.changed += 1
        logger.debug("CHECK: " + source + " is newer than " + target)
        return src_stat.st_size
    else:
        logger.debug("CHECK: " + source + " is NOT newer than " + target)
        return None


def transfer_file(source, target):
    try:
        shutil.copy2(source, target)
        logger.info('Copied {} to {}'.format(source, target))
    except FileNotFoundError:
        try:
            os.makedirs(os.path.dirname(target))
        except FileNotFoundError as e:
            logger.error(source + " cannot be copied: " + str(e))
            return "Synchronization failed: {}\n".format(e)
        transfer_file(source, target)


def sync_file(source, target):
    v.current_file.set(source)
    v.root.update()
    error_m = None
    if len(source) > 260:
        v.illegal_paths += [source]
        logger.warning("{} has a path length of {} and will not be checked.".format(source, len(source)))
    else:
        size = size_if_newer(source, target)

        if size is not None:
            logger.info("Syncing file {}".format(source))
            error_m = transfer_file(source, target)

    v.remaining_files_int -= 1
    if v.start_files - v.remaining_files_int < 100:
        v.remaining_files.set(
            "{} files (?) remaining.".format(v.remaining_files_int))
    else:
        v.remaining_files.set(
            "{} files ({:02.0f}:{:02.0f}:{:02.0f}) remaining.".format(v.remaining_files_int, math.floor(v.remaining_time / 3600), math.floor((v.remaining_time % 3600) / 60), v.remaining_time % 60))
    v.root.update()
    return error_m


def sync_dir(src, target, start_time):
    error_m = None
    for path, dirs, files in os.walk(src):
        for source in files:
            if v.time_update_timer >= v.time_update_interval:
                copied_files = v.start_files - v.remaining_files_int
                elapsed_time = time.time() - start_time
                v.remaining_time = (elapsed_time / copied_files) * v.remaining_files_int
                logger.info(
                    "Calculating time: copied files: {}, remaining files: {}, elapsed time: {}s, remaining time: {}s".format(copied_files, v.remaining_files_int, elapsed_time, v.remaining_time))
                v.time_update_timer = 0
            path = path.replace("\\", "/")
            source_path = path + "/" + source
            error_m = sync_file(source_path, target + path.replace(src, "") + "/" + source)
            v.time_update_timer += 1
    return error_m


def check_remaining_files():
    """Check how many files are still to be checked and update the counter"""
    files_to_check = 0

    # TODO: open window

    for src in src_list:
        for path, dirs, files in os.walk(src):
            for _ in files:
                files_to_check += 1

    v.remaining_files_int = files_to_check
    v.remaining_files.set("{} files remaining.".format(v.remaining_files_int))

    # TODO: close window

    v.root.update()


def sync():
    """Synchronise all source and destination folders in the current config file"""
    start = time.time()
    check_remaining_files()
    v.start_files = v.remaining_files_int

    error_messages = ""

    for src, dst in zip(src_list, dst_list):
        logger.info("Now syncing {} and {}".format(src, dst))
        ret_val = sync_dir(src, dst, start)
        if ret_val is not None:
            error_messages += ret_val
        logger.info("Done syncing {} and {}".format(src, dst))

    illegal_path_file = os.getcwd().replace("\\", "/") + "/illegal_paths.txt"
    illegal_path_file_handler = open(illegal_path_file, "a")
    for illegal_path in v.illegal_paths:
        illegal_path_file_handler.write(illegal_path + "\n")
    illegal_path_file_handler.close()

    forbidden_path_file = os.getcwd().replace("\\", "/") + "/forbidden_paths.txt"
    forbidden_path_file_handler = open(forbidden_path_file, "a")
    for forbidden_path in v.forbidden_paths:
        forbidden_path_file_handler.write(forbidden_path + "\n")
    forbidden_path_file_handler.close()

    if __name__ == '__main__':
        if v.illegal_paths:
            error_messages += "{} files were ignored due to their path length.\nA log of these files was created in {}\n".format(
                len(v.illegal_paths), illegal_path_file)

        if v.forbidden_paths:
            error_messages += "{} files were ignored due to restricted access.\nA log of these files was created in {}\n".format(
                len(v.forbidden_paths), forbidden_path_file)

        if error_messages == "":
            tkinter.messagebox.showinfo(title="Success", message="Synchronisation complete. Copied {} file(s).".format(
                v.changed))
        else:
            tkinter.messagebox.showinfo(title="Success", message="Synchronisation complete. Copied {} file(s).".format(
                v.changed) + "Errors occured.")
            error_window = tk.Toplevel(v.root)
            error_window.title("Errors")
            ErrorWindow(error_window, error_messages)

        v.loaded_config["PARAMETERS"]["last_run"] = str(date.today())
        write_config()


def get_config_files():
    """Returns a list of all available config files with ending"""
    return [ini_file for ini_file in os.listdir(v.config_dir) if ini_file.endswith(".ini")]


def start_sync():
    v.changed = 0
    sync()


def txt_event(event):
    if event.state == 12 and event.keysym == 'c':
        return
    else:
        return "break"


def get_path_for_config(config_name):
    """
    returns the path to a config file
    :param config_name: name of the config, .ini is optional
    :return: path as string
    """
    if ".ini" not in config_name:
        config_name += ".ini"
    return v.config_dir + "\\" + config_name


class ConfigDescriptionWindow:
    def __init__(self, master, config, caller, conf_window):
        self.master = master
        self.config = config
        self.caller = caller
        self.conf_window = conf_window
        self.frame = ttk.Frame(self.master)
        self.frame.pack(fill="both", expand=True)
        self.frame.grid(row=1, column=0, sticky="nsew")
        self.master.wm_attributes("-topmost", True)

        self.text_entry = tk.Text(self.frame)
        self.text_entry.pack(side=tk.TOP, expand=True)
        self.text_entry.insert(tk.INSERT, read_description_from_config(self.config))

        self.confirm_button = ttk.Button(self.frame, text="Save change", command=self.save_description)
        self.confirm_button.pack(side=tk.LEFT, expand=False)

        self.cancel_button = ttk.Button(self.frame, text="Close", command=self.close_description)
        self.cancel_button.pack(side=tk.RIGHT, expand=False)

    def save_description(self):
        """
        file_name = self.config + ".ini"
        config_path = v.working_dir + "\\" + file_name
        config_parser = configparser.ConfigParser()
        config_parser.read(config_path)
        config_parser["PARAMETERS"]["description"] = self.text_entry.get(1.0, "end-1c")
        tmp = open(config_path, "w")
        config_parser.write(tmp)
        tmp.close()
        """
        new_desc = self.text_entry.get(1.0, "end-1c")
        v.loaded_config["PARAMETERS"]["description"] = new_desc
        write_config(self.config)
        logger.info("Changed description of config '{}'".format(self.config))
        self.master.destroy()
        self.conf_window.reload()

    def close_description(self):
        if read_description_from_config(self.config) != self.text_entry.get(1.0, "end-1c"):
            if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to discard these changes?"):
                self.master.destroy()
                self.caller.wm_attributes("-topmost", True)
            else:
                return
        else:
            self.master.destroy()
            self.caller.wm_attributes("-topmost", True)


class ConfigWindow:
    def __init__(self, master):
        self.master = master

        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)

        self.frame = ttk.Frame(self.master)
        self.frame.grid(row=0, column=0, padx=50, pady=50, sticky="NSEW")

        self.master.wm_attributes("-topmost", True)
        self.next_row = 1

        config_col_label = ttk.Label(self.frame, text="Configuration Name", anchor="center", width=50)
        config_col_label.grid(column=0, row=self.next_row, sticky="NSEW")
        interval_col_label = ttk.Label(self.frame, text="Update Interval", anchor="center")
        interval_col_label.grid(column=1, row=self.next_row, stick="NSEW")
        self.next_row += 1
        sep = ttk.Separator(self.frame, orient="horizontal")
        sep.grid(row=self.next_row, sticky="EW", column=0, columnspan=5, pady=10)
        self.next_row += 1

        config_file_list = get_config_files()
        config_list = [cfg_file[0:-4] for cfg_file in config_file_list]

        for config in config_list:
            name_label = ttk.Label(self.frame, text=config, anchor="center")
            name_label.grid(column=0, row=self.next_row, sticky="NSEW")
            interval_label = ttk.Label(self.frame, text=read_interval_from_config(config), anchor="center")
            interval_label.grid(column=1, row=self.next_row, sticky="NSEW")
            load_button = ttk.Button(self.frame, text="load", command=lambda c=config: self.load_config(c))
            load_button.grid(column=2, row=self.next_row, sticky="NSEW")
            delete_button = ttk.Button(self.frame, text="delete", command=lambda c=config: self.delete_config(c), style="danger.TButton")
            delete_button.grid(column=3, row=self.next_row, sticky="NSEW")
            description_button = ttk.Button(self.frame, text="description", command=lambda c=config: self.open_config_description_window(c), style="info.TButton", width=10)
            description_button.grid(column=4, row=self.next_row, sticky="NSEW")
            if config == "config":
                delete_button["state"] = "disabled"
            self.next_row += 1
            config_desc = read_description_from_config(config).replace("\n", " ")
            if len(config_desc) > v.short_config_desc_len:
                config_desc = config_desc[:v.short_config_desc_len]
            short_desc_label = ttk.Label(self.frame, text=config_desc)
            short_desc_label.grid(column=0, row=self.next_row, sticky="NSEW")
            self.next_row += 1
            sep = ttk.Separator(self.frame, orient="horizontal")
            sep.grid(row=self.next_row, sticky="EW", column=0, columnspan=5, pady=10)
            self.next_row += 1

        ttk.Label(self.frame, text="").grid(column=0, row=self.next_row)
        self.next_row += 1
        self.new_button = ttk.Button(self.frame, text="New Configuration", command=self.new_config, style="success.TButton")
        self.new_button.grid(column=0, row=self.next_row, sticky="NSEW")

        self.close_button = ttk.Button(self.frame, text="Close", command=self.master.destroy, style="danger.Outline.TButton")
        self.close_button.grid(column=2, row=self.next_row, sticky="NSEW")

        self.new_name_entry = ttk.Entry(self.frame)

        self.frame.columnconfigure((0, 1, 2, 3, 4), weight=1)
        self.frame.rowconfigure([i for i in range(self.next_row)], weight=1)

    def delete_config(self, config_file):
        config_path = get_path_for_config(config_file)
        if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to delete configuration '{}'?".format(config_file)):
            os.remove(config_path)
            logger.info("Deleted config '{}'".format(config_path))
            self.reload()

    def load_config(self, config_file):
        read_config(config_file + ".ini")
        self.master.destroy()

    def new_config(self):
        """ Opens dialog for creating a new config """
        self.new_button.destroy()
        self.close_button.destroy()
        self.next_row += 2

        new_name_label = ttk.Label(self.frame, text="Enter New Configuration Name:", anchor="center")
        new_name_label.grid(column=0, row=self.next_row, sticky="NSEW")
        self.next_row += 1

        self.new_name_entry.grid(column=0, row=self.next_row, sticky="NSEW")

        confirm_button = ttk.Button(self.frame, text="Confirm", command=self.create_config)
        confirm_button.grid(column=1, row=self.next_row, sticky="NSEW")
        self.next_row += 1

        self.close_button = ttk.Button(self.frame, text="Close", command=self.master.destroy)
        self.close_button.grid(column=1, row=self.next_row, sticky="NSEW")

    def create_config(self):
        """ Creates a new config from entered data """
        new_config = self.new_name_entry.get()
        if not new_config:
            tkinter.messagebox.showerror(title="Error", message="Filename cannot be empty")
            return
        read_config(new_config, True)
        logger.info("Created new config '{}'".format(new_config + ".ini"))
        self.reload()

    def reload(self):
        x, y, h, w = self.master.winfo_x(), self.master.winfo_y(), self.master.winfo_height(), self.master.winfo_width()
        self.master.destroy()
        config_window = tk.Toplevel(v.root)
        config_window.title("Configurations")
        config_window.geometry('%dx%d+%d+%d' % (w, h, x, y))
        ConfigWindow(config_window)

    def open_config_description_window(self, config):
        self.master.wm_attributes("-topmost", False)
        config_description_window = tk.Toplevel(self.master)
        config_description_window.title("{} - Description".format(config))
        ConfigDescriptionWindow(config_description_window, config, self.master, self)


class FolderWindow:
    def __init__(self, master):
        self.master = master
        self.frame = tk.Frame(self.master)
        self.frame.pack(fill="both", expand=True)
        self.frame.grid(row=0, column=0, sticky="NSEW", padx=50, pady=50)
        self.master.wm_attributes("-topmost", True)

        self.src_field = None
        self.dst_field = None

        self.next_row = 1

        self.config_file = ttk.Entry(self.frame, textvariable=v.loaded_config_file, width=50)
        self.config_file.grid(column=0, row=self.next_row, sticky="NSEW")
        self.config_file.bind("<Key>", lambda e: "break")
        self.next_row += 1
        ttk.Label(self.frame, text="").grid(column=0, row=self.next_row)
        self.next_row += 1

        src_col_label = ttk.Label(self.frame, anchor="center", text="Source")
        src_col_label.grid(column=0, row=self.next_row, sticky="NSEW")
        dst_col_label = ttk.Label(self.frame, anchor="center", text="Destination")
        dst_col_label.grid(column=2, row=self.next_row, sticky="NSEW")
        self.next_row += 1

        sep = ttk.Separator(self.frame, orient="horizontal")
        sep.grid(row=self.next_row, sticky="EW", column=0, columnspan=4, pady=10)
        self.next_row += 1

        for src, dst in zip(src_list, dst_list):
            src_label = ttk.Label(self.frame, text=src, anchor="center")
            src_label.grid(column=0, row=self.next_row, sticky="NSEW")
            dst_label = ttk.Label(self.frame, text=dst, anchor="center")
            dst_label.grid(column=2, row=self.next_row, sticky="NSEW")
            remove_button = ttk.Button(self.frame, text="X", command=lambda s=src, d=dst: self.remove_src_dst(s, d), style="danger.TButton")
            remove_button.grid(column=3, row=self.next_row, sticky="NSEW")
            self.next_row += 1
            sep = ttk.Separator(self.frame, orient="horizontal")
            sep.grid(row=self.next_row, sticky="EW", column=0, columnspan=4, pady=10)
            self.next_row += 1

        self.add_button = ttk.Button(self.frame, text="+", command=self.add_folder, style="success.TButton")
        self.add_button.grid(column=0, row=self.next_row)

        self.close_button = ttk.Button(self.frame, text="Close", command=self.master.destroy, style="danger.Outline.TButton")
        self.close_button.grid(column=1, row=self.next_row)

        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        self.frame.columnconfigure([i for i in range(3)], weight=1)
        self.frame.rowconfigure(1, weight=1)
        self.frame.rowconfigure([i for i in range(1, self.next_row)], weight=3)

    def add_folder(self):
        self.add_button.destroy()
        self.close_button.destroy()

        self.src_field = ttk.Entry(self.frame, width=70)
        self.src_field.grid(column=0, row=self.next_row)
        self.dst_field = ttk.Entry(self.frame, width=70)
        self.dst_field.grid(column=2, row=self.next_row)

        swap_button = ttk.Button(self.frame, text="Swap", command=self.swap_folders, style="warning.TButton")
        swap_button.grid(column=1, row=self.next_row)

        self.next_row += 1

        src_select_button = ttk.Button(self.frame, text="...", command=lambda: self.select_directory(self.src_field), style="primary.TButton")
        src_select_button.grid(column=0, row=self.next_row)
        dst_select_button = ttk.Button(self.frame, text="...", command=lambda: self.select_directory(self.dst_field), style="primary.TButton")
        dst_select_button.grid(column=2, row=self.next_row)
        self.next_row += 1

        self.close_button = ttk.Button(self.frame, text="Close", command=self.confirm_close, style="danger.TButton")
        self.close_button.grid(column=1, row=self.next_row)

        confirm_button = ttk.Button(self.frame, text="Confirm", command=lambda: self.confirm_add_folder(self.src_field.get(), self.dst_field.get(), ), style="success.TButton")
        confirm_button.grid(column=2, row=self.next_row)

    def swap_folders(self):
        tmp = self.src_field.get()
        self.src_field.delete(0, 'end')
        self.src_field.insert(0, self.dst_field.get())
        self.dst_field.delete(0, 'end')
        self.dst_field.insert(0, tmp)

    def confirm_close(self):
        self.master.wm_attributes("-topmost", False)
        if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to close without saving?"):
            self.master.destroy()
        else:
            self.master.wm_attributes("-topmost", True)

    def remove_src_dst(self, src, dst):
        logger.info("Removing folder pair {} and {}".format(src, dst))

        global src_list
        global dst_list

        self.master.wm_attributes("-topmost", False)

        if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to delete this folder pair?"):
            src_list.remove(src)
            dst_list.remove(dst)
            v.loaded_config["FOLDERS"]["src"] = folder_list_to_string(src_list)
            v.loaded_config["FOLDERS"]["dst"] = folder_list_to_string(dst_list)
            write_config()
            check_remaining_files()

            self.reload()
        else:
            self.master.wm_attributes("-topmost", True)

    def reload(self):
        x, y, h, w = self.master.winfo_x(), self.master.winfo_y(), self.master.winfo_height(), self.master.winfo_width()
        self.master.destroy()
        folder_window = tk.Toplevel(v.root)
        folder_window.title("Folders")
        folder_window.geometry('%dx%d+%d+%d' % (w, h, x, y))
        FolderWindow(folder_window)

    def select_directory(self, field):
        self.master.wm_attributes("-topmost", False)
        folder_path = filedialog.askdirectory()
        field.delete(0, 'end')
        field.insert(0, folder_path)
        self.master.wm_attributes("-topmost", True)

    def confirm_add_folder(self, src, dst):
        if not src or not dst:
            self.master.wm_attributes("-topmost", False)
            tkinter.messagebox.showerror(title="Error", message="Source and destination cannot be empty.")
            self.master.wm_attributes("-topmost", True)
        elif src == dst:
            self.master.wm_attributes("-topmost", False)
            tkinter.messagebox.showerror(title="Error", message="Source and destination cannot be identical.")
            self.master.wm_attributes("-topmost", True)
        else:
            self.add_src_dst(src, dst)

    def add_src_dst(self, src, dst):
        logger.info("Adding folder pair {} and {} to {}".format(src, dst, v.loaded_config_file.get()))

        global src_list
        global dst_list

        src_list += [src]
        dst_list += [dst]
        v.loaded_config["FOLDERS"]["src"] = folder_list_to_string(src_list)
        v.loaded_config["FOLDERS"]["dst"] = folder_list_to_string(dst_list)
        check_remaining_files()
        write_config()
        self.reload()


class IntervalWindow:
    def __init__(self, master):
        self.master = master
        self.frame = tk.Frame(self.master)

        self.interval_label = ttk.Label(self.frame, text="Synchronisation interval (days):")
        self.interval_label.pack(fill="both", expand=True, padx=20, pady=20)

        self.interval_input = ttk.Entry(self.frame)
        self.interval_input.pack(fill="both", expand=True, padx=20, pady=20)

        # insert current interval
        logger.info("Loaded Sync Interval {} from config {}".format(v.loaded_config["PARAMETERS"]["saveinterval"], v.loaded_config_filename))
        self.current_interval = v.loaded_config["PARAMETERS"]["saveinterval"]
        self.interval_input.insert(0, self.current_interval)

        self.confirm_button = ttk.Button(self.frame, text="Confirm",
                                         command=self.confirm_interval_change, style="success.TButton")
        self.confirm_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.close_button = ttk.Button(self.frame, text="Cancel", command=self.master.destroy, style="danger.TButton")
        self.close_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.frame.pack(fill="both", expand=True, padx=20, pady=20)

    def confirm_interval_change(self):
        """Confirm the new interval and close the calling window"""
        new_interval = self.interval_input.get()

        # check validity
        try:
            new_interval = int(new_interval)
            if new_interval < 0:
                raise ValueError
        except ValueError:
            logger.warning("Interval change: '{}' is not an integer.".format(new_interval))
            tkinter.messagebox.showerror(title="Invalid Input", message="Interval must be a positive Integer.")
            # move window to the top
            self.master.wm_attributes("-topmost", True)
            self.master.wm_attributes("-topmost", False)
            return

        logger.info("Changed interval from {} to {} for config {}.".format(self.current_interval, new_interval, v.loaded_config_filename))
        v.loaded_config["PARAMETERS"]["saveinterval"] = str(new_interval)
        write_config()
        self.master.destroy()


class MainPage:
    def __init__(self, master):
        self.master = master
        self.frame = tk.Frame(self.master, padx=30, pady=20)

        self.config_file = ttk.Entry(self.frame, textvariable=v.loaded_config_file)
        self.config_file.pack(fill="both", expand=True, padx=20, pady=20)
        # make entry read only
        self.config_file.bind("<Key>", lambda e: "break")

        self.manage_config_button = ttk.Button(self.frame, text="Manage Configurations", command=self.open_config_window)
        self.manage_config_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.folders_button = ttk.Button(self.frame, text="Folders", command=self.open_folder_window)
        self.folders_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.interval_button = ttk.Button(self.frame, text="Set Update Interval", command=self.open_interval_window)
        self.interval_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.sync_button = ttk.Button(self.frame, text="Synchronize Now", command=start_sync, style="success.TButton")
        self.sync_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.close = ttk.Button(self.frame, text="Quit", command=v.root.destroy, style="danger.TButton")
        self.close.pack(fill="both", expand=True, padx=20, pady=20)

        self.remaining = ttk.Entry(self.frame, textvariable=v.remaining_files)
        self.remaining.pack(fill="both", expand=True, padx=20, pady=20)
        self.remaining.bind("<Key>", lambda e: "break")

        self.current_file = ttk.Entry(self.frame, textvariable=v.current_file)
        self.current_file.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_file.bind("<Key>", lambda e: txt_event(e))

        self.frame.pack(fill="both", expand=True)

    def open_interval_window(self):
        interval_window = tk.Toplevel(self.master)
        interval_window.title("Set Interval")
        IntervalWindow(interval_window)

    def open_folder_window(self):
        folder_window = tk.Toplevel(self.master)
        folder_window.title("Folders")
        FolderWindow(folder_window)

    def open_config_window(self):
        config_window = tk.Toplevel(self.master)
        config_window.title("Configurations")
        ConfigWindow(config_window)


def initialize():
    # clear or create illegal and forbidden path files
    illegal_path_file = v.working_dir + r"\illegal_paths.txt"
    illegal_path_file_handler = open(illegal_path_file, "w")
    illegal_path_file_handler.close()

    forbidden_path_file = v.working_dir + r"\forbidden_paths.txt"
    forbidden_path_file_handler = open(forbidden_path_file, "w")
    forbidden_path_file_handler.close()

    # move old config files and delete old logs
    for file in os.listdir(os.getcwd()):
        if file.endswith(".ini"):
            shutil.copy2(file, v.config_dir)
            os.remove(file)
            logger.info("Moved {} to documents folder".format(file))
        if file.endswith(".log") or ".log." in file or file.endswith(".txt"):
            os.remove(file)
            logger.info("Deleted {}".format(file))


class UpdateWindow:
    def __init__(self, master, latest_version):
        self.master = master

        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        self.frame = tk.Frame(self.master, padx=30, pady=20)
        self.frame.grid(row=0, column=0, sticky="NSEW")

        self.label = ttk.Label(self.frame, text="There is a new update available. The current version is {}, the latest version is {}. ".format(v.current_version, latest_version))
        self.label.grid(row=0, column=0, columnspan=2, sticky="NSEW")

        self.update_button = ttk.Button(self.frame, text="Update", style="success.TButton", command=lambda: webbrowser.open("https://github.com/RaphaelK77/python-backup/releases"))
        self.update_button.grid(row=1, column=0)

        self.close_button = ttk.Button(self.frame, text="Later", style="warning.TButton", command=self.master.destroy)
        self.close_button.grid(row=1, column=1)


class ErrorWindow:
    def __init__(self, master, error_messages):
        # window definitions
        self.master = master
        self.res = tk.Frame(self.master)
        self.master.title("Error Messages")
        self.res.pack()

        # label for error entry
        self.error_label = tk.Label(self.master, text="Errors occurred:")
        self.error_label.pack()

        # entry to show errors and warnings
        self.error_text = tk.Text(self.master, width=200, height=10)
        self.error_text.pack()
        self.error_text.insert("end", error_messages)
        # read-only
        self.error_text.bind("<Key>", lambda e: "break")

        # close button
        self.close = tk.Button(self.master, text="Close", command=self.master.destroy)
        self.close.pack()


def check_for_updates():
    # check for new version
    logger.info("Checking for updates...")
    latest_version = requests.get(v.git_link).json()["tag_name"]
    if v.current_version != latest_version:
        update_window = tk.Toplevel(v.root)
        update_window.title("New Update")
        UpdateWindow(update_window, latest_version)
    else:
        logger.info("Version up to date.")


if __name__ == '__main__':
    logger.info("********** STARTING BACKUP ************")

    initialize()

    style = ttks.Style(theme="cosmo")
    v.root = style.master
    v.root.title("Backup " + v.current_version)
    v.root.geometry("600x800")

    v.remaining_files = tk.StringVar()
    v.current_file = tk.StringVar()
    v.loaded_config_file = tk.StringVar()

    read_config(v.default_config_file)

    main_page = MainPage(v.root)

    check_for_updates()

    check_remaining_files()

    v.root.mainloop()

    logger.info("Program quit by user.")
