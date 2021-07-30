import os
import shutil
import os.path
import logging
import configparser
from tkinter import filedialog
from tkinter import ttk
import tkinter.messagebox
import vars as v
from tkinter import *

source_dir = r"E:\Dateien\Documents\Python\pythonBackup\source"
destination_dir = r"E:\Dateien\Documents\Python\pythonBackup\destination"
source_dir2 = r"E:\Dateien\Documents\Python\pythonBackup\source2"
destination_dir2 = r"E:\Dateien\Documents\Python\pythonBackup\destination2"

# clear log file
logfile = open('backup.log', mode="w")
logfile.close()

# config logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
handler = logging.FileHandler(filename='backup.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

src_list = []
dst_list = []


def read_config(config_file: str, new_file=False):
    global src_list
    global dst_list

    if any(c in config_file for c in ["/", "\\", "?", "|", '"', ":", "*", "<", ">"]):
        tkinter.messagebox.showerror(title="Error", message='Filename cannot contain /, \\, ?, |, ", :, *, <, >')
        return

    # create log file if not exists
    if not os.path.isfile(config_file):
        try:
            config_file_handler = open(config_file, "w")
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
    config_parser.read(config_file)

    # update loaded config
    v.loaded_config_filename = config_file
    config_file = config_file[0:-4]
    if config_file != "config":
        v.loaded_config_file.set("Loaded config: {}".format(config_file))
    else:
        v.loaded_config_file.set("Loaded config: config (default)")
    v.root.update()

    src_list = string_to_folder_list(config_parser["FOLDERS"]["src"])
    dst_list = string_to_folder_list(config_parser["FOLDERS"]["dst"])

    check_remaining_files()

    return config_parser


def read_interval_from_config(config_file: str):
    config_file += ".ini"
    config_parser = configparser.ConfigParser()
    config_parser.read(config_file)
    return config_parser["PARAMETERS"]["saveinterval"]


def read_description_from_config(config_file: str):
    if ".ini" not in config_file:
        config_file += ".ini"
    config_parser = configparser.ConfigParser()
    config_parser.read(config_file)
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
    if file_name is None:
        file_name = v.loaded_config_filename
    if cfg is None:
        cfg = v.loaded_config
    tmp = open(file_name, "w")
    cfg.write(tmp)
    tmp.close()


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
        os.makedirs(os.path.dirname(target))
        transfer_file(source, target)


def sync_file(source, target):
    v.current_file.set(source)
    v.root.update()
    if len(source) > 260:
        v.illegal_paths += [source]
        logger.warning("{} has a path length of {} and will not be checked.".format(source, len(source)))
    else:
        size = size_if_newer(source, target)

        if size is not None:
            logger.info("Syncing file {}".format(source))
            transfer_file(source, target)

    v.remaining_files_int -= 1
    v.remaining_files.set("{} files remaining.".format(v.remaining_files_int))
    v.root.update()


def sync_dir(src, target):
    for path, dirs, files in os.walk(src):
        for source in files:
            path = path.replace("\\", "/")
            source_path = path + "/" + source
            sync_file(source_path, target + path.replace(src, "") + "/" + source)


def check_remaining_files():
    """Check how many files are still to be checked and update the counter"""
    files_to_check = 0

    for src, dst in zip(src_list, dst_list):
        for path, dirs, files in os.walk(src):
            for _ in files:
                files_to_check += 1

    v.remaining_files_int = files_to_check
    v.remaining_files.set("{} files remaining.".format(v.remaining_files_int))

    v.root.update()


def sync():
    """Synchronise all source and destination folders in the current config file"""
    check_remaining_files()

    for src, dst in zip(src_list, dst_list):
        logger.info("Now syncing {} and {}".format(src, dst))
        sync_dir(src, dst)
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
            illegal_paths_message = "\n{} files were ignored due to their path length.\nA log of these files was created in {}".format(
                len(v.illegal_paths), illegal_path_file)
        else:
            illegal_paths_message = ""

        if v.forbidden_paths:
            forbidden_paths_message = "\n{} files were ignored due to restricted access.\nA log of these files was created in {}".format(
                len(v.forbidden_paths), forbidden_path_file)
        else:
            forbidden_paths_message = ""

        tkinter.messagebox.showinfo(title="Success", message="Synchronisation complete. Copied {} file(s).".format(
            v.changed) + illegal_paths_message + forbidden_paths_message)


def get_config_files():
    """Returns a list of all available config files with ending"""
    return [ini_file for ini_file in os.listdir() if ini_file.endswith(".ini")]


def start_sync():
    v.changed = 0
    sync()


def txt_event(event):
    if event.state == 12 and event.keysym == 'c':
        return
    else:
        return "break"


class ConfigDescriptionWindow:
    def __init__(self, master, config, caller):
        self.master = master
        self.config = config
        self.caller = caller
        self.frame = Frame(self.master)
        self.frame.pack(fill="both", expand=True)
        self.frame.grid(row=1, column=0, sticky="nsew")
        self.master.wm_attributes("-topmost", True)

        self.text_entry = Text(self.frame)
        self.text_entry.pack(side=TOP, expand=True)
        self.text_entry.insert(INSERT, read_description_from_config(self.config))

        self.confirm_button = Button(self.frame, text="Save change", command=self.save_description)
        self.confirm_button.pack(side=LEFT, expand=False)

        self.cancel_button = Button(self.frame, text="Close", command=self.close_description)
        self.cancel_button.pack(side=RIGHT, expand=False)

    def save_description(self):
        file_name = self.config + ".ini"
        config_parser = configparser.ConfigParser()
        config_parser.read(file_name)
        config_parser["PARAMETERS"]["description"] = self.text_entry.get(1.0, "end-1c")
        tmp = open(file_name, "w")
        config_parser.write(tmp)
        tmp.close()
        self.master.destroy()
        self.caller.wm_attributes("-topmost", True)

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
        self.frame = Frame(self.master)
        self.frame.pack(fill="both", expand=True)
        self.frame.grid(row=1, column=0, sticky="nsew")
        self.master.wm_attributes("-topmost", True)
        self.next_row = 1

        config_col_label = Label(self.frame, text="Configuration Name", anchor="center", width=50)
        config_col_label.grid(column=0, row=self.next_row, sticky="NSEW")
        interval_col_label = Label(self.frame, text="Update Interval", anchor="center")
        interval_col_label.grid(column=1, row=self.next_row, stick="NSEW")
        self.next_row += 1

        config_file_list = get_config_files()
        config_list = [cfg_file[0:-4] for cfg_file in config_file_list]

        for config in config_list:
            name_label = Label(self.frame, text=config, anchor="center")
            name_label.grid(column=0, row=self.next_row, sticky="NSEW")
            interval_label = Label(self.frame, text=read_interval_from_config(config), anchor="center")
            interval_label.grid(column=1, row=self.next_row, sticky="NSEW")
            load_button = Button(self.frame, text="load", command=lambda c=config: self.load_config(c))
            load_button.grid(column=2, row=self.next_row, sticky="NSEW")
            delete_button = Button(self.frame, text="delete", command=lambda c=config: self.delete_config(c))
            delete_button.grid(column=3, row=self.next_row, sticky="NSEW")
            description_button = Button(self.frame, text="description", command=lambda c=config: self.open_config_description_window(c))
            description_button.grid(column=4, row=self.next_row, sticky="NSEW")
            if config == "config":
                delete_button["state"] = "disabled"
            self.next_row += 1

        Label(self.frame, text="").grid(column=0, row=self.next_row)
        self.next_row += 1
        self.new_button = Button(self.frame, text="New Configuration", command=self.new_config)
        self.new_button.grid(column=0, row=self.next_row, sticky="NSEW")

        self.close_button = Button(self.frame, text="Close", command=self.master.destroy)
        self.close_button.grid(column=2, row=self.next_row, sticky="NSEW")

        self.new_name_entry = Entry(self.frame)

    def delete_config(self, config):
        config_path = config + ".ini"
        if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to delete configuration '{}'?".format(config)):
            os.remove(config_path)
            self.reload()

    def load_config(self, config):
        v.loaded_config = read_config(config + ".ini")
        self.master.destroy()

    def new_config(self):
        self.new_button.destroy()
        self.close_button.destroy()
        self.next_row += 2

        new_name_label = Label(self.frame, text="Enter New Configuration Name:", anchor="center")
        new_name_label.grid(column=0, row=self.next_row, sticky="NSEW")
        self.next_row += 1

        self.new_name_entry.grid(column=0, row=self.next_row, sticky="NSEW")

        confirm_button = Button(self.frame, text="Confirm", command=self.create_config)
        confirm_button.grid(column=1, row=self.next_row, sticky="NSEW")
        self.next_row += 1

        self.close_button = Button(self.frame, text="Close", command=self.master.destroy)
        self.close_button.grid(column=1, row=self.next_row, sticky="NSEW")

    def create_config(self):
        new_name = self.new_name_entry.get()
        if not new_name:
            tkinter.messagebox.showerror(title="Error", message="Filename cannot be empty")
            return
        if read_config(new_name + ".ini", True):
            self.reload()

    def reload(self):
        self.master.destroy()
        config_window = Toplevel(v.root)
        config_window.title("Configurations")
        ConfigWindow(config_window)

    def open_config_description_window(self, config):
        self.master.wm_attributes("-topmost", False)
        config_description_window = Toplevel(self.master)
        config_description_window.title("{} - Description".format(config))
        ConfigDescriptionWindow(config_description_window, config, self.master)


class FolderWindow:
    def __init__(self, master):
        self.master = master
        self.frame = Frame(self.master)
        self.frame.pack(fill="both", expand=True)
        self.frame.grid(row=1, column=0, sticky="nsew")
        self.master.wm_attributes("-topmost", True)

        self.src_field = None
        self.dst_field = None

        self.next_row = 1

        self.config_file = Entry(self.frame, textvariable=v.loaded_config_file, width=50)
        self.config_file.grid(column=0, row=self.next_row, sticky="NSEW")
        self.config_file.bind("<Key>", lambda e: "break")
        self.next_row += 1
        Label(self.frame, text="").grid(column=0, row=self.next_row)
        self.next_row += 1

        src_col_label = ttk.Label(self.frame, anchor="center", text="Source")
        src_col_label.grid(column=0, row=self.next_row, sticky="NSEW")
        dst_col_label = ttk.Label(self.frame, anchor="center", text="Destination")
        dst_col_label.grid(column=2, row=self.next_row, sticky="NSEW")
        self.next_row += 1

        for src, dst in zip(src_list, dst_list):
            src_label = ttk.Label(self.frame, text=src, anchor="center")
            src_label.grid(column=0, row=self.next_row, sticky="NSEW")
            dst_label = ttk.Label(self.frame, text=dst, anchor="center")
            dst_label.grid(column=2, row=self.next_row, sticky="NSEW")
            remove_button = ttk.Button(self.frame, text="X", command=lambda s=src, d=dst: self.remove_src_dst(s, d))
            remove_button.grid(column=3, row=self.next_row, sticky="NSEW")
            self.next_row += 1

        self.add_button = ttk.Button(self.frame, text="+", command=self.add_folder)
        self.add_button.grid(column=0, row=self.next_row)

        self.close_button = ttk.Button(self.frame, text="Close", command=self.master.destroy)
        self.close_button.grid(column=1, row=self.next_row)

        for column in range(0, 2):
            self.master.columnconfigure(column, weight=1)
            self.frame.columnconfigure(column, weight=1)
        for row in range(0, self.next_row + 1):
            self.master.rowconfigure(row, weight=1)
            self.frame.rowconfigure(row, weight=1)

    def add_folder(self):
        self.add_button.destroy()
        self.close_button.destroy()

        self.src_field = Entry(self.frame, width=70)
        self.src_field.grid(column=0, row=self.next_row)
        self.dst_field = Entry(self.frame, width=70)
        self.dst_field.grid(column=2, row=self.next_row)

        swap_button = Button(self.frame, text="Swap", command=self.swap_folders)
        swap_button.grid(column=1, row=self.next_row)

        self.next_row += 1

        src_select_button = Button(self.frame, text="...", command=lambda: self.select_directory(self.src_field))
        src_select_button.grid(column=0, row=self.next_row)
        dst_select_button = Button(self.frame, text="...", command=lambda: self.select_directory(self.dst_field))
        dst_select_button.grid(column=2, row=self.next_row)
        self.next_row += 1

        self.close_button = Button(self.frame, text="Close", command=self.confirm_close)
        self.close_button.grid(column=1, row=self.next_row)

        confirm_button = Button(self.frame, text="Confirm", command=lambda: self.confirm_add_folder(self.src_field.get(), self.dst_field.get(), ))
        confirm_button.grid(column=2, row=self.next_row)

    def swap_folders(self):
        tmp = self.src_field.get()
        self.src_field.delete(0, 'end')
        self.src_field.insert(0, self.dst_field.get())
        self.dst_field.delete(0, 'end')
        self.dst_field.insert(0, tmp)

    def confirm_close(self):
        if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to close without saving?"):
            self.master.destroy()

    def remove_src_dst(self, src, dst):
        logger.info("Removing folder pair {} and {}".format(src, dst))

        global src_list
        global dst_list

        if tkinter.messagebox.askyesno(title="Confirmation", message="Are you sure you want to delete this folder pair?"):
            src_list.remove(src)
            dst_list.remove(dst)
            v.loaded_config["FOLDERS"]["src"] = folder_list_to_string(src_list)
            v.loaded_config["FOLDERS"]["dst"] = folder_list_to_string(dst_list)
            write_config()
            check_remaining_files()

            self.reload()

    def reload(self):
        self.master.destroy()
        folder_window = Toplevel(v.root)
        folder_window.title("Folders")
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
        self.frame = Frame(self.master)

        self.interval_label = ttk.Label(self.frame, text="Synchronisation interval (days):")
        self.interval_label.pack(fill="both", expand=True, padx=20, pady=20)

        self.interval_input = ttk.Entry(self.frame)
        self.interval_input.pack(fill="both", expand=True, padx=20, pady=20)

        # insert current interval
        logger.info("Loaded Sync Interval {} from config {}".format(v.loaded_config["PARAMETERS"]["saveinterval"], v.loaded_config_filename))
        self.current_interval = v.loaded_config["PARAMETERS"]["saveinterval"]
        self.interval_input.insert(0, self.current_interval)

        self.confirm_button = ttk.Button(self.frame, text="Confirm",
                                         command=self.confirm_interval_change)
        self.confirm_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.close_button = ttk.Button(self.frame, text="Cancel", command=self.master.destroy)
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
            logger.error("Interval change: '{}' is not an integer.".format(new_interval))
            tkinter.messagebox.showerror(title="Invalid Input", message="Interval must be a positive Integer.")
            return

        logger.info("Changed interval from {} to {} for config {}.".format(self.current_interval, new_interval, v.loaded_config_filename))
        v.loaded_config["PARAMETERS"]["saveinterval"] = str(new_interval)
        write_config()
        self.master.destroy()


class MainPage:
    def __init__(self, master):
        self.master = master
        self.frame = Frame(self.master)

        self.config_file = Entry(self.frame, textvariable=v.loaded_config_file)
        self.config_file.pack(fill="both", expand=True, padx=20, pady=20)
        # make entry read only
        self.config_file.bind("<Key>", lambda e: "break")

        self.manage_config_button = Button(self.frame, text="Manage Configurations", command=self.open_config_window)
        self.manage_config_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.folders_button = Button(self.frame, text="Folders", command=self.open_folder_window)
        self.folders_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.sync_button = Button(self.frame, text="Synchronize Now", command=start_sync)
        self.sync_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.interval_button = Button(self.frame, text="Set Update Interval", command=self.open_interval_window)
        self.interval_button.pack(fill="both", expand=True, padx=20, pady=20)

        self.close = Button(self.frame, text="Quit", command=v.root.destroy)
        self.close.pack(fill="both", expand=True, padx=20, pady=20)

        self.remaining = Entry(self.frame, textvariable=v.remaining_files)
        self.remaining.pack(fill="both", expand=True, padx=20, pady=20)
        self.remaining.bind("<Key>", lambda e: "break")

        self.current_file = Entry(self.frame, textvariable=v.current_file)
        self.current_file.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_file.bind("<Key>", lambda e: txt_event(e))

        self.frame.pack(fill="both", expand=True)

    def open_interval_window(self):
        interval_window = Toplevel(self.master)
        interval_window.title("Set Interval")
        IntervalWindow(interval_window)

    def open_folder_window(self):
        folder_window = Toplevel(self.master)
        folder_window.title("Folders")
        FolderWindow(folder_window)

    def open_config_window(self):
        config_window = Toplevel(self.master)
        config_window.title("Configurations")
        ConfigWindow(config_window)


def initialize():
    # clear illegal and forbidden path files
    illegal_path_file = os.getcwd().replace("\\", "/") + "/illegal_paths.txt"
    illegal_path_file_handler = open(illegal_path_file, "w")
    illegal_path_file_handler.close()

    forbidden_path_file = os.getcwd().replace("\\", "/") + "/forbidden_paths.txt"
    forbidden_path_file_handler = open(forbidden_path_file, "w")
    forbidden_path_file_handler.close()


if __name__ == '__main__':
    initialize()

    v.root = Tk()
    v.root.title("Backup")
    v.root.geometry("600x800")

    v.remaining_files = StringVar()
    v.current_file = StringVar()
    v.loaded_config_file = StringVar()

    v.loaded_config = read_config(v.default_config_file)

    main_page = MainPage(v.root)

    check_remaining_files()

    v.root.mainloop()

    handler.close()
