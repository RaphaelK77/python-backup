import logging
from datetime import date
from datetime import datetime
from tkinter import *
from tkinter import ttk

from plyer import notification

import backup
import vars as v

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
handler = logging.FileHandler(filename='backup.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class AutoUpdate:
    def __init__(self, master):
        self.master = master
        self.frame = Frame(self.master)
        self.frame.pack(fill="both", expand=True)

        self.config_file = Entry(self.frame, textvariable=v.loaded_config_file)
        self.config_file.pack(fill="both", expand=True, padx=20, pady=20)
        # make entry read only
        self.config_file.bind("<Key>", lambda e: "break")

        remaining = ttk.Entry(self.frame, textvariable=v.remaining_files)
        remaining.pack(fill="both", expand=True, padx=20, pady=20)
        remaining.bind("<Key>", lambda e: "break")

        current_file = ttk.Entry(self.frame, textvariable=v.current_file)
        current_file.pack(fill="both", expand=True, padx=20, pady=20)
        current_file.bind("<Key>", lambda e: "break")

        close = ttk.Button(self.frame, text="Quit", command=self.master.destroy)
        close.pack(fill="both", expand=True, padx=20, pady=20)


def check_if_sync():
    """Check if current config should be synchronized"""
    try:
        last_run = v.loaded_config["PARAMETERS"]["last_run"]
        last_run_date = datetime.strptime(last_run, '%Y-%m-%d').date()
        days_since_last_run = (date.today() - last_run_date).days
        logger.info("Config: {}, {} days since last run, saveInterval is {}.".format(v.loaded_config_filename, days_since_last_run, v.loaded_config["PARAMETERS"]["saveinterval"]))
        if not int(v.loaded_config["PARAMETERS"]["saveinterval"]) <= days_since_last_run:
            logger.info("Not updating config {}.".format(v.loaded_config_filename))
            return False
    except KeyError:
        pass
    return True


def auto_sync():
    for config in backup.get_config_files():
        logger.info("Current config: {}".format(config))
        backup.read_config(config)

        if check_if_sync():
            backup.sync()
            logger.info("Done synchronizing config {}".format(v.loaded_config_filename))

        v.loaded_config["PARAMETERS"]["last_run"] = str(date.today())
        backup.write_config()
    logger.info("Synchronization complete. Closing GUI.")
    v.root.destroy()


if __name__ == '__main__':
    v.root = Tk()
    v.root.title("Backup Auto")
    v.root.geometry("600x300")

    backup.initialize()
    v.remaining_files = StringVar()
    v.current_file = StringVar()
    v.loaded_config_file = StringVar()

    v.loaded_config = backup.read_config(v.default_config_file)

    backup.check_remaining_files()

    auto_update = AutoUpdate(v.root)

    v.root.after(5, auto_sync())

    v.root.mainloop()

    if v.illegal_paths:
        illegal_paths_message = "\n{} files were ignored due to their path length.".format(
            len(v.illegal_paths))
    else:
        illegal_paths_message = ""

    if v.forbidden_paths:
        forbidden_paths_message = "\n{} files were ignored due to restricted access.".format(
            len(v.forbidden_paths))
    else:
        forbidden_paths_message = ""

    logger.info("Backup done. Notification will now be displayed.")
    # show windows notification of completion
    try:
        notification.notify(title="Backup", message="Synchronisation complete. Copied {} file(s).".format(v.changed) + illegal_paths_message, timeout=300)
    except Exception as e:
        logger.error(e)

