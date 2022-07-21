import _tkinter as _tk
import tkinter as tk
import unittest
from time import sleep

import backup
import vars
import os


class TKinterTestCase(unittest.TestCase):
    """These methods are going to be the same for every GUI test,
    so refactored them into a separate class
    """

    def setUp(self):
        # run init function
        self.root = backup.initialize()
        self.pump_events()
        self.main_page = backup.main_page

    def tearDown(self):
        if self.root:
            try:
                self.root.destroy()
            except tk.TclError:
                pass
            self.pump_events()

    def pump_events(self):
        while self.root.dooneevent(_tk.ALL_EVENTS | _tk.DONT_WAIT):
            pass


class OpenApplication(TKinterTestCase):
    def test_open_close(self):
        # check if open
        self.root.winfo_viewable()
        # click close button
        self.main_page.close.invoke()
        # check if closed
        self.assertRaises(_tk.TclError, self.root.winfo_viewable)

    def test_open_close_folder_window(self):
        self.main_page.folders_button.invoke()
        self.assertIsInstance(self.main_page.guest, backup.FolderWindow)
        folder_window = self.main_page.guest
        # check if folder window open
        self.assertTrue(folder_window.exists())
        # click folder window close button
        folder_window.close_button.invoke()
        # check if folder window closed
        self.assertFalse(folder_window.exists())

    def test_update_window(self):
        update_window = tk.Toplevel(self.root)
        update_window.title("New Update")
        backup.UpdateWindow(update_window, "latest_version")
        self.pump_events()


class ConfigurationWindowTest(TKinterTestCase):
    def setUp(self):
        super().setUp()
        self.main_page.manage_config_button.invoke()
        self.pump_events()
        self.assertIsInstance(self.main_page.guest, backup.ConfigWindow)
        self.config_window = self.main_page.guest

    def test_open_close_config_window(self):
        # check if config window open
        self.assertTrue(self.config_window.exists())
        self.config_window.close_button.invoke()
        # check if config window closed
        self.assertFalse(self.config_window.exists())

    def test_create_new_config(self):
        test_config_name = "__unit_test_config__"
        test_config_path = f"{vars.config_dir}/{test_config_name}.ini"
        # remove testfile if already exists
        if os.path.exists(test_config_path):
            os.remove(test_config_path)
        self.config_window.new_button.invoke()
        self.config_window.new_name_entry.focus_set()
        self.config_window.new_name_entry.insert(tk.END, test_config_name)
        self.config_window.confirm_button.invoke()
        self.pump_events()
        # check if config exists
        self.assertTrue(os.path.exists(test_config_path))
        # cleanup
        os.remove(test_config_path)

    def test_cancel_description_change(self):
        self.main_page.manage_config_button.invoke()
        config_widget = self.main_page.guest
        config_widget.description_buttons["config"].invoke()
        description_window = config_widget.description_window
        description_window.cancel_button.invoke()
        self.pump_events()

    def test_confirm_description_change(self):
        self.main_page.manage_config_button.invoke()
        config_widget = self.main_page.guest
        config_widget.description_buttons["config"].invoke()
        description_window = config_widget.description_window
        description_window.confirm_button.invoke()
        self.pump_events()

    def create_config(self):
        pass


if __name__ == '__main__':
    unittest.main()
