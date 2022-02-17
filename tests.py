import unittest
import tkinter as tk
import _tkinter as _tk
import ttkbootstrap as ttks
from time import sleep

import backup
import vars


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


if __name__ == '__main__':
    unittest.main()
