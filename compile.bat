@echo off
pyinstaller Backup.spec -n Backup -i device_floppy.ico --noconfirm --noconsole --onefile
pyinstaller Backup_autorun.spec -n Backup_Autorun -i device_floppy.ico --noconfirm --noconsole --onefile
echo "Done."
pause