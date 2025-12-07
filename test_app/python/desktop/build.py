import PyInstaller.__main__
import customtkinter
import os
import platform

# Get the path to customtkinter to include its assets
ctk_path = os.path.dirname(customtkinter.__file__)

# Determine the separator for --add-data based on OS
# Windows uses ';', Linux/Unix uses ':'
sep = ';' if platform.system() == "Windows" else ':'

print(f"Building for {platform.system()}...")
print(f"Including CustomTkinter from: {ctk_path}")

PyInstaller.__main__.run([
    'main.py',
    '--name=LoginApp',
    '--onefile',
    '--noconsole',
    f'--add-data={ctk_path}{sep}customtkinter',
    '--clean',
])
