"""
FOLDER ENCRYPTOR
It is safe but only suitable for HOME USE!
"""
import pathlib
import os
from tkinter import filedialog
from decrypt import decrypt_folder
from encrypt import encrypt_folder
import maskpass
import misc_utils
import sys
from pathlib import Path
while True:
    choice = input("Enter 1 To Encrypt, 2 To Decrypt, 3 To Exit:")
    if choice not in ["1", "2", "3"]:
        print("Please enter 1, 2 or 3")
        continue
    if choice == "1":
        while True:
            second_choice = input("Enter 1 To Select Folder, 2 To Enter Path, 3 To Exit:")
            if second_choice not in ["1", "2", "3"]:
                print("Error! Try 1, 2 or 3!")
                continue
            elif second_choice == "1":
                print("Enter Path To Folder")
                folder = pathlib.Path(filedialog.askdirectory())
                if not folder:
                    print("Error! Folder Not Chosen!")
                    continue
            elif second_choice == "2":
                folder = Path(input("Enter Path To Folder:"))
                if not misc_utils.is_exists(folder):
                    print("Error! Folder Not Found!")
                    continue
            else:
                break
            password = maskpass.askpass("Enter Password To Encrypt:")
            if not password:
                print("Error! Password Is Empty!")
                continue
            if "pass.hash" in os.listdir(folder) or "pass.salt" in os.listdir(folder):
                print("Folder is seems to already being encrypted")
                choice_overwrite = input("You sure you want to encrypt again? (Y/n):")
                if choice_overwrite != "Y":
                    continue
                else:
                    pass
            encrypt_folder(password, folder)
            print("Folder Encrypted Successful!")
    elif choice == "2":
        while True:
            third_choice = input("Enter 1 To Select Folder, 2 To Enter Path, 3 To Exit:")
            if third_choice not in ["1", "2", "3"]:
                print("Error! Try 1, 2 or 3!")
                continue
            elif third_choice == "1":
                print("Enter Path To Folder")
                folder = pathlib.Path(filedialog.askdirectory())
                if not folder:
                    print("Error! Folder Not Chosen!")
                    continue
            elif third_choice == "2":
                folder = Path(input("Enter Path To Folder:"))
                if not misc_utils.is_exists(folder):
                    print("Error! Folder Not Found!")
                    continue
            else:
                break
            password = maskpass.askpass("Enter Password To Decrypt:")
            try:
                decrypt_folder(password, folder)
                print("Folder Decrypted Successful!")
            except Exception as e:
                print(f"Decryption failed: {e}")
                print("Data Is Corrupted!")
    else:
        sys.exit()
