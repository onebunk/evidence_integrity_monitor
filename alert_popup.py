# Michael Bunke
# CYBR 260 Final Project
# Alert Popup Module
# Due 10/9/2026
#
# This "Alert Popup module is needed to maintain persistent pop-ups since plyer alone created only
# momentary pop-ups. This was not functional with plyer as notification could eventually disappear.
#

import sys
import tkinter as tk
from tkinter import messagebox

root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)
messagebox.showwarning(sys.argv[1], sys.argv[2], parent=root)
root.destroy()