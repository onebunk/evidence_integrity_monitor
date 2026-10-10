# Michael Bunke
# CYBR260 Final Project - Evidence Integrity Monitor
# Listener Module
# Due 10/9/2026
#
# This module runs on the monitoring machine. It listens on a TCP port for event
# messages sent by the Watcher Module and records each one in a SQLite database,
# which is the permanent log. When an evidence file is modified, deleted, or
# moved, it also shows a pop-up that stays on screen until it is dismissed. Once
# a day, at a set time, it shows a summary of that day's activity.
#
# This module is set up to run at login through Windows Task Scheduler. It starts
# before the Watcher Module so it is ready for the first events.


import socket
import json
import sqlite3
from datetime import datetime
import os
import subprocess
import sys
import threading
import time


# ----- SETTINGS -----

# 0.0.0.0 means "accept connections on any network interface". The port must
# match LISTENER_PORT in the Watcher Module.
HOST = "0.0.0.0"
PORT = 5000

# Hour (24-hour clock) when the daily summary appears. 16 = 4:00 PM, an hour
# before the end of a typical workday.
SUMMARY_HOUR = 16

# ----- DATABASE -----

# This is the permanent log of events. It is kept separate from the watcher's own
# events.db so the two never write to the same file when testing on one machine.
# check_same_thread=False lets the summary thread use this connection, and the
# lock makes the threads take turns.
database_connection = sqlite3.connect("listener_events.db", check_same_thread=False)
#print("Listener database:", os.path.abspath("listener_events.db"))
cursor = database_connection.cursor()
db_lock = threading.Lock()

def create_events_table():
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            file_path TEXT,
            event_type TEXT,
            timestamp TEXT,
            old_hash TEXT,
            new_hash TEXT
        )
    """)
    database_connection.commit()

def log_event(case_id, file_path, event_type, timestamp, old_hash, new_hash):
    try:
        with db_lock:
            cursor.execute("""
                INSERT INTO events (case_id, file_path, event_type, timestamp, old_hash, new_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (case_id, file_path, event_type, timestamp, old_hash, new_hash))
            database_connection.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        log_event_fallback(case_id, file_path, event_type, timestamp, old_hash, new_hash)

def log_event_fallback(case_id, file_path, event_type, timestamp, old_hash, new_hash):
    try:
        with open("fallback_log.txt", "a") as f:
            f.write(f"{timestamp} | Case: {case_id} | {event_type} | {file_path} | "
                    f"old_hash: {old_hash} | new_hash: {new_hash}\n")
    except OSError as e:
        print(f"CRITICAL: Could not write to fallback log either: {e}")

create_events_table()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print(f"Listener is waiting on port {PORT}...")

# This makes pop-ups persistent, otherwise they will be only momentarily displayed.
# The now need to be manually cleared.

def persistent_popup(title, message):
    """
    Shows a dialog that stays on screen until someone clicks OK. Windows
    notifications disappear on their own, which is not good enough for evidence
    alerts. The dialog runs as a separate process (alert_popup.py) so the
    listener keeps receiving events while it is open.
    """
    popup_script = os.path.join(os.path.dirname(__file__), "alert_popup.py")
    subprocess.Popen([sys.executable, popup_script, title, message])



def show_alert(event):
    """Shows a pop-up describing one event."""
    persistent_popup(f"Evidence change: {event['case_id']}",
    f"{event['event_type'].upper()}: {event['file_path']}")

# Daily Summary set to run once a day at set time. Pulls from Listener / server rather than the Watcher.

def daily_summary():
    today = datetime.now().strftime("%Y-%m-%d")
    # print("Searching for:", today + "%")
    try:
        with db_lock:
            cursor.execute("""
                SELECT event_type, COUNT(*) FROM events
                WHERE timestamp LIKE ? GROUP BY event_type
            """, (today + "%",))
            counts = dict(cursor.fetchall())
            cursor.execute("""
                    SELECT COUNT(DISTINCT case_id) FROM events WHERE timestamp LIKE ?
                    """, (today + "%",))
            case_count = cursor.fetchone()[0]
    except sqlite3.Error as e:
        print(f"Database error building summary: {e}")
        return
    total = sum(counts.values())
    if total == 0:
        message = "No file activity recorded today."
    else:
        breakdown = ", ".join(f"{n} {t}" for t, n in counts.items())
        message = f"{total} events across {case_count} case(s): {breakdown}"

    print(f"Daily summary: {message}")
    persistent_popup("Daily evidence activity summary", message)




def summary_scheduler():
    """Runs in the background, checking the clock and showing the summary once a day."""
    last_run = None
    while True:
        now = datetime.now()
        if now.hour == SUMMARY_HOUR and last_run != now.date():
            daily_summary()
            last_run = now.date()
        time.sleep(30)

threading.Thread(target=summary_scheduler, daemon=True).start()

while True:
    client, addr = server.accept()
    data = client.recv(4096)
    client.close()
    if not data:
        continue
    try:
        event = json.loads(data.decode())
    except json.JSONDecodeError:
        print(f"Ignored a malformed message from {addr}")
        continue
    log_event(event["case_id"], event["file_path"], event["event_type"],
              event["timestamp"], event["old_hash"], event["new_hash"])
    print(f"Logged: {event['event_type']} - {event['file_path']}")
    if event["event_type"].startswith(("modified", "deleted", "moved")):
        show_alert(event)

