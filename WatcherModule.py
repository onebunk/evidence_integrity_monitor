# Michael Bunke
# CYBR 260 Final Project - Evidence Integrity Monitor
# Watcher Module
# Due 10/9/2026
#
# This module runs on the storage device and watches the case folders for file
# changes (created / modified / deleted / moved). For each change to an evidence
# file it works out the case ID from the folder name, computes a SHA-256 hash,
# and sends the event to the Listener Module over a TCP socket. If the listener
# cannot be reached, the event is saved to a local cache file and resent later.
# Every event is also logged to a local SQLite database. Together these keep a
# record for chain of custody and the integrity of evidence files.
# This module is set up to run at login through the Windows Task Schedule with a
# 30 second delay so the Listener Module is already running. "Start in" is set
# to the project folder so the database and cache files are always created in
# the same place.
#
# Installation of Watchdog is necessary for this to run (pip install watchdog)
#





import socket
import time
import os
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import sqlite3
from pathlib import Path
import hashlib
import json
import threading

# ----- SETTINGS -----

# Address and port of the Listener Module. 127.0.0.1 for testing on one
# machine; change it to the monitoring machine's IP address when deployed.

LISTENER_HOST = "127.0.0.1"
LISTENER_PORT = 5000

# Connections set-up when the watcher starts.
# check_same_thread=False is needed because watchdog runs the event handlers on its
# own thread. The lock makes sure only one thread writes to the database at a time.

conn = sqlite3.connect("events.db", check_same_thread=False)
db_lock = threading.Lock()

# Find events.db

print("Database file location:", os.path.abspath("events.db"))

cursor = conn.cursor()

# Create events table if NOT EXISTS

def create_events_table():
    """Creates the events table the first time the watcher runs."""
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
    conn.commit()

create_events_table()

# File types that are tool output rather than evidence (reports, Cellebrite
# Reader executables, etc.), so they are not hashed. .txt is included because it
# was easy to edit while testing. Created, deleted, and moved events for these
# files are still logged, just without a hash.

EXCLUDED_EXTENSIONS = (".pdf", ".docx", ".exe", ".txt")

def is_relevant_file(file_path):
    """
    Returns False for the file types above, so they are not hashed.
    .lower() makes sure .PDF and .pdf are treated the same.
    """

    return not file_path.lower().endswith(EXCLUDED_EXTENSIONS)

# Verify SHA-256 hash values

def compute_hash(file_path):
    """
    Return SHA-256 of a file as a hex string,
    or None if the file cannot be read.
    """
    sha256 = hashlib.sha256()
    try:
        # Opened in binary mode ("rb") because hashing needs the raw bytes.
        with open(file_path, "rb") as f:
            # Reads 1 MB at a time so a large image does not fill up memory.
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError as e:
        # A locked or unreadable file returns None so the watcher keeps running.
        print(f"Could not hash {file_path}: {e}")
        return None


# Cache for pending alert if server / ListenerModule is down.

PENDING_FILE = "pending_alerts.json1"

def cache_pending_event(event):
    """Saves an unsent event to resend when the listener is back online."""
    try:
        with open(PENDING_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        print(f"CRITICAL: Event did not cache: {e}")

# Connect and send to Listener_Module / Server.

def try_send(event):
    """Attempt one send. Returns True if delivered, False if not."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((LISTENER_HOST, LISTENER_PORT))
            # json.dumps() turns the dictionary into a string and .encode() turns it
            # into bytes, sockets can only send bytes.
            s.sendall(json.dumps(event).encode())
        return True
    except OSError as e:
        print(f"Could not reach listener: {e}")
        return False

def send_event(case_id, file_path, event_type, timestamp, old_hash, new_hash):
    """Builds the event dictionary, sends it, and caches it if the send fails."""
    event = {"case_id": case_id, "file_path": file_path, "event_type": event_type,
             "timestamp": timestamp, "old_hash": old_hash, "new_hash": new_hash}
    # Cached events go first so the listener gets them in the order they happened.
    if os.path.exists(PENDING_FILE) and os.path.getsize(PENDING_FILE) > 0:
        retry_pending_events()
    if not try_send(event):
        cache_pending_event(event)

# This will Resend cached event in order, if it fails again it will stay in the cache.

def retry_pending_events():
    """Resends the cached events, oldest first. Anything that still fails stays cached."""
    if not os.path.exists(PENDING_FILE):
        return
    with open(PENDING_FILE, "r") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    sent = 0
    for line in lines:
        if not try_send(json.loads(line)):
            break  # listener still down, stop and keep the rest in order
        sent += 1
    # Rewrite the cache file with only the events that were not sent.
    with open(PENDING_FILE, "w") as f:
        for line in lines[sent:]:
            f.write(line + "\n")
    print(f"Resent {sent} cached event(s); {len(lines) - sent} still pending.")

# Logging
def log_event(case_id, file_path, event_type, old_hash, new_hash):
    """Sends the event to the listener, then logs it to the local database."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    send_event(case_id, file_path, event_type, timestamp, old_hash, new_hash)

    try:
        with db_lock:
            # The ? placeholders keep file names from being run as SQL.
            cursor.execute("""
                INSERT INTO events (case_id, file_path, event_type, timestamp, old_hash, new_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (case_id, file_path, event_type, timestamp, old_hash, new_hash))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error while logging event for {file_path}: {e}")
        # If the database write fails the event goes to the fallback file so it is not lost.
        log_event_fallback(case_id, file_path, event_type, timestamp, old_hash, new_hash)


def log_event_fallback(case_id, file_path, event_type, timestamp, old_hash, new_hash):
    """
    Writes event to local backup file if the database write fails,
    to avoid loss.
    """
    try:
        with open("fallback_log.txt", "a") as f:
            f.write(f"{timestamp} | Case: {case_id} | {event_type} | {file_path} | "
                     f"old_hash: {old_hash} | new_hash: {new_hash}\n")
    except OSError as e:
        print(f"CRITICAL: Could not write to fallback log either: {e}")


# Cleanup: called when the watcher shuts down.
def close_log_connection():
    conn.close()

# Lookup function for recovering last hash of relevant evidence files.

def get_last_hash(file_path):
    """
    Return the most recent hash for a file path,
    or None if there is no prior hash
    """
    try:
        with db_lock:
            # Newest row first, and only rows that have a hash (excluded files never do).
            cursor.execute("""
            SELECT new_hash FROM events
            WHERE file_path = ? AND new_hash IS NOT NULL
            ORDER BY event_id DESC LIMIT 1
        """, (file_path,))
            row = cursor.fetchone()
    except sqlite3.Error as e:
        print(f"Database error looking up hash for {file_path}: {e}")
        return None
    # row is None when the file has no earlier hash.
    return row[0] if row else None

# Folder to watch. Layout is WATCH_ROOT / investigator folder / case folder / evidence files.
WATCH_ROOT = Path.home() / "Documents" / "Watcher_Test"

def get_case_id(file_path):
    """
    Returns the case folder name for a file based on the structure:
    WATCH_ROOT / investigator_###_ / case / files ...
    will return "UNASSIGNED" if the file is not in a case folder.
    """
    try:
        relative = Path(file_path).relative_to(WATCH_ROOT)
    except ValueError:
        return "UNASSIGNED"

    parts = relative.parts
    # Needs at least investigator, case, and a file name.
    if len(parts) >= 3:
        return parts[1]
    return "UNASSIGNED"


class BasicHandler(FileSystemEventHandler):
    """Watchdog calls these methods when a file changes in the watched folders."""

    def on_created(self, event):
        # Folders are skipped. Excluded types are logged but not hashed.
        if event.is_directory:
            return
        new_hash = compute_hash(event.src_path) if is_relevant_file(event.src_path) else None
        log_event(get_case_id(event.src_path), event.src_path, "created", None, new_hash)

    def on_modified(self, event):
        # Edits to excluded types are not logged, without a hash there is no way to
        # tell a real change from the repeat events one save creates.
        if event.is_directory or not is_relevant_file(event.src_path):
            return
        old_hash = get_last_hash(event.src_path)
        new_hash = compute_hash(event.src_path)
        if old_hash == new_hash:
            return # content didn't change, skip the duplicate event
        log_event(get_case_id(event.src_path), event.src_path, "modified", old_hash, new_hash)

    def on_deleted(self, event):
        # The file is gone so only the last known hash can be recorded.
        if event.is_directory:
            return
        old_hash = get_last_hash(event.src_path)  # None for excluded files, since they are never hashed
        log_event(get_case_id(event.src_path), event.src_path, "deleted", old_hash, None)

    def on_moved(self, event):
        # Watchdog also reports a rename (including a changed file extension) as a move.
        # The contents should not change so the hash at the destination should match
        # the hash recorded before the move. On Windows a move between folders shows
        # up as a delete and a create instead.
        if event.is_directory:
            return
        old_hash = get_last_hash(event.src_path)
        new_hash = compute_hash(event.dest_path) if is_relevant_file(event.dest_path) else None
        log_event(get_case_id(event.src_path), event.dest_path,
                  f"moved from {event.src_path}", old_hash, new_hash)


if __name__ == "__main__":

    """Path to Watch"""
    path_to_watch = str(WATCH_ROOT)

    handler = BasicHandler()
    observer = Observer()
    # recursive=True so the investigator and case folders underneath are watched too.
    observer.schedule(handler, path_to_watch, recursive=True)
    # Send anything cached while the listener was offline before watching for new events.
    retry_pending_events()
    observer.start()

    print(f"Watching {path_to_watch}...")
    # The observer runs on its own thread. This loop just keeps the program running
    # until it is stopped with Ctrl+C.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Close the database once the watcher has stopped.
close_log_connection()