# Evidence Integrity Monitor

**Status:** class project prototype. Tested only with test data and not deployed. It needs more testing before it is used on a system holding real evidence.

A Python tool that watches case folders on a storage device, hashes evidence files, and sends every change to a separate monitoring machine that keeps a permanent log and raises alerts.

Built for CYBR-260 (Security Scripting with Python) at Champlain College Online.

---

## Why this exists

Digital forensic images are hashed when they are acquired and again when they are transferred. This project adds a second, independent layer: a continuous record of what happens to the files after that. If an image is modified, deleted, or moved, there is a timestamped entry stored on a different machine than the one being watched, with the file's hash where one applies.

The design assumes a closed lab network with no internet access, so nothing in it depends on email, cloud services, or any outside connection.

## How it works

```
 WATCHER (runs near the storage)               LISTENER (monitoring machine)
 ------------------------------               -----------------------------
 watchdog detects a file event                 waits for connections
        |                                             |
 work out the case ID from the folder                 |
        |                                             |
 hash the file (SHA-256) unless its                   |
 type is on the exclusion list                        |
        |                                             |
 build event message (JSON) ---- TCP socket ---->  receives message
        |                                             |
 if listener is unreachable:                    writes to SQLite log
 save to a local pending file                         |
 and resend later                              pop-up that stays until
                                               dismissed for modified,
                                               deleted, and moved files
                                                      |
                                               daily summary at 4:00 PM
```

Two separate scripts, plus a small helper:

- **WatcherModule.py** detects, hashes, and sends.
- **ListenerModule.py** receives, logs, and alerts.
- **alert_popup.py** is the dialog window the listener opens for each alert.

## Design decisions and why

| Decision | Reason |
|---|---|
| Event-driven monitoring with `watchdog` | Re-hashing every file on a timer would be wasteful, especially with images that can be hundreds of GB or more. `watchdog` uses the operating system's own file-change notifications, so the script sits idle until something actually happens. |
| Plain TCP sockets for alerts | The storage has no internet access, which rules out email. TCP guarantees delivery and ordering, which UDP does not, and a dropped integrity alert would defeat the purpose of the tool. |
| Database lives on the listener, not the watcher | The record of what happened should not sit on the device being monitored. |
| SQLite for the event log | The main need is querying by case and by day. A flat file would mean loading everything and filtering in Python. SQLite handles that with one query and enforces a fixed structure. |
| JSON for messages | Sockets only carry bytes. A Python dictionary becomes a JSON string, then bytes, then is reversed on the other side. |
| A new connection for each alert | Events are infrequent, so the simplicity is worth more than the small saving from keeping a connection open. |
| Send events immediately, not in a daily batch | Batching holds events in memory, and a crash would lose them. Sending immediately means each event is stored the moment it happens. The daily summary reads from the log that already exists. |
| Cache unsent events and resend in order | If the listener is down, events are saved to a local file and replayed oldest-first once it returns. Original timestamps are kept, so the log shows when things happened, not when they were delivered. |
| SHA-256, read in 1 MB chunks | Chunked reading keeps memory use flat. A plain read of a 1 TB image would try to load the whole thing into memory. |
| Case ID taken from the folder structure | Folders are laid out as `root / investigator / case / files`, so the case is the second folder level. Files outside a case folder are logged as `UNASSIGNED`, which is worth noticing in its own right. |
| Some file types are not hashed, but their created, deleted, and moved events are still logged | Reports, documents, and viewer executables are tool output, not evidence, and `.txt` files were easy to edit while testing. Hashing them would be wasted work, but a report appearing, disappearing, or leaving a case folder is still worth a record. Edits to these files are not tracked, since without a hash a real change cannot be told apart from the repeat events one save produces. |
| Pop-ups use a small tkinter dialog run as a separate process | Windows notifications disappear on their own, which is a problem for evidence alerts. A dialog stays up until someone dismisses it. Running it as its own process keeps the listener receiving events while a dialog is open. A built-in Windows message box (`ctypes`) was considered and rejected because it only works on Windows, and tkinter keeps the option of running the listener on a Raspberry Pi. |
| Windows Task Scheduler runs both scripts at login | A service that starts before login cannot show windows on the desktop. The watcher starts 30 seconds after the listener so the listener is ready for its first events. |
| Parameterized SQL queries (`?` placeholders) | Prevents SQL injection from odd file names or values. |
| Fallback log file | If a database write fails, the event is written to a text file instead of being lost. |

## Data and transformations

| Data | Type | Transformation |
|---|---|---|
| File path | string | Stripped of the watch root to find the case folder |
| File contents | bytes | Read in chunks and turned into a fixed-length hash string |
| Hash | string | Stored as hex text; compared to the previous hash for the same file |
| Timestamp | datetime | Formatted as `YYYY-MM-DD HH:MM:SS` text |
| Watchdog event object | object | Pulled apart into a dictionary of the fields that matter |
| Event dictionary | dict | `json.dumps()` to a string, then `.encode()` to bytes for the socket; reversed on the listener |

## Event handling

| Event | What is logged |
|---|---|
| Created | New hash (empty for types that are not hashed); no previous hash |
| Modified | Previous hash and new hash; skipped if the two are identical, and skipped for types that are not hashed |
| Deleted | Last known hash (empty for types that are not hashed); no new hash |
| Moved | Destination path, source in the event text, and the hash at the destination. Watchdog also reports renames, including a changed file extension, as moves. |

## Modules used

`watchdog` (third party), and from the standard library: `socket`, `json`, `sqlite3`, `hashlib`, `threading`, `subprocess`, `tkinter`, `pathlib`, `os`, `datetime`, `time`.

## Running it

1. Install the one dependency: `pip install watchdog`
2. Set `WATCH_ROOT` in the watcher to the folder to monitor.
3. Set `LISTENER_HOST` and `LISTENER_PORT` in the watcher to match the listener.
4. Start the listener first: `python ListenerModule.py`
5. Start the watcher: `python WatcherModule.py`

To run them at login on Windows, create two Task Scheduler tasks with the trigger "At log on". Point each at your Python executable with the script name as the argument, and set "Start in" to the project folder so the database files always land in the same place. Delay the watcher task by 30 seconds.

Expected folder layout under the watch root: `investigator folder / case folder / evidence files`.

On a Raspberry Pi or other Linux machine, the tkinter dialogs may need `sudo apt install python3-tk`.

## Current status

**Working**
- Detects created, modified, deleted, and moved files
- SHA-256 hashing with change detection
- File types that are not hashed are still logged for created, deleted, and moved events
- Case ID from the folder structure
- Event messages over TCP to the listener
- Listener logging to SQLite with a fallback file
- Pop-up alerts that stay until dismissed, for modified, deleted, and moved files
- Daily summary pop-up at 4:00 PM
- Caching of unsent events with ordered resend, both at startup and while running
- Both scripts start at login through Task Scheduler

## Known limitations

- **Files that already exist when the watcher starts have no baseline** until the first time they change.
- **On Windows, a move between folders arrives as a delete followed by a create**, not a single move. For files that are hashed, the deleted row's old hash matches the created row's new hash, which shows it is the same file. A move into or out of the watched folders also looks like a create or a delete, because the watcher cannot see the other end.
- **A copy out of the watched folders is not detected.** A copy inside them appears only as a created file. Catching data leaving the storage would need operating system file access auditing, which is a different project.
- **A "created" event fires when a file first appears, not when it finishes copying.** Large images will need a check that the file has stopped growing before it is hashed.
- **The watcher still keeps its own copy of the log**, which it uses to look up a file's previous hash.
- **Messages are not authenticated or encrypted.** Anyone who can reach the listener's port could send a false event. That is acceptable on an isolated lab network and would not be in production.
- **The daily summary is skipped** if the listener is not running during the 4:00 PM hour.
- Paths, the listener address, and the port are set in the code.
- Tested with small files, not forensic images.

## Problems hit along the way

- SQLite refused to be used from watchdog's background thread. Fixed with `check_same_thread=False` and a lock around every database write.
- Handler calls with the wrong number of arguments killed the observer thread silently, so nothing was logged after the first error. Reading the *last* line of a traceback, not the first, is what pointed to the cause.
- A listener that crashed on an empty message. It now ignores malformed or empty messages and keeps running.
- The daily summary reported "no activity" every day because of a lowercase `%y` in the date format. It produced a two-digit year that never matched the stored timestamps.
- Moved files never raised a pop-up. The watcher stores a move as "moved from <path>", and the listener checked for exactly "moved".
- I assumed a cut and paste between folders would arrive as one moved event. On Windows it arrives as a delete and a create.

## Possible next steps

- Hash a file only after it has stopped growing, so large images are handled safely
- Pair a delete and a create into one "moved" entry when their hashes match within a few seconds
- Give the watcher its own baseline store and remove the duplicate log
- Authenticate or encrypt the connection
- Run the listener on a small single-board computer with a display
