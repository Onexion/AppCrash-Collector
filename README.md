# Eventlog Crashed Tool

A Windows tool to collect and analyze crashed executables from the Application Event Log.

## Features

- Detects if the Application Event Log has been cleared.
- Collects Event IDs: `1000`, `1001`, `1002`.
- Extracts crashed executable paths from event logs.
- Checks if executables exist on disk.
- Verifies if executables are digitally signed.
- Displays results in chronological order (newest first).
- Handles Ctrl+C / Ctrl+Break gracefully.
- Requires administrator rights.

## Safety & VirusTotal Scan

All files collected by this tool have been scanned with [VirusTotal](https://www.virustotal.com/gui/file/9f3e9c08d8507a9dc6c5545ddd5864b9673b33c8281c9357d67fc26bd64a82cc/detection) to ensure they are safe.  
This tool itself has also been tested and shows **no detection** on VirusTotal.

- You can verify by uploading the `EventlogCrashedTool.exe` or any collected executables to VirusTotal yourself.
- No system files are modified; the tool only reads event logs and file metadata.
  
## Usage

1. Run the program as Administrator.
2. The tool will open the Application Event Log.
3. It will check if the log has been cleared and display a notice.
4. It will list all crashed executables, indicating:
   - `Present` or `Deleted`
   - `Signed` or `Unsigned`
5. Press any key (other than Ctrl, Ctrl+C, Tab, or Windows keys) to exit.

## Build Instructions

Requires:

- Windows SDK
- C++17 compatible compiler

Compile with:

```bash
g++ -O2 -Wall -std=c++17 -municode -mconsole main.cpp -o MyProgram.exe -ladvapi32 -lwintrust -s`
```

(.md made by chatgpt)
