#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <iostream>
#include <set>
#include <string>
#include <vector>
#include <filesystem>
#include <shlobj.h>
#include <regex>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")

bool IsFileSigned(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileData = {};
    fileData.cbStruct = sizeof(fileData);
    fileData.pcwszFilePath = filePath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    return (status == ERROR_SUCCESS);
}

bool WasEventLogCleared(HANDLE hLog) {
    const DWORD flags = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ;
    const size_t bufferSize = 64 * 1024;
    std::vector<BYTE> buffer(bufferSize);
    DWORD bytesRead = 0, bytesNeeded = 0;

    while (ReadEventLogW(hLog, flags, 0, buffer.data(), buffer.size(), &bytesRead, &bytesNeeded)) {
        BYTE* pRecord = buffer.data();
        while (pRecord < buffer.data() + bytesRead) {
            EVENTLOGRECORD* record = reinterpret_cast<EVENTLOGRECORD*>(pRecord);
            if (record->EventID == 104) {
                return true;
            }
            pRecord += record->Length;
        }
    }
    return false;
}

std::vector<std::wstring> GetCrashedExecutables(HANDLE hLog, DWORD flags, size_t bufferSize) {
    std::vector<std::wstring> crashedExecutables;
    std::set<std::wstring> seen; // Für Duplikate
    std::vector<BYTE> buffer(bufferSize);
    DWORD bytesRead = 0, bytesNeeded = 0;
    std::wregex exeRegex(LR"((?:[A-Z]:\\[^ ]*?\.exe))", std::regex_constants::icase);

    while (ReadEventLogW(hLog, flags, 0, buffer.data(), buffer.size(), &bytesRead, &bytesNeeded)) {
        BYTE* pRecord = buffer.data();
        while (pRecord < buffer.data() + bytesRead) {
            EVENTLOGRECORD* record = reinterpret_cast<EVENTLOGRECORD*>(pRecord);
            if (record->EventID == 1000 || record->EventID == 1001 || record->EventID == 1002) {
                LPCWSTR strings = reinterpret_cast<LPCWSTR>(pRecord + record->StringOffset);
                for (int i = 0; i < record->NumStrings; i++) {
                    std::wstring str(strings);
                    std::wsmatch match;
                    if (std::regex_search(str, match, exeRegex)) {
                        std::wstring exePath = match.str();
                        if (seen.insert(exePath).second) // Nur wenn noch nicht gesehen
                            crashedExecutables.push_back(exePath);
                    }
                    strings += wcslen(strings) + 1;
                }
            }
            pRecord += record->Length;
        }
    }
    return crashedExecutables;
}

// Ctrl+C / Ctrl+Break Handler
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_BREAK_EVENT) {
        std::wcout << L"\nCtrl+C / Ctrl+Break pressed, ignored.\n";
        return TRUE;
    }
    return FALSE;
}

int wmain() {
    // Set console title
    SetConsoleTitleW(L"Eventlog Crashed Tool by onexions");

    // Ctrl+C abfangen
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Admin Check
    if (!IsUserAnAdmin()) {
        std::wcerr << L"[ERROR] This program must be run with administrator rights.\n";
        return 1;
    }

    HANDLE hLog = OpenEventLogW(NULL, L"Application");
    if (!hLog) {
        std::wcerr << L"[ERROR] Could not open Application event log.\n";
        return 1;
    }

    if (WasEventLogCleared(hLog)) {
        std::wcout << L"[NOTICE] The Event Log has been cleared at least once.\n";
    } else {
        std::wcout << L"[INFO] The Event Log does not appear to have been cleared.\n";
    }

    CloseEventLog(hLog);
    hLog = OpenEventLogW(NULL, L"Application");

    const DWORD flags = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ;
    const size_t bufferSize = 64 * 1024;

    auto crashedExecutables = GetCrashedExecutables(hLog, flags, bufferSize);

    size_t maxPathLength = 0;
    for (const auto& exe : crashedExecutables) {
        if (exe.length() > maxPathLength)
            maxPathLength = exe.length();
    }
    size_t colStart = maxPathLength + 5;

    if (crashedExecutables.empty()) {
        std::wcout << L"[INFO] No crashed executables found.\n";
    } else {
        std::wcout << L"\nCrashed executables (newest first):\n";
        for (const auto& exe : crashedExecutables) {
            bool exists = std::filesystem::exists(exe);
            bool signedFile = exists && IsFileSigned(exe);

            std::wcout << exe;

            if (exe.length() < colStart)
                std::wcout << std::wstring(colStart - exe.length(), L' ');

            std::wcout << (exists ? L"Present" : L"Deleted") << " | ";
            std::wcout << (exists ? (signedFile ? L"Signed" : L"Unsigned") : L"-") << "\n";
        }
    }

    CloseEventLog(hLog);

    std::wcout << L"\nPress any key to exit...";

    // Warte auf einen Tastendruck, aber ignoriere Ctrl und Ctrl+C
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

    INPUT_RECORD inputRecord;
    DWORD eventsRead;
    do {
        ReadConsoleInput(hStdin, &inputRecord, 1, &eventsRead);

        // Prüfe, ob es ein KeyEvent ist und die Taste gedrückt wurde
        if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown) {
            WORD vk = inputRecord.Event.KeyEvent.wVirtualKeyCode;
            DWORD ctrlState = inputRecord.Event.KeyEvent.dwControlKeyState;

            // Ignoriere Strg, Strg+C, Tab und Windows-Tasten
            if ((vk == VK_CONTROL) ||
                (vk == 'C' && (ctrlState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED))) ||
                (vk == VK_TAB) ||
                (vk == VK_LWIN) ||
                (vk == VK_RWIN)) {
                continue; // Schleife fortsetzen, Programm bleibt offen
            }
            break; // Bei allen anderen Tasten beenden
        }
    } while (true);

    return 0;
}
