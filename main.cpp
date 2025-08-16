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
#include <chrono>
#include <ctime>
#include <iomanip>

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

std::wstring RelativeTime(DWORD eventTime) {
    using namespace std::chrono;
    auto now = system_clock::to_time_t(system_clock::now());
    auto diff = now - eventTime;

    if (diff < 60 * 60 * 24) return L"today";
    if (diff < 60 * 60 * 48) return L"yesterday";
    if (diff < 60 * 60 * 24 * 7) return L"this week";
    if (diff < 60 * 60 * 24 * 30) return L"this month";
    if (diff < 60 * 60 * 24 * 365) return L"this year";
    return L"long ago";
}

struct CrashInfo {
    std::wstring exePath;
    DWORD timeGenerated;
};

std::vector<CrashInfo> GetCrashedExecutables(HANDLE hLog, DWORD flags, size_t bufferSize) {
    std::vector<CrashInfo> crashedExecutables;
    std::set<std::wstring> seen;
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
                        if (seen.insert(exePath).second)
                            crashedExecutables.push_back({ exePath, record->TimeGenerated });
                    }
                    strings += wcslen(strings) + 1;
                }
            }
            pRecord += record->Length;
        }
    }
    return crashedExecutables;
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_BREAK_EVENT) {
        std::wcout << L"\nCtrl+C / Ctrl+Break pressed, ignored.\n";
        return TRUE;
    }
    return FALSE;
}

int wmain() {
    SetConsoleTitleW(L"Eventlog Crashed Tool by onexions");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

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
    for (const auto& info : crashedExecutables) {
        if (info.exePath.length() > maxPathLength)
            maxPathLength = info.exePath.length();
    }
    size_t colStart = maxPathLength + 5;

    const int statusWidth = 8;   // "Present"/"Deleted"
    const int signWidth = 9;     // "Signed"/"Unsigned"/"-"
    const int timeWidth = 12;    // "today"/"yesterday"/...

    size_t neededWidth = colStart + statusWidth + 3 + signWidth + 3 + timeWidth + 1;

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        SHORT currentWidth = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        if (neededWidth > currentWidth) {
            COORD newSize = csbi.dwSize;
            newSize.X = static_cast<SHORT>(neededWidth);
            SetConsoleScreenBufferSize(hConsole, newSize);

            SMALL_RECT newRect = csbi.srWindow;
            newRect.Right = newRect.Left + static_cast<SHORT>(neededWidth) - 1;
            SetConsoleWindowInfo(hConsole, TRUE, &newRect);
        }
    }

    if (crashedExecutables.empty()) {
        std::wcout << L"[INFO] No crashed executables found.\n";
    } else {
        std::wcout << L"\nCrashed executables (newest first):\n";
        for (const auto& info : crashedExecutables) {
            bool exists = std::filesystem::exists(info.exePath);
            bool signedFile = exists && IsFileSigned(info.exePath);

            std::wcout << std::left << std::setw(static_cast<int>(colStart))
                << info.exePath;

            if (!exists) {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << std::left << std::setw(statusWidth) << L"Deleted";
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            } else {
                std::wcout << std::left << std::setw(statusWidth) << L"Present";
            }
            std::wcout << " | ";

            std::wstring signStr = exists ? (signedFile ? L"Signed" : L"Unsigned") : L"-";
            if (signStr == L"Unsigned") {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << std::left << std::setw(signWidth) << signStr;
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            } else {
                std::wcout << std::left << std::setw(signWidth) << signStr;
            }
            std::wcout << " | ";

            std::wcout << std::left << std::setw(timeWidth)
                << RelativeTime(info.timeGenerated) << "\n";
        }
    }

    CloseEventLog(hLog);

    std::wcout << L"\nPress any key to exit...";

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

    INPUT_RECORD inputRecord;
    DWORD eventsRead;
    do {
        ReadConsoleInput(hStdin, &inputRecord, 1, &eventsRead);

        if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown) {
            WORD vk = inputRecord.Event.KeyEvent.wVirtualKeyCode;
            DWORD ctrlState = inputRecord.Event.KeyEvent.dwControlKeyState;

            if ((vk == VK_CONTROL) ||
                (vk == 'C' && (ctrlState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED))) ||
                (vk == VK_TAB) ||
                (vk == VK_LWIN) ||
                (vk == VK_RWIN)) {
                continue;
            }
            break;
        }
    } while (true);

    return 0;
}
