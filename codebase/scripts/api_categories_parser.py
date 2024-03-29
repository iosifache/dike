#!/usr/bin/env python3
"""Script for mapping Windows API functions to their corresponding categories.

API categories and the mapping are defines on the open-source repository
report-parser.

The script is meant to be run on the terminal. Its output is placed on a YAML
file, into a custom format.

Usage:
    ./api_categories_parser.py
"""
import modules.features.extractors as extractors
import yaml
from modules.configuration.folder_structure import Files
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces, LoggedMessageTypes

CATEGORIES = [
    "Activation Context Reference", "Authentication Functions",
    "Configuration Reference", "Console Functions", "Cryptography Functions",
    "Debugging Functions", "Driver Support Routines",
    "Dynamic-Link Library Functions", "File Management Functions",
    "Font and Text Functions", "Functions",
    "HTTP Server API Version 2.0 Functions", "Handle and Object Functions",
    "IMFSignedLibrary", "IP Helper Functions", "Memory Management Functions",
    "Process and Thread Functions", "Registry Functions", "Resource Functions",
    "Service Functions", "String Functions",
    "Structured Exception Handling Functions", "Synchronization Functions",
    "System Information Functions", "Time Functions", "Tool Help Functions",
    "Tools, Best Practices, and Guidance", "Using File Mapping",
    "WinINet Functions", "Windows Networking Functions", "Winsock Functions"
]
FUNCTIONS = {
    "CertControlStore": "Cryptography Functions",
    "CertOpenStore": "Cryptography Functions",
    "CoCreateInstance": "Functions",
    "CoCreateInstanceEx": "Functions",
    "CoGetClassObject": "Functions",
    "CoInitializeEx": "Functions",
    "CoInitializeSecurity": "Functions",
    "CoUninitialize": "Functions",
    "CopyFileA": "File Management Functions",
    "CopyFileW": "File Management Functions",
    "CreateActCtxW": "Activation Context Reference",
    "CreateDirectoryW": "Directory Management Functions",
    "CreateProcessInternalW": "Process and Thread Functions",
    "CreateRemoteThread": "Process and Thread Functions",
    "CreateThread": "Process and Thread Functions",
    "CreateToolhelp32Snapshot": "Tool Help Functions",
    "CryptAcquireContextA": "Cryptography Functions",
    "CryptAcquireContextW": "Cryptography Functions",
    "CryptCreateHash": "Cryptography Functions",
    "CryptDecodeObjectEx": "Cryptography Functions",
    "CryptDecrypt": "Cryptography Functions",
    "CryptEncrypt": "Cryptography Functions",
    "CryptExportKey": "Cryptography Functions",
    "CryptGenKey": "Cryptography Functions",
    "CryptHashData": "Cryptography Functions",
    "CryptProtectData": "Cryptography Functions",
    "CryptUnprotectData": "Cryptography Functions",
    "DeleteFileW": "File Management Functions",
    "DeviceIoControl": "Device Management Functions",
    "DrawTextExA": "cat_not_found",
    "DrawTextExW": "Font and Text Functions",
    "EncryptMessage": "Authentication Functions",
    "EnumWindows": "Authorization Functions",
    "FindFirstFileExW": "File Management Functions",
    "FindResourceA": "Resource Functions",
    "FindResourceExW": "Resource Functions",
    "FindResourceW": "Resource Functions",
    "FindWindowA": "Window Functions",
    "FindWindowExW": "Window Functions",
    "FindWindowW": "Window Functions",
    "GetAdaptersAddresses": "IP Helper Functions",
    "GetAdaptersInfo": "IP Helper Functions",
    "GetAddrInfoW": "Winsock Functions",
    "GetBestInterfaceEx": "IP Helper Functions",
    "GetComputerNameA": "System Information Functions",
    "GetComputerNameW": "System Information Functions",
    "GetCursorPos": "Cursor Functions",
    "GetDiskFreeSpaceExW": "Disk Management Functions",
    "GetFileAttributesExW": "File Management Functions",
    "GetFileAttributesW": "File Management Functions",
    "GetFileInformationByHandle": "File Management Functions",
    "GetFileInformationByHandleEx": "File Management Functions",
    "GetFileSize": "File Management Functions",
    "GetFileSizeEx": "File Management Functions",
    "GetFileType": "File Management Functions",
    "GetFileVersionInfoExW": "Version Information Functions",
    "GetFileVersionInfoSizeExW": "Version Information Functions",
    "GetFileVersionInfoSizeW": "Version Information Functions",
    "GetFileVersionInfoW": "Version Information Functions",
    "GetForegroundWindow": "Window Functions",
    "GetKeyState": "Keyboard Input Functions",
    "GetKeyboardState": "Keyboard Input Functions",
    "GetNativeSystemInfo": "System Information Functions",
    "GetShortPathNameW": "File Management Functions",
    "GetSystemDirectoryA": "System Information Functions",
    "GetSystemDirectoryW": "System Information Functions",
    "GetSystemInfo": "System Information Functions",
    "GetSystemMetrics": "Configuration Reference",
    "GetSystemTimeAsFileTime": "Time Functions",
    "GetSystemWindowsDirectoryW": "System Information Functions",
    "GetTempPathW": "File Management Functions",
    "GetTimeZoneInformation": "Time Functions",
    "GetUserNameA": "System Information Functions",
    "GetUserNameExA": "System Information Functions",
    "GetUserNameExW": "System Information Functions",
    "GetUserNameW": "System Information Functions",
    "GetVolumeNameForVolumeMountPointW": "Volume Management Functions",
    "GetVolumePathNameW": "Volume Management Functions",
    "GetVolumePathNamesForVolumeNameW": "Volume Management Functions",
    "GlobalMemoryStatus": "Memory Management Functions",
    "GlobalMemoryStatusEx": "Memory Management Functions",
    "HttpOpenRequestA": "WinINet Functions",
    "HttpOpenRequestW": "WinINet Functions",
    "HttpQueryInfoA": "Synchronization Functions",
    "HttpSendRequestA": "WinINet Functions",
    "HttpSendRequestW": "WinINet Functions",
    "IWbemServices_ExecMethod": "cat_not_found",
    "IWbemServices_ExecQuery": "cat_not_found",
    "InternetCloseHandle": "WinINet Functions",
    "InternetConnectA": "WinINet Functions",
    "InternetConnectW": "WinINet Functions",
    "InternetCrackUrlA": "WinINet Functions",
    "InternetCrackUrlW": "WinINet Functions",
    "InternetOpenA": "WinINet Functions",
    "InternetOpenUrlA": "WinINet Functions",
    "InternetOpenUrlW": "WinINet Functions",
    "InternetOpenW": "WinINet Functions",
    "InternetQueryOptionA": "WinINet Functions",
    "InternetReadFile": "WinINet Functions",
    "InternetSetOptionA": "WinINet Functions",
    "IsDebuggerPresent": "Debugging Functions",
    "LdrGetDllHandle": "Dynamic-Link Library Functions",
    "LdrGetProcedureAddress": "IMFSignedLibrary",
    "LdrLoadDll": "Using File Mapping",
    "LdrUnloadDll": "Tools, Best Practices, and Guidance",
    "LoadResource": "Resource Functions",
    "LoadStringA": "String Functions",
    "LoadStringW": "String Functions",
    "LookupAccountSidW": "Authorization Functions",
    "LookupPrivilegeValueW": "Registry Functions",
    "MessageBoxTimeoutA": "Debugging Functions",
    "MessageBoxTimeoutW": "Cryptography Functions",
    "Module32FirstW": "Tool Help Functions",
    "Module32NextW": "Tool Help Functions",
    "MoveFileWithProgressW": "File Management Functions",
    "NetShareEnum": "Network Share Management Functions",
    "NtAllocateVirtualMemory": "Memory Management Functions",
    "NtClose": "Handle and Object Functions",
    "NtCreateFile": "File Management Functions",
    "NtCreateKey": "Registry Functions",
    "NtCreateMutant": "Synchronization Functions",
    "NtCreateSection": "Memory Management Functions",
    "NtCreateThreadEx": "Process and Thread Functions",
    "NtDelayExecution": "Process and Thread Functions",
    "NtDeleteFile": "Winsock Functions",
    "NtDeviceIoControlFile": "HTTP Server API Version 2.0 Functions",
    "NtDuplicateObject": "Handle and Object Functions",
    "NtEnumerateKey": "Driver Support Routines",
    "NtEnumerateValueKey": "Driver Support Routines",
    "NtFreeVirtualMemory": "Driver Support Routines",
    "NtGetContextThread": "Debugging Functions",
    "NtMapViewOfSection": "File Management Functions",
    "NtOpenDirectoryObject": "cat_not_found",
    "NtOpenFile": "File Management Functions",
    "NtOpenKey": "Driver Support Routines",
    "NtOpenKeyEx": "Registry Functions",
    "NtOpenMutant": "Synchronization Functions",
    "NtOpenProcess": "Process and Thread Functions",
    "NtOpenSection": "Driver Support Routines",
    "NtOpenThread": "Process and Thread Functions",
    "NtProtectVirtualMemory": "Memory Management Functions",
    "NtQueryAttributesFile": "Winsock Functions",
    "NtQueryDirectoryFile": "Driver Support Routines",
    "NtQueryInformationFile": "Process and Thread Functions",
    "NtQueryKey": "Registry Functions",
    "NtQuerySystemInformation": "System Information Functions",
    "NtQueryValueKey": "Driver Support Routines",
    "NtReadFile": "File Management Functions",
    "NtReadVirtualMemory": "Debugging Functions",
    "NtResumeThread": "Process and Thread Functions",
    "NtSetContextThread": "Window Functions",
    "NtSetInformationFile": "Driver Support Routines",
    "NtSetValueKey": "Driver Support Routines",
    "NtTerminateProcess": "Process and Thread Functions",
    "NtUnmapViewOfSection": "Windows Networking Functions",
    "NtWriteFile": "File Management Functions",
    "ObtainUserAgentString": "API index",
    "OleInitialize": "Functions",
    "OpenSCManagerA": "Service Functions",
    "OpenSCManagerW": "Service Functions",
    "OpenServiceA": "Service Functions",
    "OpenServiceW": "Service Functions",
    "OutputDebugStringA": "Debugging Functions",
    "Process32FirstW": "Tool Help Functions",
    "Process32NextW": "Tool Help Functions",
    "ReadProcessMemory": "Debugging Functions",
    "RegCloseKey": "Registry Functions",
    "RegCreateKeyExA": "Version Information Functions",
    "RegCreateKeyExW": "Registry Functions",
    "RegDeleteKeyW": "Registry Functions",
    "RegDeleteValueW": "Registry Functions",
    "RegEnumKeyExA": "Registry Functions",
    "RegEnumKeyExW": "Registry Functions",
    "RegEnumKeyW": "Registry Functions",
    "RegEnumValueA": "Registry Functions",
    "RegEnumValueW": "Registry Functions",
    "RegOpenKeyExA": "Registry Functions",
    "RegOpenKeyExW": "Registry Functions",
    "RegQueryInfoKeyA": "Registry Functions",
    "RegQueryInfoKeyW": "Registry Functions",
    "RegQueryValueExA": "Registry Functions",
    "RegQueryValueExW": "Registry Functions",
    "RegSetValueExA": "Registry Functions",
    "RegSetValueExW": "Registry Functions",
    "RtlAddVectoredContinueHandler": "cat_not_found",
    "RtlAddVectoredExceptionHandler":
    "Structured Exception Handling Functions",
    "RtlDecompressBuffer": "System Information Functions",
    "RtlRemoveVectoredExceptionHandler": "cat_not_found",
    "SHGetFolderPathW": "Deprecated API",
    "SHGetSpecialFolderLocation": "Deprecated API",
    "SearchPathW": "Debugging Functions",
    "SendNotifyMessageA": "Message Functions",
    "SendNotifyMessageW": "Message Functions",
    "SetEndOfFile": "File Management Functions",
    "SetErrorMode": "Error Handling Functions",
    "SetFileAttributesW": "File Management Functions",
    "SetFileInformationByHandle": "File Management Functions",
    "SetFilePointer": "File Management Functions",
    "SetFilePointerEx": "File Management Functions",
    "SetFileTime": "Time Functions",
    "SetUnhandledExceptionFilter": "Structured Exception Handling Functions",
    "SetWindowsHookExA": "Hook Functions",
    "ShellExecuteExW": "Shell Functions",
    "SizeofResource": "Resource Functions",
    "StartServiceA": "Service Functions",
    "Thread32First": "Tool Help Functions",
    "Thread32Next": "Tool Help Functions",
    "UnhookWindowsHookEx": "Hook Functions",
    "UuidCreate": "RPC Functions",
    "WSARecv": "Winsock Functions",
    "WSASend": "Winsock Functions",
    "WSASocketA": "Winsock Functions",
    "WSASocketW": "Winsock Functions",
    "WSAStartup": "Winsock Functions",
    "WriteConsoleA": "Console Functions",
    "WriteConsoleW": "cat_not_found",
    "WriteProcessMemory": "Debugging Functions",
    "__exception__": "cat_not_found",
    "accept": "Winsock Functions",
    "bind": "Winsock Functions",
    "closesocket": "Winsock Functions",
    "connect": "Winsock Functions",
    "getaddrinfo": "Winsock Functions",
    "gethostbyname": "Winsock Functions",
    "getsockname": "Winsock Functions",
    "ioctlsocket": "Winsock Functions",
    "listen": "System Information Functions",
    "recv": "Winsock Functions",
    "select": "Winsock Functions",
    "send": "Winsock Functions",
    "sendto": "Winsock Functions",
    "setsockopt": "Winsock Functions",
    "shutdown": "Winsock Functions",
    "socket": "Winsock Functions"
}


class CustomDumper(yaml.Dumper):
    """Class implementing a custom YAML dumper."""

    def increase_indent(self, flow=False, indentless=False):  # noqa
        return super(CustomDumper, self).increase_indent(flow, False)


def main():
    """Main function."""
    # pylint: disable=global-statement
    functions = FUNCTIONS

    configuration = ConfigurationManager()
    features_config = configuration.get_space(ConfigurationSpaces.FEATURES)

    # Create an extractor for API calls to be able to use the normalization
    # method
    api_extractor = extractors.DynamicAPIs()
    api_extractor.set_configuration(
        features_config["apis"]["ignored_prefixes"],
        features_config["apis"]["ignored_suffixes"])

    formatted_categories = dict()
    for category in CATEGORIES:
        formatted_categories[category] = [
            api_extractor.normalize_function_name(function)
            for function in functions if functions[function] == category
        ]
        functions = {
            function: functions[function]
            for function in functions if functions[function] != category
        }

    with open(Files.API_CATEGORIZATION, "w") as output_file:
        output_file.write(yaml.dump(formatted_categories, Dumper=CustomDumper))

    Logger(is_enabled=True).log(("The categorization of the Windows API "
                                 "functions was finished"),
                                LoggedMessageTypes.SUCCESS)


if __name__ == "__main__":
    main()
