#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <sstream>

#include <lm.h>
#pragma comment(lib, "Netapi32.lib")

#include <userenv.h>
#pragma comment(lib, "Userenv.lib")

// A stripped down version of restarting with a God token
// Still has the same permissions just a simpler api
// All errors are written to the console
// A return of FALSE means the call failed and we are not a God
// A return of TRUE means we can now continue execution as a God
BOOL Transcend(int argc, char** argv) {
	/* KNOWN ISSUE
	NtCreateToken only works with pointers to stack memory or pointers to
	heap memory allocated with LocalAlloc or GlobalAlloc. C++ style new[]
	or C style malloc will not work.
	*/
	/* KNOWN ISSUE
	The SE_UNSOLICITED_INPUT_NAME privilege is not supported on Windows 10
	home edition and therefore is not given to the god token.
	*/

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;
	typedef struct OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
	typedef NTSTATUS(*PNtCreateToken)(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups, PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner, PTOKEN_PRIMARY_GROUP TokenPrimaryGroup, PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource);

	// Check if the current token has admin or is already a god token
	BOOL alreadyAdmin = FALSE;
	BOOL alreadyGod = FALSE;
	{
		HANDLE currentToken = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentToken)) {
			std::wcerr << L"ERROR: Failed to create open current process token." << std::endl;
			return FALSE;
		}
		DWORD currentTokenElevationLength = 0;
		TOKEN_ELEVATION currentTokenElevation = { };
		if (!GetTokenInformation(currentToken, TokenElevation, &currentTokenElevation, sizeof(TOKEN_ELEVATION), &currentTokenElevationLength) || currentTokenElevationLength != sizeof(TOKEN_ELEVATION)) {
			CloseHandle(currentToken);
			std::wcerr << L"ERROR: Failed to get token source for current process token." << std::endl;
			return FALSE;
		}
		alreadyAdmin = currentTokenElevation.TokenIsElevated != 0;
		DWORD currentTokenSourceLength = 0;
		TOKEN_SOURCE currentTokenSource = { };
		if (!GetTokenInformation(currentToken, TokenSource, &currentTokenSource, sizeof(TOKEN_SOURCE), &currentTokenSourceLength) || currentTokenSourceLength != sizeof(TOKEN_SOURCE)) {
			CloseHandle(currentToken);
			std::wcerr << L"ERROR: Failed to get token source for current process token." << std::endl;
			return FALSE;
		}
		alreadyGod = lstrcmpA(currentTokenSource.SourceName, "MYSTERY") == 0;
		if (!CloseHandle(currentToken)) {
			std::wcerr << L"ERROR: Failed to close current process token." << std::endl;
			return FALSE;
		}
	}

	if (alreadyGod) {
		return TRUE;
	}

	// Enable all privilegs for current token
	{
		HANDLE currentToken = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentToken)) {
			std::wcerr << L"ERROR: Failed to create open current process token." << std::endl;
			return FALSE;
		}
		DWORD currentTokenPrivilegesLength = 0;
		GetTokenInformation(currentToken, TokenPrivileges, NULL, 0, &currentTokenPrivilegesLength);
		if (currentTokenPrivilegesLength == 0) {
			std::wcerr << L"ERROR: Failed to get length of current token privileges." << std::endl;
			return FALSE;
		}
		TOKEN_PRIVILEGES* currentTokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(new BYTE[currentTokenPrivilegesLength]);
		DWORD currentTokenPrivilegesLength2 = 0;
		if (!GetTokenInformation(currentToken, TokenPrivileges, currentTokenPrivileges, currentTokenPrivilegesLength, &currentTokenPrivilegesLength2) || currentTokenPrivilegesLength != currentTokenPrivilegesLength2) {
			delete[] currentTokenPrivileges;
			std::wcerr << L"ERROR: Failed to get current token privileges." << std::endl;
			return FALSE;
		}
		for (DWORD i = 0; i < currentTokenPrivileges->PrivilegeCount; i++) {
			currentTokenPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
		}
		if (!AdjustTokenPrivileges(currentToken, FALSE, currentTokenPrivileges, currentTokenPrivilegesLength, NULL, NULL) || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			delete[] currentTokenPrivileges;
			std::wcerr << L"ERROR: Failed to adjust token privileges." << std::endl;
			return FALSE;
		}
		delete[] currentTokenPrivileges;
		if (!CloseHandle(currentToken)) {
			std::wcerr << L"ERROR: Failed to close current process token." << std::endl;
			return FALSE;
		}
	}

	if (!alreadyAdmin) {
		// Get command line and current exe path
		std::wostringstream exePathStream = { };
		exePathStream << "\"" << argv[0] << "\"";
		std::wstring exePathString = exePathStream.str();
		LPWSTR exePath = new WCHAR[exePathString.size() + 1];
		memcpy(exePath, exePathString.c_str(), exePathString.size() * sizeof(WCHAR));
		exePath[exePathString.size()] = '\0';
		std::wostringstream commandLineStream = { };
		for (int i = 1; i < argc; i++) {
			if (i >= 2) {
				commandLineStream << " ";
			}
			commandLineStream << "\"" << argv[i] << "\"";
		}
		std::wstring commandLineString = commandLineStream.str();
		LPWSTR commandLine = new WCHAR[commandLineString.size() + 1];
		memcpy(commandLine, commandLineString.c_str(), commandLineString.size() * sizeof(WCHAR));
		commandLine[commandLineString.size()] = '\0';

		// Restart the current process as admin with a UAC
		SHELLEXECUTEINFOW shellExecuteInfo = { };
		shellExecuteInfo.cbSize = sizeof(SHELLEXECUTEINFO);
		shellExecuteInfo.fMask = SEE_MASK_NOASYNC;
		shellExecuteInfo.hwnd = NULL;
		shellExecuteInfo.lpVerb = L"runas";
		shellExecuteInfo.lpFile = exePath;
		shellExecuteInfo.lpParameters = commandLine;
		shellExecuteInfo.lpDirectory = NULL;
		shellExecuteInfo.nShow = SW_SHOWNORMAL;
		shellExecuteInfo.hInstApp = NULL;
		shellExecuteInfo.lpIDList = NULL;
		shellExecuteInfo.lpClass = NULL;
		shellExecuteInfo.hkeyClass = NULL;
		shellExecuteInfo.dwHotKey = 0;
		shellExecuteInfo.hMonitor = NULL;
		shellExecuteInfo.hProcess = NULL;
		if (!ShellExecuteExW(&shellExecuteInfo)) {
			delete[] exePath;
			delete[] commandLine;
			std::wcerr << L"ERROR: Failed to shell execute current process with a UAC." << std::endl;
			return FALSE;
		}
		delete[] exePath;
		delete[] commandLine;

		// Exit the process now that we restarted with a UAC
		ExitProcess(0);
	}


	// Locate the PID of lsass.exe
	DWORD lsassPID = 0;
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			std::wcerr << L"ERROR: Failed to create snapshot." << std::endl;
			return FALSE;
		}
		PROCESSENTRY32W processEntry = { };
		processEntry.dwSize = sizeof(PROCESSENTRY32W);
		if (!Process32FirstW(snapshot, &processEntry)) {
			CloseHandle(snapshot);
			std::wcerr << L"ERROR: Failed to get first process from snapshot." << std::endl;
			return FALSE;
		}
		do {
			if (lstrcmpW(processEntry.szExeFile, L"lsass.exe") == 0) {
				lsassPID = processEntry.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &processEntry));
		DWORD lastError = GetLastError();
		if (lastError != 0 && lastError != ERROR_NO_MORE_FILES) {
			CloseHandle(snapshot);
			std::wcerr << L"ERROR: Failed to get next process from snapshot." << std::endl;
			return FALSE;
		}
		if (!CloseHandle(snapshot)) {
			std::wcerr << L"ERROR: Failed to close handle to snapshot." << std::endl;
			return FALSE;
		}
		if (lsassPID == 0) {
			std::wcerr << L"ERROR: Failed to process id of lsass.exe." << std::endl;
			return FALSE;
		}
	}

	// Impersonate lsass.exe
	{
		HANDLE lsass = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPID);
		if (lsass == NULL) {
			std::wcerr << L"ERROR: Failed to open handle to lsass.exe." << std::endl;
			return FALSE;
		}
		HANDLE lsassToken = NULL;
		if (!OpenProcessToken(lsass, TOKEN_QUERY | TOKEN_DUPLICATE, &lsassToken)) {
			CloseHandle(lsass);
			std::wcerr << L"ERROR: Failed to open handle to token of lsass.exe." << std::endl;
			return FALSE;
		}
		if (!ImpersonateLoggedOnUser(lsassToken)) {
			if (!SetThreadToken(NULL, lsassToken)) {
				CloseHandle(lsassToken);
				CloseHandle(lsass);
				std::wcerr << L"ERROR: Failed to impersonate token of lsass.exe." << std::endl;
				return FALSE;
			}
		}
		if (!CloseHandle(lsassToken)) {
			CloseHandle(lsass);
			std::wcerr << L"ERROR: Failed to close handle to token of lsass.exe." << std::endl;
			return FALSE;
		}
		if (!CloseHandle(lsass)) {
			std::wcerr << L"ERROR: Failed to close handle to lsass.exe." << std::endl;
			return FALSE;
		}
	}

	HANDLE godToken = NULL;
	{
		// Load NtCreateToken function from ntdll.dll
		HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
		if (ntdll == NULL) {
			std::wcerr << L"ERROR: Failed to load library ntdll.dll." << std::endl;
			return FALSE;
		}
		PNtCreateToken NtCreateToken = reinterpret_cast<PNtCreateToken>(GetProcAddress(ntdll, "NtCreateToken"));
		if (NtCreateToken == NULL) {
			std::wcerr << L"ERROR: Failed to locate NtCreateToken from ntdll.dll." << std::endl;
			return FALSE;
		}

		// Prepare access mask for function call to NtCreateToken
		ACCESS_MASK desiredAccess = TOKEN_ALL_ACCESS;

		// Prepare security quality of server for function call to NtCreateToken
		SECURITY_QUALITY_OF_SERVICE securityQualityOfService = { };
		securityQualityOfService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
		securityQualityOfService.ImpersonationLevel = SecurityAnonymous;
		securityQualityOfService.ContextTrackingMode = SECURITY_STATIC_TRACKING;
		securityQualityOfService.EffectiveOnly = FALSE;

		// Prepare object attributes for function call to NtCreateToken
		OBJECT_ATTRIBUTES objectAttributes = { };
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		objectAttributes.RootDirectory = NULL;
		objectAttributes.ObjectName = NULL;
		objectAttributes.Attributes = 0;
		objectAttributes.SecurityDescriptor = NULL;
		objectAttributes.SecurityQualityOfService = &securityQualityOfService;

		// Prepare token type for function call to NtCreateToken
		TOKEN_TYPE tokenType = TokenPrimary;

		// Prepare authentication id for function call to NtCreateToken
		LUID authenticationID = SYSTEM_LUID;

		// Prepare expiration time for function call to NtCreateToken
		LARGE_INTEGER expirationTime = { };
		expirationTime.QuadPart = 9223372036854775807;

		// Prepare token default dacl for function call to NtCreateToken
		TOKEN_DEFAULT_DACL tokenDefaultDacl = { };
		tokenDefaultDacl.DefaultDacl = NULL;

		// Prepare token source for function call to NtCreateToken
		TOKEN_SOURCE tokenSource = { };
		tokenSource.SourceIdentifier = SYSTEM_LUID;
		memcpy(tokenSource.SourceName, "MYSTERY", 8);

		// Prepare token privileges for function call to NtCreateToken
		constexpr DWORD tokenPrivilegesPrivilegeCount = 35;
		PTOKEN_PRIVILEGES tokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(LocalAlloc(LPTR, sizeof(PTOKEN_PRIVILEGES) + ((tokenPrivilegesPrivilegeCount - 1) * sizeof(LUID_AND_ATTRIBUTES))));
		tokenPrivileges->PrivilegeCount = 35;
		for (int i = 0; i < tokenPrivilegesPrivilegeCount; i++)
		{
			tokenPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
		}
		if (!LookupPrivilegeValueW(NULL, SE_CREATE_TOKEN_NAME, &tokenPrivileges->Privileges[0].Luid))
		{
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &tokenPrivileges->Privileges[1].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_LOCK_MEMORY_NAME, &tokenPrivileges->Privileges[2].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_INCREASE_QUOTA_NAME, &tokenPrivileges->Privileges[3].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_MACHINE_ACCOUNT_NAME, &tokenPrivileges->Privileges[4].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_TCB_NAME, &tokenPrivileges->Privileges[5].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_SECURITY_NAME, &tokenPrivileges->Privileges[6].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_TAKE_OWNERSHIP_NAME, &tokenPrivileges->Privileges[7].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &tokenPrivileges->Privileges[8].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_SYSTEM_PROFILE_NAME, &tokenPrivileges->Privileges[9].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_SYSTEMTIME_NAME, &tokenPrivileges->Privileges[10].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_PROF_SINGLE_PROCESS_NAME, &tokenPrivileges->Privileges[11].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_INC_BASE_PRIORITY_NAME, &tokenPrivileges->Privileges[12].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_CREATE_PAGEFILE_NAME, &tokenPrivileges->Privileges[13].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_CREATE_PERMANENT_NAME, &tokenPrivileges->Privileges[14].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_BACKUP_NAME, &tokenPrivileges->Privileges[15].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &tokenPrivileges->Privileges[16].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &tokenPrivileges->Privileges[17].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tokenPrivileges->Privileges[18].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_AUDIT_NAME, &tokenPrivileges->Privileges[19].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &tokenPrivileges->Privileges[20].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_CHANGE_NOTIFY_NAME, &tokenPrivileges->Privileges[21].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_REMOTE_SHUTDOWN_NAME, &tokenPrivileges->Privileges[22].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_UNDOCK_NAME, &tokenPrivileges->Privileges[23].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_SYNC_AGENT_NAME, &tokenPrivileges->Privileges[24].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_ENABLE_DELEGATION_NAME, &tokenPrivileges->Privileges[25].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_MANAGE_VOLUME_NAME, &tokenPrivileges->Privileges[26].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_IMPERSONATE_NAME, &tokenPrivileges->Privileges[27].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_CREATE_GLOBAL_NAME, &tokenPrivileges->Privileges[28].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_TRUSTED_CREDMAN_ACCESS_NAME, &tokenPrivileges->Privileges[29].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_RELABEL_NAME, &tokenPrivileges->Privileges[30].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_INC_WORKING_SET_NAME, &tokenPrivileges->Privileges[31].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_TIME_ZONE_NAME, &tokenPrivileges->Privileges[32].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_CREATE_SYMBOLIC_LINK_NAME, &tokenPrivileges->Privileges[33].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}
		if (!LookupPrivilegeValueW(NULL, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, &tokenPrivileges->Privileges[34].Luid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to lookup privilege." << std::endl;
			return FALSE;
		}

		// Get sids for users, groups, and integrity levels needed later
		PSID systemUserSid = NULL;
		if (!ConvertStringSidToSidW(L"S-1-5-18", &systemUserSid)) {
			LocalFree(tokenPrivileges);
			std::wcerr << L"ERROR: Failed to convert string to SID." << std::endl;
			return FALSE;
		}
		PSID administratorsGroupSid = NULL;
		if (!ConvertStringSidToSidW(L"S-1-5-32-544", &administratorsGroupSid)) {
			LocalFree(tokenPrivileges);
			LocalFree(systemUserSid);
			std::wcerr << L"ERROR: Failed to convert string to SID." << std::endl;
			return FALSE;
		}
		PSID authenticatedUsersGroupSid = NULL;
		if (!ConvertStringSidToSidW(L"S-1-5-11", &authenticatedUsersGroupSid)) {
			LocalFree(tokenPrivileges);
			LocalFree(systemUserSid);
			LocalFree(administratorsGroupSid);
			std::wcerr << L"ERROR: Failed to convert string to SID." << std::endl;
			return FALSE;
		}
		PSID everyoneGroupSid = NULL;
		if (!ConvertStringSidToSidW(L"S-1-1-0", &everyoneGroupSid)) {
			LocalFree(tokenPrivileges);
			LocalFree(systemUserSid);
			LocalFree(administratorsGroupSid);
			LocalFree(authenticatedUsersGroupSid);
			std::wcerr << L"ERROR: Failed to convert string to SID." << std::endl;
			return FALSE;
		}
		PSID systemIntegrityLevelSid = NULL;
		if (!ConvertStringSidToSidW(L"S-1-16-16384", &systemIntegrityLevelSid)) {
			LocalFree(tokenPrivileges);
			LocalFree(systemUserSid);
			LocalFree(administratorsGroupSid);
			LocalFree(authenticatedUsersGroupSid);
			LocalFree(everyoneGroupSid);
			std::wcerr << L"ERROR: Failed to convert string to SID." << std::endl;
			return FALSE;
		}
		PSID trustedInstallerUserSid = NULL;
		if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &trustedInstallerUserSid)) {
			LocalFree(tokenPrivileges);
			LocalFree(systemUserSid);
			LocalFree(administratorsGroupSid);
			LocalFree(authenticatedUsersGroupSid);
			LocalFree(everyoneGroupSid);
			LocalFree(systemIntegrityLevelSid);
			std::wcerr << L"ERROR: Failed to convert string to SID." << std::endl;
			return FALSE;
		}

		// Prepare token user for call to NtCreateToken
		TOKEN_USER tokenUser = { };
		tokenUser.User.Sid = systemUserSid;
		tokenUser.User.Attributes = 0;

		// Prepare token groups for call to NtCreateToken
		constexpr DWORD tokenGroupsGroupCount = 5;
		PTOKEN_GROUPS tokenGroups = reinterpret_cast<PTOKEN_GROUPS>(LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + ((tokenGroupsGroupCount - 1) * sizeof(SID_AND_ATTRIBUTES))));
		tokenGroups->GroupCount = tokenGroupsGroupCount;
		tokenGroups->Groups[0].Sid = administratorsGroupSid;
		tokenGroups->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER;
		tokenGroups->Groups[1].Sid = authenticatedUsersGroupSid;
		tokenGroups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		tokenGroups->Groups[2].Sid = everyoneGroupSid;
		tokenGroups->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		tokenGroups->Groups[3].Sid = systemIntegrityLevelSid;
		tokenGroups->Groups[3].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED | SE_GROUP_MANDATORY;
		tokenGroups->Groups[4].Sid = trustedInstallerUserSid;
		tokenGroups->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

		// Prepare token owner for call to NtCreateToken
		TOKEN_OWNER tokenOwner = { };
		tokenOwner.Owner = administratorsGroupSid;

		// Prepare token primary group for call to NtCreateToken
		TOKEN_PRIMARY_GROUP tokenPrimaryGroup = { };
		tokenPrimaryGroup.PrimaryGroup = administratorsGroupSid;

		// Call NTCreateToken
		if (FAILED(NtCreateToken(&godToken, desiredAccess, &objectAttributes, tokenType, &authenticationID, &expirationTime, &tokenUser, tokenGroups, tokenPrivileges, &tokenOwner, &tokenPrimaryGroup, &tokenDefaultDacl, &tokenSource))) {
			LocalFree(tokenPrivileges);
			LocalFree(systemUserSid);
			LocalFree(administratorsGroupSid);
			LocalFree(authenticatedUsersGroupSid);
			LocalFree(everyoneGroupSid);
			LocalFree(systemIntegrityLevelSid);
			LocalFree(trustedInstallerUserSid);
			LocalFree(tokenGroups);
			std::wcerr << L"ERROR: The call to NtCreateToken failed." << std::endl;
			return FALSE;
		}

		// Cleanup after call to NtCreateToken
		LocalFree(tokenPrivileges);
		LocalFree(systemUserSid);
		LocalFree(administratorsGroupSid);
		LocalFree(authenticatedUsersGroupSid);
		LocalFree(everyoneGroupSid);
		LocalFree(systemIntegrityLevelSid);
		LocalFree(trustedInstallerUserSid);
		LocalFree(tokenGroups);
	}

	// Set the God token to the current active session id
	{
		DWORD activeConsoleSessionId = WTSGetActiveConsoleSessionId();
		if (activeConsoleSessionId == 0xFFFFFFFF) {
			CloseHandle(godToken);
			std::wcerr << L"ERROR: Failed to get active console session id." << std::endl;
			return FALSE;
		}
		if (!SetTokenInformation(godToken, TokenSessionId, &activeConsoleSessionId, sizeof(DWORD))) {
			std::wcerr << L"ERROR: Failed to set console session id." << std::endl;
			return FALSE;
		}
	}

	// Give the God token UI access
	{
		BOOL uiAccess = TRUE;
		if (!SetTokenInformation(godToken, TokenUIAccess, &uiAccess, sizeof(BOOL))) {
			CloseHandle(godToken);
			std::wcerr << L"ERROR: Failed to set ui access." << std::endl;
			return FALSE;
		}
	}

	// Stop impersonating lsass.exe
	{
		if (!SetThreadToken(NULL, NULL)) {
			std::wcerr << L"ERROR: Failed to revert to normal token." << std::endl;
			return FALSE;
		}
		if (!RevertToSelf()) {
			std::wcerr << L"ERROR: Failed to revert to normal token." << std::endl;
			return FALSE;
		}
	}

	{
		// Get command line
		std::wostringstream commandLineStream = { };
		for (int i = 0; i < argc; i++) {
			if (i >= 1) {
				commandLineStream << " ";
			}
			commandLineStream << "\"" << argv[i] << "\"";
		}
		std::wstring commandLineString = commandLineStream.str();
		LPWSTR commandLine = new WCHAR[commandLineString.size() + 1];
		memcpy(commandLine, commandLineString.c_str(), commandLineString.size() * sizeof(WCHAR));
		commandLine[commandLineString.size()] = '\0';

		STARTUPINFOW si = { };
		si.cb = sizeof(STARTUPINFOW);
		GetStartupInfoW(&si);

		// Call CreateProcessWithTokenW to create the new process with the God token
		PROCESS_INFORMATION pi = { };
		if (!CreateProcessWithTokenW(godToken, LOGON_WITH_PROFILE, NULL, commandLine, 0, NULL, NULL, &si, &pi)) {
			delete[] commandLine;
			std::wcerr << L"ERROR: The call to CreateProcessWithTokenW failed." << std::endl;
			return FALSE;
		}

		// Cleanup after call to CreateProcessWithTokenW
		delete[] commandLine;
		if (!CloseHandle(pi.hThread)) {
			CloseHandle(pi.hProcess);
			std::wcerr << L"ERROR: Failed to close handle to thread of child process." << std::endl;
			return FALSE;
		}
		if (!CloseHandle(pi.hProcess)) {
			std::wcerr << L"ERROR: Failed to close handle to child process." << std::endl;
			return FALSE;
		}
	}

	// Exit the current process now that a higher privilege child has been started
	ExitProcess(0);
}

int main(int argc, char** argv) {
	if (!Transcend(argc, argv)) {
		ExitProcess(1);
	}

	// Get command line minus the process name
	std::wostringstream commandLineStream = { };
	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			if (i >= 2) {
				commandLineStream << " ";
			}
			commandLineStream << "\"" << argv[i] << "\"";
		}
	}
	else {
		commandLineStream << "\"C:\\Windows\\System32\\cmd.exe\"";
	}
	std::wstring commandLineString = commandLineStream.str();
	LPWSTR commandLine = new WCHAR[commandLineString.size() + 1];
	memcpy(commandLine, commandLineString.c_str(), commandLineString.size() * sizeof(WCHAR));
	commandLine[commandLineString.size()] = '\0';



	STARTUPINFOW si = { };
	si.cb = sizeof(STARTUPINFOW);
	GetStartupInfoW(&si);

	// Call CreateProcessW
	PROCESS_INFORMATION pi = { };
	if (!CreateProcessW(NULL, commandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		delete[] commandLine;
		DWORD lastError = GetLastError();
		std::wcerr << L"ERROR: The call to CreateProcessWithTokenW failed." << std::endl;
		ExitProcess(1);
	}
	delete[] commandLine;

	// Cleanup after call to CreateProcessW
	if (!CloseHandle(pi.hThread)) {
		CloseHandle(pi.hProcess);
		std::wcerr << L"ERROR: Failed to close handle to thread of child process." << std::endl;
		ExitProcess(1);
	}
	if (!CloseHandle(pi.hProcess)) {
		std::wcerr << L"ERROR: Failed to close handle to child process." << std::endl;
		ExitProcess(1);
	}

	ExitProcess(0);
	return 0;
}