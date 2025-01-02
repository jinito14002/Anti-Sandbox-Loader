#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <psapi.h>
#pragma comment(lib, "Shlwapi.lib")


BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata) {

	int				X = 0,
		Y = 0;
	MONITORINFO		MI = { .cbSize = sizeof(MONITORINFO) };

	if (!GetMonitorInfoW(hMonitor, &MI)) {
		// printf("\n\t[!] GetMonitorInfoW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// calculating the X coordinates of the desplay
	X = MI.rcMonitor.right - MI.rcMonitor.left;

	// calculating the Y coordinates of the desplay
	Y = MI.rcMonitor.top - MI.rcMonitor.bottom;

	// if numbers are in negative value, reverse them 
	if (X < 0)
		X = -X;
	if (Y < 0)
		Y = -Y;

	/*
	if not :
		-	1920x1080	-	1920x1200	-	1920x1600	-	1920x900
		-	2560x1080	-	2560x1200	-	2560x1600	-	1920x900
		-	1440x1080	-	1440x1200	-	1440x1600	-	1920x900
	*/

	if ((X != 1920 && X != 2560 && X != 1440) || (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
		*((BOOL*)ldata) = TRUE;

	return TRUE;
}

BOOL CheckMachineProcesses() {
	DWORD		adwProcesses[1024];
	DWORD		dwReturnLen = NULL,	dwNmbrOfPids = NULL;
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
		// printf("\n\t[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	dwNmbrOfPids = dwReturnLen / sizeof(DWORD);
	// If less than 50 process, it's possibly a sandbox	
	if (dwNmbrOfPids < 50) {
		return TRUE;
	}
	return FALSE;
}

BOOL ExeDigitsInNameCheck() {

	CHAR	Path[MAX_PATH * 3];
	CHAR	cName[MAX_PATH];
	DWORD   dwNumberOfDigits = NULL;

	// getting the current filename (with the full path)
	if (!GetModuleFileNameA(NULL, Path, MAX_PATH * 3)) {
		// printf("\n\t[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// to prevent a buffer overflow - getting the filename from the full path
	if (lstrlenA(PathFindFileNameA(Path)) < MAX_PATH)
		lstrcpyA(cName, PathFindFileNameA(Path));

	// counting number of digits
	for (int i = 0; i < lstrlenA(cName); i++) {
		if (isdigit(cName[i]))
			dwNumberOfDigits++;
	}

	// max 3 digits allowed 
	if (dwNumberOfDigits > 10) {
		return TRUE;
	}
	return FALSE;
}

