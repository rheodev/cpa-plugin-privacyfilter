//go:build cgo && windows

package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

extern int PrivacyFilterPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);

static wchar_t* privacyfilter_shared_object_path() {
	HMODULE module = NULL;
	DWORD size = MAX_PATH;
	if (!GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)(void*)&PrivacyFilterPluginCall,
		&module
	)) {
		return NULL;
	}
	for (;;) {
		wchar_t* buffer = (wchar_t*)malloc(size * sizeof(wchar_t));
		if (buffer == NULL) {
			return NULL;
		}
		DWORD copied = GetModuleFileNameW(module, buffer, size);
		if (copied == 0) {
			free(buffer);
			return NULL;
		}
		if (copied < size - 1) {
			return buffer;
		}
		free(buffer);
		size *= 2;
		if (size > 32768) {
			return NULL;
		}
	}
}
*/
import "C"

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func sharedLibraryPath() string {
	sharedObjectPath := C.privacyfilter_shared_object_path()
	if sharedObjectPath == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(sharedObjectPath))
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(sharedObjectPath)))
}
