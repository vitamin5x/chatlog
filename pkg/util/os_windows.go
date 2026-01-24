package util

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Is64Bit(handle windows.Handle) (bool, error) {
	var is32Bit bool
	if err := windows.IsWow64Process(handle, &is32Bit); err != nil {
		return false, fmt.Errorf("检查进程位数失败: %w", err)
	}
	return !is32Bit, nil
}

// IsElevated 检查当前进程是否具有管理员权限
func IsElevated() bool {
	var tokenHandle windows.Token
	var elevation uint32

	// 获取当前进程的令牌
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tokenHandle); err != nil {
		return false
	}
	defer tokenHandle.Close()

	// 查询令牌的提升状态
	tokenInfo := make([]byte, 4)
	var returnLength uint32
	if err := windows.GetTokenInformation(tokenHandle, windows.TokenElevation, &tokenInfo[0], uint32(len(tokenInfo)), &returnLength); err != nil {
		return false
	}

	// 解析结果
	elevation = *(*uint32)(unsafe.Pointer(&tokenInfo[0]))
	return elevation != 0
}
