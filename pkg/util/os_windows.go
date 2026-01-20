package util

import (
	"fmt"
	"os"

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
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}
