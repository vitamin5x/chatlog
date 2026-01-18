package windows

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/registry"
)

// FindWeChatInstallPath 查找微信的安装路径
func FindWeChatInstallPath() string {
	// 1. 从注册表中查找微信安装路径
	if path := findWeChatPathFromRegistry(); path != "" {
		log.Debug().Str("path", path).Msg("从注册表中找到微信安装路径")
		return path
	}

	// 2. 在常见路径中查找微信安装路径
	if path := findWeChatPathFromCommonLocations(); path != "" {
		log.Debug().Str("path", path).Msg("从常见路径中找到微信安装路径")
		return path
	}

	log.Debug().Msg("未找到微信安装路径")
	return ""
}

// findWeChatPathFromRegistry 从注册表中查找微信安装路径
func findWeChatPathFromRegistry() string {
	// 腾讯特定的注册表键
	tencentKeys := []string{
		"Software\\Tencent\\WeChat",
		"Software\\WOW6432Node\\Tencent\\WeChat",
		"Software\\Tencent\\Weixin",
	}

	// 尝试从HKEY_LOCAL_MACHINE和HKEY_CURRENT_USER查找
	roots := []registry.Key{
		registry.LOCAL_MACHINE,
		registry.CURRENT_USER,
	}

	for _, root := range roots {
		for _, keyPath := range tencentKeys {
			if path := readRegistryString(root, keyPath, "InstallPath"); path != "" {
				// 检查路径是否存在Weixin.exe或WeChat.exe
				if exists(filepath.Join(path, "Weixin.exe")) {
					return filepath.Join(path, "Weixin.exe")
				}
				if exists(filepath.Join(path, "WeChat.exe")) {
					return filepath.Join(path, "WeChat.exe")
				}
			}
		}
	}

	// 从卸载注册表中查找
	uninstallKeys := []string{
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}

	for _, root := range roots {
		for _, parentKey := range uninstallKeys {
			path := readRegistryString(root, parentKey+"\\WeChat", "InstallLocation")
			if path != "" {
				if exists(filepath.Join(path, "Weixin.exe")) {
					return filepath.Join(path, "Weixin.exe")
				}
				if exists(filepath.Join(path, "WeChat.exe")) {
					return filepath.Join(path, "WeChat.exe")
				}
			}
		}
	}

	return ""
}

// findWeChatPathFromCommonLocations 在常见路径中查找微信安装路径
func findWeChatPathFromCommonLocations() string {
	// 常见的安装路径
	commonPaths := []string{
		"Program Files\\Tencent\\WeChat\\WeChat.exe",
		"Program Files (x86)\\Tencent\\WeChat\\WeChat.exe",
		"Program Files\\Tencent\\Weixin\\Weixin.exe",
		"Program Files (x86)\\Tencent\\Weixin\\Weixin.exe",
	}

	// 常见的系统驱动器
	drives := []string{"C:", "D:", "E:", "F:"}

	for _, drive := range drives {
		for _, path := range commonPaths {
			fullPath := filepath.Join(drive, path)
			if exists(fullPath) {
				return fullPath
			}
		}
	}

	return ""
}

// readRegistryString 从注册表中读取字符串值
func readRegistryString(root registry.Key, path, value string) string {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()

	val, _, err := key.GetStringValue(value)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(val)
}

// exists 检查文件是否存在
func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
