package windows

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

// DllExport 定义DLL导出函数类型
type DllExport func() uintptr

// WxKeyDllExtractor 基于wx_key.dll的V4密钥提取器
type WxKeyDllExtractor struct {
	validator         *decrypt.Validator
	dllHandle         windows.Handle
	initializeHookPtr uintptr
	pollKeyDataPtr    uintptr
	getStatusMsgPtr   uintptr
	cleanupHookPtr    uintptr
	getLastErrMsgPtr  uintptr
}

// NewWxKeyDllExtractor 创建新的wx_key.dll密钥提取器
func NewWxKeyDllExtractor() *WxKeyDllExtractor {
	return &WxKeyDllExtractor{}
}

// SetValidate 设置验证器
func (e *WxKeyDllExtractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}

// SearchKey 在内存中搜索密钥（此方法在DLL实现中未使用）
func (e *WxKeyDllExtractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	return "", false
}

// loadDLL 加载wx_key.dll
func (e *WxKeyDllExtractor) loadDLL() error {
	// 尝试加载DLL的路径列表
	var dllPaths []string

	// 获取当前工作目录
	currentDir, err := os.Getwd()
	if err == nil {
		// 当前工作目录
		dllPaths = append(dllPaths, filepath.Join(currentDir, "wx_key.dll"))
		// 当前工作目录下的assets目录
		dllPaths = append(dllPaths, filepath.Join(currentDir, "assets", "wx_key.dll"))
	}

	// 可执行文件目录
	exeDir := filepath.Dir(os.Args[0])
	dllPaths = append(dllPaths, filepath.Join(exeDir, "wx_key.dll"))
	// lib目录
	dllPaths = append(dllPaths, filepath.Join(exeDir, "lib", "wx_key.dll"))
	// assets目录
	dllPaths = append(dllPaths, filepath.Join(exeDir, "assets", "wx_key.dll"))

	// 用户可能配置的常见路径
	userDir, _ := os.UserHomeDir()
	if userDir != "" {
		dllPaths = append(dllPaths, filepath.Join(userDir, "chatlog", "wx_key.dll"))
		dllPaths = append(dllPaths, filepath.Join(userDir, "chatlog", "assets", "wx_key.dll"))
	}

	// 系统环境变量指定的路径
	if dllDir := os.Getenv("CHATLOG_DLL_DIR"); dllDir != "" {
		dllPaths = append(dllPaths, filepath.Join(dllDir, "wx_key.dll"))
	}

	var lastErr error
	log.Debug().Msgf("正在尝试从%d个路径加载wx_key.dll", len(dllPaths))

	for _, path := range dllPaths {
		log.Debug().Str("path", path).Msg("尝试加载wx_key.dll")
		handle, err := windows.LoadLibrary(path)
		if err == nil {
			e.dllHandle = handle
			log.Info().Str("path", path).Msg("成功加载wx_key.dll")
			break
		}
		log.Debug().Str("path", path).Err(err).Msg("无法加载wx_key.dll")
		lastErr = err
	}

	if e.dllHandle == 0 {
		log.Error().Err(lastErr).Msgf("无法从所有%d个路径加载wx_key.dll", len(dllPaths))
		return errors.DllLoadFailed(fmt.Errorf("无法从所有%d个路径加载wx_key.dll: %w", len(dllPaths), lastErr))
	}

	// 获取DLL导出函数
	getProc := func(name string) uintptr {
		addr, _ := windows.GetProcAddress(e.dllHandle, name)
		return addr
	}

	e.initializeHookPtr = getProc("InitializeHook")
	e.pollKeyDataPtr = getProc("PollKeyData")
	e.getStatusMsgPtr = getProc("GetStatusMessage")
	e.cleanupHookPtr = getProc("CleanupHook")
	e.getLastErrMsgPtr = getProc("GetLastErrorMsg")

	// 检查必要的函数是否都存在
	requiredFuncs := map[string]uintptr{
		"InitializeHook": e.initializeHookPtr,
		"PollKeyData":    e.pollKeyDataPtr,
		"CleanupHook":    e.cleanupHookPtr,
	}

	for name, addr := range requiredFuncs {
		if addr == 0 {
			windows.FreeLibrary(e.dllHandle)
			e.dllHandle = 0
			return errors.DllProcNotFound(name, nil)
		}
	}

	return nil
}

// getLastErrorMsg 获取最后错误信息
func (e *WxKeyDllExtractor) getLastErrorMsg() string {
	if e.dllHandle == 0 || e.getLastErrMsgPtr == 0 {
		return "DLL未加载或函数不存在"
	}

	ret, _, _ := syscall.SyscallN(e.getLastErrMsgPtr)
	if ret == 0 {
		return "获取错误信息失败"
	}

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ret)))
}

// getStatusMessage 获取状态信息 - 单次调用
func (e *WxKeyDllExtractor) getSingleStatusMessage() (string, int) {
	if e.dllHandle == 0 || e.getStatusMsgPtr == 0 {
		return "", 0
	}

	msgBuf := make([]byte, 512)
	var level int32

	ret, _, _ := syscall.SyscallN(
		e.getStatusMsgPtr,
		uintptr(unsafe.Pointer(&msgBuf[0])),
		uintptr(len(msgBuf)),
		uintptr(unsafe.Pointer(&level)),
	)

	if ret == 0 {
		return "", 0
	}

	// 查找字符串结束符
	end := 0
	for i, b := range msgBuf {
		if b == 0 {
			end = i
			break
		}
	}

	return string(msgBuf[:end]), int(level)
}

// Extract 从进程中提取密钥
func (e *WxKeyDllExtractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	// 根据wx_key.dll文档，只要有PID就可以获取密钥，不需要检查进程状态
	// 移除对进程状态的检查

	// 加载DLL
	if err := e.loadDLL(); err != nil {
		return "", "", err
	}
	defer func() {
		// 清理资源
		if e.dllHandle != 0 {
			e.cleanup()
			windows.FreeLibrary(e.dllHandle)
			e.dllHandle = 0
		}
	}()

	// 初始化Hook
	if !e.initializeHook(proc.PID) {
		return "", "", errors.DllInitFailed(fmt.Errorf(e.getLastErrorMsg()))
	}
	defer e.cleanupHook()

	// 轮询获取密钥
	return e.pollKeys(ctx)
}

// getStatusMessage 获取所有状态信息 - 循环调用直到没有更多消息
func (e *WxKeyDllExtractor) getStatusMessages() []struct {
	Message string
	Level   int
} {
	var messages []struct {
		Message string
		Level   int
	}

	for {
		msg, level := e.getSingleStatusMessage()
		if msg == "" {
			break
		}
		messages = append(messages, struct {
			Message string
			Level   int
		}{Message: msg, Level: level})
	}

	return messages
}

// initializeHook 初始化Hook
func (e *WxKeyDllExtractor) initializeHook(pid uint32) bool {
	if e.dllHandle == 0 || e.initializeHookPtr == 0 {
		return false
	}

	ret, _, _ := syscall.SyscallN(e.initializeHookPtr, uintptr(pid))
	return ret != 0
}

// cleanupHook 清理Hook资源
func (e *WxKeyDllExtractor) cleanupHook() bool {
	if e.dllHandle == 0 || e.cleanupHookPtr == 0 {
		return false
	}

	ret, _, _ := syscall.SyscallN(e.cleanupHookPtr)
	return ret != 0
}

// cleanup 清理所有资源
func (e *WxKeyDllExtractor) cleanup() {
	e.cleanupHook()
}

// pollKeys 轮询获取密钥
func (e *WxKeyDllExtractor) pollKeys(ctx context.Context) (string, string, error) {
	var dataKey, imgKey string
	keyBuf := make([]byte, 65) // 64位HEX字符串 + 结束符
	pollInterval := 100 * time.Millisecond
	timeout := time.After(60 * time.Second) // 增加超时时间到60秒

	log.Info().Msg(strings.Repeat("=", 60))
	log.Info().Msg("🔑 Hook已成功安装到微信进程！")
	log.Info().Msg("💡 请在微信中执行以下操作之一来触发密钥捕获：")
	log.Info().Msg("   1. 打开任意聊天对话框（最常用的方法）")
	log.Info().Msg("   2. 发送或接收一条新消息")
	log.Info().Msg("   3. 查看朋友圈、公众号文章或小程序")
	log.Info().Msg("   4. 点击微信界面的任意功能按钮")
	log.Info().Msg("")
	log.Info().Msg("⏱️  正在等待密钥...（超时时间：60秒）")
	log.Info().Msg("   - 请确保微信窗口处于激活状态")
	log.Info().Msg("   - 如果超过60秒仍未获取到密钥，请重试")
	log.Info().Msg(strings.Repeat("=", 60))

	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-timeout:
			log.Error().Msg("密钥获取超时！")
			log.Error().Msg("请确保：")
			log.Error().Msg("1. 已以管理员身份运行程序")
			log.Error().Msg("2. 微信版本兼容（当前支持4.x版本）")
			log.Error().Msg("3. 在微信中执行了触发操作")
			log.Error().Msg("4. wx_key.dll与微信版本匹配")
			return "", "", errors.ErrDllPollTimeout
		case <-time.After(pollInterval):
			// 轮询获取状态信息
			statusMessages := e.getStatusMessages()
			for _, msg := range statusMessages {
				logLevel := log.Debug()
				switch msg.Level {
				case 1: // Success
					logLevel = log.Info()
				case 2: // Error
					logLevel = log.Error()
				}
				logLevel.Msg(msg.Message)
			}

			// 轮询获取密钥
			if e.pollKeyData(keyBuf) {
				// 查找字符串结束符
				endIndex := 0
				for i, b := range keyBuf {
					if b == 0 {
						endIndex = i
						break
					}
				}

				// 如果没有找到结束符，使用完整的64个字符
				if endIndex == 0 {
					endIndex = 64
				}

				// 提取有效的HEX字符串
				keyHex := string(keyBuf[:endIndex])
				log.Debug().Str("key", keyHex).Msg("从wx_key.dll获取到密钥")

				// 验证密钥格式
				if len(keyHex) != 64 && len(keyHex) != 32 {
					log.Debug().Msgf("密钥长度不正确，期望32或64个字符，实际获取到%d个字符", len(keyHex))
					continue
				}

				// 验证密钥
				keyBytes, err := hex.DecodeString(keyHex)
				if err != nil {
					log.Debug().Err(err).Msg("密钥格式错误")
					continue
				}

				// 检查密钥类型
				if len(keyBytes) == 32 {
					if e.validator.Validate(keyBytes) {
						dataKey = keyHex
						log.Info().Msg("✓ 成功获取数据库密钥！")
					} else {
						log.Debug().Msg("不是有效的数据库密钥")
					}
				} else if len(keyBytes) == 16 {
					if e.validator.ValidateImgKey(keyBytes) {
						imgKey = keyHex
						log.Info().Msg("✓ 成功获取图片密钥！")
					} else {
						log.Debug().Msg("不是有效的图片密钥")
					}
				} else {
					log.Debug().Msgf("密钥长度不支持，期望16或32字节，实际获取到%d字节", len(keyBytes))
				}

				// 如果获取到了至少一种密钥，返回结果
				// 不再等待两种密钥都获取到，避免超时
				if dataKey != "" || imgKey != "" {
					log.Info().Msgf("密钥获取完成！耗时: %v", time.Since(startTime))
					log.Info().Msgf("数据库密钥: %s", dataKey)
					log.Info().Msgf("图片密钥: %s", imgKey)
					return dataKey, imgKey, nil
				}
			}
		}
	}
}

// pollKeyData 轮询获取密钥
func (e *WxKeyDllExtractor) pollKeyData(keyBuf []byte) bool {
	if e.dllHandle == 0 || e.pollKeyDataPtr == 0 {
		return false
	}

	// 确保缓冲区大小合适
	if len(keyBuf) < 65 {
		log.Warn().Msg("密钥缓冲区太小，无法存储完整密钥")
		return false
	}

	// 调用DLL函数获取密钥
	ret, _, err := syscall.SyscallN(
		e.pollKeyDataPtr,
		uintptr(unsafe.Pointer(&keyBuf[0])),
		uintptr(len(keyBuf)),
	)

	// 检查返回值
	if ret == 0 {
		log.Debug().Err(err).Msg("从wx_key.dll获取密钥失败")
		return false
	}

	return true
}
