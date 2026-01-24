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

	"github.com/vitamin5x/chatlog/internal/errors"
	"github.com/vitamin5x/chatlog/internal/wechat/decrypt"
	"github.com/vitamin5x/chatlog/internal/wechat/model"
	"github.com/vitamin5x/chatlog/pkg/util"
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
		log.Info().Str("envPath", dllDir).Msg("从环境变量CHATLOG_DLL_DIR获取到DLL路径")
	}

	var lastErr error
	var failedPaths []string
	log.Info().Msgf("正在尝试从%d个路径加载wx_key.dll", len(dllPaths))

	for _, path := range dllPaths {
		log.Info().Str("path", path).Msg("尝试加载wx_key.dll")

		// 检查文件是否存在
		if _, err := os.Stat(path); os.IsNotExist(err) {
			log.Debug().Str("path", path).Msg("wx_key.dll文件不存在")
			failedPaths = append(failedPaths, path+": 文件不存在")
			continue
		}

		handle, err := windows.LoadLibrary(path)
		if err == nil {
			e.dllHandle = handle
			log.Info().Str("path", path).Msg("成功加载wx_key.dll")
			break
		}
		log.Debug().Str("path", path).Err(err).Msg("无法加载wx_key.dll")
		failedPaths = append(failedPaths, path+": "+err.Error())
		lastErr = err
	}

	if e.dllHandle == 0 {
		log.Error().Err(lastErr).Msgf("无法从所有%d个路径加载wx_key.dll", len(dllPaths))
		log.Error().Msg("失败的路径列表：")
		for _, fp := range failedPaths {
			log.Error().Msgf("  - %s", fp)
		}
		log.Error().Msg("请确保wx_key.dll位于以下位置之一：")
		log.Error().Msg("  1. 可执行文件所在目录")
		log.Error().Msg("  2. 可执行文件所在目录的assets子目录")
		log.Error().Msg("  3. 用户主目录下的chatlog目录")
		log.Error().Msg("  4. 通过CHATLOG_DLL_DIR环境变量指定的目录")
		return errors.DllLoadFailed(fmt.Errorf("无法从所有%d个路径加载wx_key.dll: %w", len(dllPaths), lastErr))
	}

	// 获取DLL导出函数
	getProc := func(name string) uintptr {
		addr, err := windows.GetProcAddress(e.dllHandle, name)
		if err != nil {
			log.Debug().Str("func", name).Err(err).Msg("无法获取DLL导出函数")
		}
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

	missingFuncs := []string{}
	for name, addr := range requiredFuncs {
		if addr == 0 {
			missingFuncs = append(missingFuncs, name)
		}
	}

	if len(missingFuncs) > 0 {
		windows.FreeLibrary(e.dllHandle)
		e.dllHandle = 0
		log.Error().Strs("missingFuncs", missingFuncs).Msg("DLL缺少必要的导出函数")
		return errors.DllProcNotFound(strings.Join(missingFuncs, ", "), nil)
	}

	// 记录成功获取的函数
	log.Info().Msg("成功获取DLL导出函数：")
	log.Info().Msgf("  - InitializeHook: %v", e.initializeHookPtr != 0)
	log.Info().Msgf("  - PollKeyData: %v", e.pollKeyDataPtr != 0)
	log.Info().Msgf("  - GetStatusMessage: %v", e.getStatusMsgPtr != 0)
	log.Info().Msgf("  - CleanupHook: %v", e.cleanupHookPtr != 0)
	log.Info().Msgf("  - GetLastErrorMsg: %v", e.getLastErrMsgPtr != 0)

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

	// 根据参考，DLL返回的是UTF-8编码的指针
	p := (*[1 << 30]byte)(unsafe.Pointer(ret))
	n := 0
	for p[n] != 0 {
		n++
	}

	return string(p[:n])
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
	log.Info().Uint32("pid", proc.PID).Msg("开始初始化Hook")
	if !e.initializeHook(proc.PID) {
		errMsg := e.getLastErrorMsg()
		if !util.IsElevated() {
			errMsg += " (请尝试以管理员权限运行)"
		}
		return "", "", errors.DllInitFailed(fmt.Errorf("%s", errMsg))
	}
	defer e.cleanupHook()

	// 轮询获取密钥
	return e.pollKeys(ctx, proc, e.validator.GetDataDir())
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
		log.Error().Msg("DLL未加载或InitializeHook函数不存在")
		return false
	}

	log.Info().Uint32("pid", pid).Msg("调用InitializeHook")
	ret, _, _ := syscall.SyscallN(e.initializeHookPtr, uintptr(pid))
	if ret == 0 {
		// 获取详细的错误信息
		errMsg := e.getLastErrorMsg()
		log.Error().Str("errMsg", errMsg).Msg("Hook初始化失败")
		return false
	}

	// 获取Hook初始化后的状态信息
	statusMessages := e.getStatusMessages()
	for _, msg := range statusMessages {
		logLevel := log.Info()
		if msg.Level == 2 {
			logLevel = log.Error()
		} else if msg.Level == 1 {
			logLevel = log.Warn()
		}
		logLevel.Str("dll_msg", msg.Message).Int("level", msg.Level).Msg("Hook初始化状态信息")
	}

	log.Info().Msg("Hook初始化成功")
	return true
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

// 窗口枚举回调函数类型
var enumWindowsProc uintptr

// _ChildWindowInfo 子窗口信息

type _ChildWindowInfo struct {
	hwnd      int
	title     string
	className string
}

// user32.dll 函数
var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procIsWindowVisible     = user32.NewProc("IsWindowVisible")
	procGetWindowTextLength = user32.NewProc("GetWindowTextLengthW")
	procGetWindowText       = user32.NewProc("GetWindowTextW")
	procGetClassName        = user32.NewProc("GetClassNameW")
)

// IsWindowVisible 检查窗口是否可见
func IsWindowVisible(hwnd windows.HWND) bool {
	ret, _, _ := syscall.SyscallN(procIsWindowVisible.Addr(), uintptr(hwnd))
	return ret != 0
}

// GetWindowTextLength 获取窗口文本长度
func GetWindowTextLength(hwnd windows.HWND) int {
	ret, _, _ := syscall.SyscallN(procGetWindowTextLength.Addr(), uintptr(hwnd))
	return int(ret)
}

// GetWindowText 获取窗口文本
func GetWindowText(hwnd windows.HWND, lpString []uint16, nMaxCount int) int {
	ret, _, _ := syscall.SyscallN(procGetWindowText.Addr(), uintptr(hwnd), uintptr(unsafe.Pointer(&lpString[0])), uintptr(nMaxCount))
	return int(ret)
}

// GetClassName 获取窗口类名
func GetClassName(hwnd windows.HWND, lpClassName []uint16, nMaxCount int) int {
	ret, _, _ := syscall.SyscallN(procGetClassName.Addr(), uintptr(hwnd), uintptr(unsafe.Pointer(&lpClassName[0])), uintptr(nMaxCount))
	return int(ret)
}

// findWechatWindowHandles 查找微信窗口句柄
func findWechatWindowHandles(pid uint32) []int {
	var handles []int

	// 定义窗口枚举回调函数
	enumWindowsProc = windows.NewCallback(func(hwnd windows.HWND, lParam uintptr) uintptr {
		var windowPid uint32
		windows.GetWindowThreadProcessId(hwnd, &windowPid)
		if windowPid == pid {
			// 检查窗口是否可见
			if !IsWindowVisible(hwnd) {
				return 1 // 继续枚举
			}

			// 获取窗口文本长度
			titleLen := GetWindowTextLength(hwnd)
			if titleLen == 0 {
				return 1 // 继续枚举
			}

			// 获取窗口文本
			titleBuffer := make([]uint16, titleLen+1)
			GetWindowText(hwnd, titleBuffer, titleLen+1)
			title := windows.UTF16ToString(titleBuffer)

			// 获取窗口类名
			classNameBuffer := make([]uint16, 256)
			classNameLen := GetClassName(hwnd, classNameBuffer, 256)
			className := ""
			if classNameLen > 0 {
				className = windows.UTF16ToString(classNameBuffer)
			}

			// 检查是否是微信窗口
			if strings.Contains(title, "微信") || strings.Contains(title, "Weixin") || strings.Contains(className, "WeChat") || strings.Contains(className, "Weixin") {
				handles = append(handles, int(hwnd))
			}
		}
		return 1 // 继续枚举
	})

	// 枚举所有顶层窗口
	windows.EnumWindows(enumWindowsProc, unsafe.Pointer(nil))

	return handles
}

// collectChildWindowInfos 收集子窗口信息
func collectChildWindowInfos(hwnd int) []_ChildWindowInfo {
	var children []_ChildWindowInfo

	// 定义子窗口枚举回调函数
	enumChildProc := windows.NewCallback(func(childHwnd windows.HWND, lParam uintptr) uintptr {
		// 获取窗口文本长度
		titleLen := GetWindowTextLength(childHwnd)
		title := ""
		if titleLen > 0 {
			titleBuffer := make([]uint16, titleLen+1)
			GetWindowText(childHwnd, titleBuffer, titleLen+1)
			title = windows.UTF16ToString(titleBuffer)
		}

		// 获取窗口类名
		classNameBuffer := make([]uint16, 256)
		classNameLen := GetClassName(childHwnd, classNameBuffer, 256)
		className := ""
		if classNameLen > 0 {
			className = windows.UTF16ToString(classNameBuffer)
		}

		children = append(children, _ChildWindowInfo{
			hwnd:      int(childHwnd),
			title:     title,
			className: className,
		})

		return 1 // 继续枚举
	})

	// 枚举子窗口
	windows.EnumChildWindows(windows.HWND(hwnd), enumChildProc, unsafe.Pointer(nil))

	return children
}

// checkWindowReadiness 检查窗口是否就绪
func checkWindowReadiness(children []_ChildWindowInfo) bool {
	// 检查是否有足够的子窗口
	if len(children) < 2 {
		return false
	}

	// 关键组件文本 - 与Flutter版本检测逻辑保持一致
	readyComponentTexts := []string{"微信", "Weixin", "WeChat"}
	// 关键组件类名标记
	readyComponentClassMarkers := []string{"WeChat", "Weixin", "TXGuiFoundation"}

	// 统计找到的关键组件
	foundComponents := 0

	for _, child := range children {
		// 检查标题
		if child.title != "" {
			for _, marker := range readyComponentTexts {
				if strings.Contains(child.title, marker) {
					foundComponents++
					if foundComponents >= 1 {
						return true
					}
					break
				}
			}
		}

		// 检查类名
		if child.className != "" {
			for _, marker := range readyComponentClassMarkers {
				if strings.Contains(child.className, marker) {
					foundComponents++
					if foundComponents >= 1 {
						return true
					}
					break
				}
			}
		}
	}

	// 备用检查：如果有足够多的子窗口，也认为窗口已就绪
	if len(children) >= 5 {
		return true
	}

	// 最终检查：如果找到至少一个关键组件，且子窗口数量足够
	if foundComponents >= 1 && len(children) >= 2 {
		return true
	}

	return false
}

// waitForWeChatWindowComponents 等待微信窗口组件加载完成
func waitForWeChatWindowComponents(pid uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	attemptCount := 0
	lastFoundHandles := 0
	lastChildCount := 0
	maxAttempts := 100 // 设置最大尝试次数，避免无限循环

	for time.Now().Before(deadline) && attemptCount < maxAttempts {
		attemptCount++
		log.Info().Uint32("pid", pid).Int("attempt", attemptCount).Msg("检测微信窗口组件")

		// 查找微信窗口句柄
		handles := findWechatWindowHandles(pid)
		if len(handles) == 0 {
			log.Warn().Msg("未找到微信窗口句柄")
			time.Sleep(300 * time.Millisecond) // 缩短等待时间，提高检测频率
			continue
		}

		if len(handles) != lastFoundHandles {
			log.Info().Int("handles", len(handles)).Msg("找到微信窗口句柄")
			lastFoundHandles = len(handles)
		}

		for _, handle := range handles {
			// 收集子窗口信息
			children := collectChildWindowInfos(handle)

			if len(children) != lastChildCount {
				log.Debug().Int("handle", handle).Int("childCount", len(children)).Msg("收集到子窗口信息")
				lastChildCount = len(children)
			}

			// 检查是否有就绪组件
			if checkWindowReadiness(children) {
				log.Info().Int("handle", handle).Int("childCount", len(children)).Msg("微信界面组件已加载完毕")
				return nil
			}
		}

		time.Sleep(300 * time.Millisecond) // 缩短等待时间，提高检测频率
	}

	log.Warn().Msg("等待微信界面组件超时，但窗口可能已就绪，将继续执行Hook安装")
	return nil
}

// pollKeys 轮询获取密钥
func (e *WxKeyDllExtractor) pollKeys(ctx context.Context, proc *model.Process, validatorDataDir string) (string, string, error) {
	var dataKey string
	keyBuf := make([]byte, 129) // 增加缓冲区大小到128位 + 结束符，与参考文档保持一致
	pollInterval := 100 * time.Millisecond
	timeout := time.After(10 * time.Second) // 减少超时时间到10秒
	lastHeartbeat := time.Now()
	lastStatusCheck := time.Now()

	log.Info().Msg(strings.Repeat("=", 60))
	log.Info().Msg("🔑 Hook已成功安装到微信进程！")
	log.Info().Msg("💡 请在微信中执行以下操作之一来触发密钥捕获：")
	log.Info().Msg("   1. 打开任意聊天对话框（最常用的方法）")
	log.Info().Msg("   2. 发送或接收一条新消息")
	log.Info().Msg("   3. 查看朋友圈、公众号文章或小程序")
	log.Info().Msg("   4. 点击微信界面的任意功能按钮")
	log.Info().Msg("")
	log.Info().Msg("⏱️  正在等待密钥...（超时时间：10秒）")
	log.Info().Msg("   - 请确保微信窗口处于激活状态")
	log.Info().Msg("   - 如果超过10秒仍未获取到密钥，请重试")
	log.Info().Msg(strings.Repeat("=", 60))

	for {
		select {
		case <-ctx.Done():
			log.Warn().Msg("密钥获取任务被取消")
			return "", "", ctx.Err()
		case <-timeout:
			log.Error().Msg("密钥获取超时！(DLL POLL TIMEOUT)")
			log.Error().Msg("💡 此错误通常意味着 Hook 已经安装，但在 10 秒内没有捕捉到任何有效的解密动作。")
			log.Error().Msg("💡 如果你已经进行了聊天操作但仍然超时，请尝试在微信中切换账号或重新登录。")

			if !util.IsElevated() {
				log.Warn().Msg("⚠️ 检测到当前未以管理员权限运行，这可能是 Hook 监听失效的主要原因！")
			}

			// 在超时前最后获取一次状态信息
			lastMsgs := e.getStatusMessages()
			for _, m := range lastMsgs {
				logLevel := log.Info()
				if m.Level == 2 {
					logLevel = log.Error()
				}
				logLevel.Str("last_msg", m.Message).Int("level", m.Level).Msg("DLL 最后的内部状态报告")
			}
			return "", "", errors.ErrDllPollTimeout
		case <-time.After(pollInterval):
			// 轮询获取状态信息
			statusMessages := e.getStatusMessages()
			for _, msg := range statusMessages {
				logLevel := log.Info()
				if msg.Level == 2 {
					logLevel = log.Error()
				} else if msg.Level == 1 {
					logLevel = log.Warn()
				}
				logLevel.Str("dll_msg", msg.Message).Int("level", msg.Level).Msg("来自 wx_key.dll 的消息")

				// 根据状态信息提供更详细的用户操作指导
				if strings.Contains(msg.Message, "等待微信组件加载") {
					log.Info().Msg("💡 微信正在加载组件，请稍候...")
				} else if strings.Contains(msg.Message, "请执行聊天操作") {
					log.Info().Msg("💡 请在微信中执行聊天操作，例如打开聊天对话框或发送消息")
				} else if strings.Contains(msg.Message, "Hook 安装成功") {
					log.Info().Msg("✅ Hook 安装成功，正在等待密钥触发...")
				} else if strings.Contains(msg.Message, "Hook 安装失败") {
					log.Error().Msg("❌ Hook 安装失败，请重新尝试")
				}
			}

			// 每10秒打印一次心跳
			if time.Since(lastHeartbeat) > 10*time.Second {
				log.Info().Msg("⏱️  正在持续监听密钥触发操作...")
				log.Info().Msg("💡 如果你还没有在微信中执行操作，请立即执行以下操作之一：")
				log.Info().Msg("   1. 打开任意聊天对话框（最常用的方法）")
				log.Info().Msg("   2. 发送或接收一条新消息")
				log.Info().Msg("   3. 查看朋友圈、公众号文章或小程序")
				lastHeartbeat = time.Now()
			}

			// 每30秒获取一次更详细的状态信息
			if time.Since(lastStatusCheck) > 30*time.Second {
				log.Info().Msg("🔍 执行详细状态检查...")
				detailedMsgs := e.getStatusMessages()
				if len(detailedMsgs) == 0 {
					log.Info().Msg("📋 没有新的状态消息")
				} else {
					log.Info().Msg("📋 详细状态报告：")
					for _, m := range detailedMsgs {
						logLevel := log.Info()
						if m.Level == 2 {
							logLevel = log.Error()
						} else if m.Level == 1 {
							logLevel = log.Warn()
						}
						logLevel.Str("message", m.Message).Int("level", m.Level).Msg("状态信息")
					}
				}
				lastStatusCheck = time.Now()
			}

			// 轮询获取密钥
			ok := e.pollKeyData(keyBuf)
			if ok {
				log.Info().Msg("✨ wx_key.dll 报告已成功捕获到密钥数据！")
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
				log.Info().Str("key", keyHex).Msg("从wx_key.dll获取到密钥")

				// 验证密钥格式
				if len(keyHex) != 64 && len(keyHex) != 32 {
					log.Warn().Msgf("密钥长度不正确，期望32或64个字符，实际获取到%d个字符", len(keyHex))
					continue
				}

				// 验证密钥
				keyBytes, err := hex.DecodeString(keyHex)
				if err != nil {
					log.Error().Err(err).Msg("获取到的密钥不是有效的HEX字符串")
					continue
				}

				// 检查密钥类型
				if len(keyBytes) == 32 {
					// 尝试验证密钥
					isValid := e.validator.Validate(keyBytes)
					if isValid {
						log.Info().Msg("✓ 成功获取并验证数据库密钥！")

						// 如果之前是 unknown_wechat，且验证成功，说明此时 validatorDataDir 是正确的
						if proc.AccountName == "" || proc.AccountName == "unknown_wechat" || strings.Contains(proc.AccountName, "unknown_wechat") {
							// 从路径中提取可能的账号名
							accountName := filepath.Base(validatorDataDir)
							if accountName != "" && accountName != "unknown_wechat" && accountName != "xwechat_files" {
								proc.AccountName = accountName
								log.Info().Str("newName", proc.AccountName).Msg("验证成功，根据路径修正账号名")
							}
						}
					} else {
						log.Warn().Str("key", keyHex).Msg("⚠️ 获取到数据库密钥，但在当前数据目录下验证失败（可能是数据目录检测错误），将尝试直接只用该密钥")
					}

					dataKey = keyHex
					return dataKey, "", nil
				} else if len(keyBytes) == 16 {
					// 暂时忽略 DLL 返回的图片密钥，因为我们有了专门的提取器
					// 且 DLL 返回的图片密钥可能不完整 (只有16字节，没有XOR)
					log.Debug().Str("key", keyHex).Msg("检测到潜在的图片密钥(DLL)，但已忽略")
				} else {
					log.Debug().Msgf("密钥长度不支持，期望32字节，实际获取到%d字节", len(keyBytes))
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

	// 调用DLL函数获取密钥 - 与Flutter版本保持一致，传递缓冲区大小
	ret, _, err := syscall.SyscallN(
		e.pollKeyDataPtr,
		uintptr(unsafe.Pointer(&keyBuf[0])),
		uintptr(65), // 传递缓冲区大小，与Flutter版本一致
	)

	// 检查返回值
	if ret == 0 {
		// 这里不打日志，因为轮询过程中ret通常为0
		_ = err
		return false
	}

	return true
}
