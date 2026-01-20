//go:build windows

package chatlog

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"syscall"
	"unsafe"

	"github.com/rs/zerolog/log"
	syswindows "golang.org/x/sys/windows"

	iwechat "github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/internal/wechat/process/windows"
	"github.com/sjzar/chatlog/pkg/util"
)

var (
	user32                       = syswindows.NewLazySystemDLL("user32.dll")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW     = user32.NewProc("GetWindowTextLengthW")
)

// 自动重启微信获取密钥的超时时间
const autoWeChatTimeout = 60 * time.Second

// autoGetDataKeyOnWindows 自动重启微信获取密钥
func (m *CliManager) autoGetDataKeyOnWindows() error {
	// 自动查找微信安装路径
	wechatPath := windows.FindWeChatInstallPath()
	if wechatPath == "" {
		return fmt.Errorf("未找到微信安装路径，请先安装微信")
	}

	// 关闭所有微信进程，确保完全终止
	log.Info().Msg("正在关闭所有微信进程...")
	if err := windows.KillWeChatProcesses(); err != nil {
		log.Warn().Err(err).Msg("关闭微信进程时出现警告")
	}

	// 启动微信
	log.Info().Msg("正在启动新的微信实例...")
	if err := windows.StartWeChat(wechatPath); err != nil {
		return fmt.Errorf("启动微信失败: %w", err)
	}

	// 等待微信启动并检测到进程
	log.Info().Msg("等待微信启动...")
	startTime := time.Now()
	var wechatInstance *iwechat.Account
	var err error // Defined here

	for time.Since(startTime) < autoWeChatTimeout {
		// 刷新微信实例列表
		m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
		if len(m.ctx.WeChatInstances) >= 1 {
			wechatInstance = m.ctx.WeChatInstances[0]
			log.Info().Str("name", wechatInstance.Name).Uint32("pid", wechatInstance.PID).Msg("检测到微信进程")
			break
		}
		// 等待1秒后重试
		time.Sleep(1 * time.Second)
	}

	if wechatInstance == nil {
		return fmt.Errorf("等待微信启动超时，请手动启动微信后重试")
	}

	// 切换到检测到的微信实例
	if err := m.Switch(wechatInstance, ""); err != nil {
		return fmt.Errorf("切换到微信实例失败: %w", err)
	}

	// 等待微信界面就绪并初始化登录流程
	log.Info().Msg("等待微信界面就绪...")
	time.Sleep(5 * time.Second) // 增加等待时间，确保微信完全初始化

	// 向用户提供明确的指导
	log.Info().Msg("=== 请执行以下操作获取密钥 ===")
	log.Info().Msg("1. 确保微信登录界面已显示")
	log.Info().Msg("2. 使用手机微信扫码登录或账号密码登录")
	log.Info().Msg("3. 登录成功后，程序将自动捕获密钥")
	log.Info().Msg("4. 如果超时，请确保微信版本与wx_key.dll兼容")
	log.Info().Msg("============================")

	// 等待用户登录并获取密钥
	log.Info().Msg("等待用户登录微信账号...")
	loginStartTime := time.Now()
	var dataKey string

	for time.Since(loginStartTime) < autoWeChatTimeout {
		// 1. 检查当前账号信息是否完整
		if m.ctx.Current.Name == "" || m.ctx.Current.Name == "unknown_wechat" || m.ctx.Current.DataDir == "" {
			// 刷新实例列表
			m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
			// 更新当前实例
			found := false
			for _, ins := range m.ctx.WeChatInstances {
				if ins.PID == m.ctx.Current.PID {
					// 只有当检测到有效信息时才更新
					if ins.Name != "" && ins.Name != "unknown_wechat" && ins.DataDir != "" {
						m.ctx.Current = ins
						log.Info().Str("account", ins.Name).Str("dataDir", ins.DataDir).Msg("检测到有效的微信账号信息")
					}
					found = true
					break
				}
			}

			// 如果进程都找不到了（可能崩溃或手动关闭），退出
			if !found {
				log.Warn().Msg("微信进程已退出")
				break
			}

			// 如果信息仍然不完整，继续等待
			if m.ctx.Current.Name == "" || m.ctx.Current.Name == "unknown_wechat" || m.ctx.Current.DataDir == "" {
				if time.Since(loginStartTime)%5 == 0 { // 减少日志频率
					log.Info().Msg("正在等待账号登录及数据目录生成...")
				}
				time.Sleep(1 * time.Second)
				continue
			}
		}

		// 2. 信息完整，等待窗口就绪
		log.Info().Msg("账号信息完整，正在等待微信窗口就绪...")
		if err := waitForWeChatWindow(m.ctx.Current.PID, 30*time.Second); err != nil {
			log.Warn().Err(err).Msg("等待窗口就绪超时，但仍将尝试获取密钥")
		} else {
			log.Info().Msg("微信窗口已就绪")
		}

		// 3. 尝试获取密钥
		log.Info().Msg("开始捕获密钥...")
		dataKey, err = m.wechat.GetDataKey(m.ctx.Current)
		if err == nil && dataKey != "" {
			log.Info().Msg("密钥获取成功")
			break
		} else if err != nil {
			log.Warn().Err(err).Msg("获取密钥尝试失败")
		}

		// 等待2秒后重试
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("获取密钥失败: %w", err)
	}

	// 尝试修复 unknown_wechat 账号名
	// 使用 m.ctx.Current.DataDir 因为这是最新的，而 m.ctx.DataDir 可能还没更新
	currentDataDir := m.ctx.Current.DataDir
	if (m.ctx.Account == "" || m.ctx.Account == "unknown_wechat") && currentDataDir != "" {
		// 尝试从数据目录获取账号名
		// DataDir通常格式: .../Documents/xwechat_files/<wx_id>/Msg
		// 或者 .../Documents/xwechat_files/<wx_id>
		base := filepath.Base(currentDataDir)
		if base == "Msg" {
			base = filepath.Base(filepath.Dir(currentDataDir))
		}

		if base != "" && base != "." && base != "xwechat_files" {
			log.Info().Str("oldAccount", m.ctx.Account).Str("newAccount", base).Msg("从数据目录推断出账号名称")
			// 必须更新 m.ctx.Current.Name，否则 Refresh() 会再次覆盖为 "unknown_wechat"
			m.ctx.Current.Name = base
			m.ctx.Account = base
			// 同步更新 Context 中的 DataDir
			m.ctx.DataDir = currentDataDir

			// 既然我们现在有了正确的账号名，检查是否有历史记录并加载
			// 这能确保加载用户自定义的 WorkDir 和其他配置
			if history, ok := m.ctx.History[base]; ok {
				log.Info().Str("account", base).Msg("找到修复后账号的历史记录，加载配置")
				// 我们可以部分加载需要的字段，或者完整加载
				// 这里主要需要 WorkDir
				if history.WorkDir != "" {
					m.ctx.WorkDir = history.WorkDir
					log.Info().Str("workDir", m.ctx.WorkDir).Msg("已恢复历史工作目录")
				}
				// 也可以恢复其他可能已保存的字段
				if m.ctx.ImgKey == "" && history.ImgKey != "" {
					m.ctx.ImgKey = history.ImgKey
				}
				if m.ctx.ImageAESKey == "" && history.ImageAESKey != "" {
					m.ctx.ImageAESKey = history.ImageAESKey
				}
				if m.ctx.ImageXORKey == "" && history.ImageXORKey != "" {
					m.ctx.ImageXORKey = history.ImageXORKey
				}
			}
		}
	}

	// 确保WorkDir已设置，或修复包含 "unknown_wechat" 的错误路径
	if m.ctx.WorkDir == "" || strings.Contains(m.ctx.WorkDir, "unknown_wechat") {
		// 只有当账号名有效时才更新，避免再次设置为 unknown_wechat
		if m.ctx.Account != "" && m.ctx.Account != "unknown_wechat" && !strings.Contains(m.ctx.Account, "unknown_wechat") {
			newWorkDir := util.DefaultWorkDir(m.ctx.Account)
			// 如果新路径确实不同，则更新
			if newWorkDir != m.ctx.WorkDir {
				log.Info().Str("oldWorkDir", m.ctx.WorkDir).Str("newWorkDir", newWorkDir).Msg("修复工作目录路径")
				m.ctx.WorkDir = newWorkDir
			}
		} else if m.ctx.WorkDir == "" {
			// 如果账号名仍然无效且WorkDir为空，只能先设置默认值
			m.ctx.WorkDir = util.DefaultWorkDir(m.ctx.Account)
			log.Info().Str("workDir", m.ctx.WorkDir).Msg("设置默认工作目录")
		}
	}

	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}

func waitForWeChatWindow(pid uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		found := false
		cb := syscall.NewCallback(func(hwnd syscall.Handle, lParam uintptr) uintptr {
			var wndPid uint32
			procGetWindowThreadProcessId.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&wndPid)))

			if wndPid == pid {
				// 检查窗口是否可见
				ret, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
				if ret != 0 {
					// 检查标题
					len, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
					if len > 0 {
						buf := make([]uint16, len+1)
						procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len+1))
						title := syscall.UTF16ToString(buf)
						if title == "微信" || title == "WeChat" {
							found = true
							return 0 // Stop enumeration
						}
					}
				}
			}
			return 1 // Continue enumeration
		})

		procEnumWindows.Call(cb, 0)
		if found {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for window")
}
