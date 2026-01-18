//go:build windows

package chatlog

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	iwechat "github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/internal/wechat/process/windows"
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
	var err error

	for time.Since(loginStartTime) < autoWeChatTimeout {
		// 尝试获取密钥
		dataKey, err = m.wechat.GetDataKey(m.ctx.Current)
		if err == nil && dataKey != "" {
			log.Info().Msg("密钥获取成功")
			break
		}
		// 每2秒提示一次用户
		if time.Since(loginStartTime)%5 == 0 {
			log.Info().Msg("请继续登录微信账号，程序正在等待...")
		}
		// 等待2秒后重试
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("获取密钥失败: %w", err)
	}

	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}
