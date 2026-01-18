package windows

import (
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// KillWeChatProcesses 关闭所有微信进程
func KillWeChatProcesses() error {
	// 要关闭的微信进程列表
	processNames := []string{
		"Weixin.exe",
		"WeChat.exe",
		"WeChatAppEx.exe",
		"WeChatHelper.exe",
		"WeChatUpdate.exe",
	}

	log.Debug().Msg("正在关闭微信进程")

	// 对每个进程分别执行taskkill命令
	for _, processName := range processNames {
		// 为每个进程构建单独的命令参数
		commands := []string{
			"/F", "/IM", processName,
		}

		// 执行taskkill命令
		cmd := exec.Command("taskkill", commands...)
		output, err := cmd.CombinedOutput()

		// 输出调试信息
		log.Debug().Str("process", processName).Str("output", string(output)).Msg("关闭微信进程的命令输出")

		// 即使有错误也继续，因为可能进程已经不存在
		if err != nil {
			// 检查错误是否是因为进程不存在
			outputStr := string(output)
			if !strings.Contains(outputStr, "ERROR: The process") || !strings.Contains(outputStr, "not found") {
				log.Debug().Err(err).Str("process", processName).Str("output", outputStr).Msg("关闭微信进程时出现错误")
				// 不返回错误，因为可能只是部分进程无法关闭
			}
		}
	}

	log.Debug().Msg("微信进程已关闭")

	// 等待3秒，确保所有微信进程完全关闭
	time.Sleep(3 * time.Second)

	return nil
}
