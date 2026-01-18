package windows

import (
	"os/exec"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/wechat/model"
)

// StartWeChat 启动微信
func StartWeChat(wechatPath string) error {
	if wechatPath == "" {
		log.Error().Msg("微信安装路径为空，无法启动微信")
		return nil
	}

	log.Debug().Str("path", wechatPath).Msg("正在启动微信")

	// 使用更简单的方式启动微信，不设置特殊的进程属性
	cmd := exec.Command(wechatPath)

	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Str("path", wechatPath).Msg("启动微信失败")
		return err
	}

	// 不要等待命令完成，因为微信是GUI应用程序
	go func() {
		cmd.Wait()
	}()

	// 等待微信窗口显示
	time.Sleep(1 * time.Second)

	log.Debug().Msg("微信已启动")
	return nil
}

// WaitForWeChatProcess 等待微信进程启动
func WaitForWeChatProcess(timeoutMs int) (*model.Process, error) {
	log.Debug().Int("timeout", timeoutMs).Msg("等待微信进程启动")

	startTime := time.Now()
	maxWaitTime := time.Duration(timeoutMs) * time.Millisecond

	// 使用现有的进程检测器查找微信进程
	detector := NewDetector()

	for time.Since(startTime) < maxWaitTime {
		processes, err := detector.FindProcesses()
		if err != nil {
			log.Err(err).Msg("查找微信进程失败")
			return nil, err
		}

		if len(processes) > 0 {
			log.Debug().Int("pid", int(processes[0].PID)).Msg("找到微信进程")
			return processes[0], nil
		}

		// 等待一段时间后再次检查
		time.Sleep(200 * time.Millisecond)
	}

	log.Debug().Msg("等待微信进程启动超时")
	return nil, nil
}
