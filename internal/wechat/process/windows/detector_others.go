//go:build !windows

package windows

import (
	"github.com/shirou/gopsutil/v4/process"
	"github.com/vitamin5x/chatlog/internal/wechat/model"
)

func initializeProcessInfo(p *process.Process, info *model.Process) error {
	return nil
}

