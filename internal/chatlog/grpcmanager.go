package chatlog

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/ctx"
	"github.com/sjzar/chatlog/internal/chatlog/database"
	"github.com/sjzar/chatlog/internal/chatlog/http"
	"github.com/sjzar/chatlog/internal/chatlog/wechat"
	iwechat "github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/internal/wechat/process/windows"
	"github.com/sjzar/chatlog/pkg/config"
	"github.com/sjzar/chatlog/pkg/util"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

// GRPCManager 管理聊天日志应用
type GRPCManager struct {
	ctx *ctx.Context
	sc  *conf.ServerConfig
	scm *config.Manager

	// Services
	db     *database.Service
	http   *http.Service
	wechat *wechat.Service

	// Terminal UI
	app *App
}

var _ Manager = (*GRPCManager)(nil)

func (m *GRPCManager) Run(configPath string) error {

	var err error
	m.ctx, err = ctx.New(configPath)
	if err != nil {
		return err
	}

	m.wechat = wechat.NewService(m.ctx)

	m.db = database.NewService(m.ctx)

	m.http = http.NewService(m.ctx, m.db)

	m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
	if len(m.ctx.WeChatInstances) >= 1 {
		m.ctx.SwitchCurrent(m.ctx.WeChatInstances[0])
	}

	if m.ctx.HTTPEnabled {
		// 启动HTTP服务
		if err := m.StartService(); err != nil {
			m.StopService()
		}
	}
	// 启动终端UI
	m.app = NewApp(m.ctx, m)
	m.app.Run() // 阻塞
	return nil
}

func (m *GRPCManager) Switch(info *iwechat.Account, history string) error {
	if m.ctx.AutoDecrypt {
		if err := m.StopAutoDecrypt(); err != nil {
			return err
		}
	}
	if m.ctx.HTTPEnabled {
		if err := m.stopService(); err != nil {
			return err
		}
	}
	if info != nil {
		m.ctx.SwitchCurrent(info)
	} else {
		m.ctx.SwitchHistory(history)
	}

	if m.ctx.HTTPEnabled {
		// 启动HTTP服务
		if err := m.StartService(); err != nil {
			log.Info().Err(err).Msg("启动服务失败")
			m.StopService()
		}
	}
	return nil
}

func (m *GRPCManager) StartService() error {

	// 按依赖顺序启动服务
	if err := m.db.Start(); err != nil {
		return err
	}

	if err := m.http.Start(); err != nil {
		m.db.Stop()
		return err
	}

	// 如果是 4.0 版本，更新下 xorkey
	if m.ctx.Version == 4 {
		if m.ctx.ImageAESKey != "" {
			dat2img.SetAesKey(m.ctx.ImageAESKey)
		} else {
			// 兼容旧逻辑
			dat2img.SetAesKey(m.ctx.ImgKey)
		}

		if m.ctx.ImageXORKey != "" {
			dat2img.SetXorKey(m.ctx.ImageXORKey)
		} else {
			go dat2img.ScanAndSetXorKey(m.ctx.DataDir)
		}
	}

	// 更新状态
	m.ctx.SetHTTPEnabled(true)

	return nil
}

func (m *GRPCManager) StopService() error {
	if err := m.stopService(); err != nil {
		return err
	}

	// 更新状态
	m.ctx.SetHTTPEnabled(false)

	return nil
}

func (m *GRPCManager) stopService() error {
	// 按依赖的反序停止服务
	var errs []error

	if err := m.http.Stop(); err != nil {
		errs = append(errs, err)
	}

	if err := m.db.Stop(); err != nil {
		errs = append(errs, err)
	}

	// 如果有错误，返回第一个错误
	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

func (m *GRPCManager) SetHTTPAddr(text string) error {
	var addr string
	if util.IsNumeric(text) {
		addr = fmt.Sprintf("127.0.0.1:%s", text)
	} else if strings.HasPrefix(text, "http://") {
		addr = strings.TrimPrefix(text, "http://")
	} else if strings.HasPrefix(text, "https://") {
		addr = strings.TrimPrefix(text, "https://")
	} else {
		addr = text
	}
	m.ctx.SetHTTPAddr(addr)
	return nil
}

func (m *GRPCManager) GetImageKey() error {
	return fmt.Errorf("getting image key is not supported in gRPC mode")
}

func (m *GRPCManager) GetDataKey() error {
	// 添加详细的日志记录
	log.Debug().Bool("hasCurrent", m.ctx.Current != nil).Str("os", runtime.GOOS).Msg("GetDataKey 方法开始执行")

	// 检查是否为Windows平台
	isWindows := runtime.GOOS == "windows"
	log.Debug().Bool("isWindows", isWindows).Msg("检查操作系统")

	// 如果是Windows平台，无论是否有微信进程，都采用自动重启微信的方式获取密钥
	// 因为直接从已运行的微信进程中获取密钥容易失败（DLL POLL TIMEOUT错误）
	if isWindows {
		// 检查是否有微信安装路径
		wechatPath := windows.FindWeChatInstallPath()
		if wechatPath == "" {
			return fmt.Errorf("未找到微信安装路径，请先安装微信")
		}

		log.Info().Msg("Windows平台，尝试自动重启微信获取密钥...")

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
		const autoWeChatTimeout = 60 * time.Second

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

	// 如果不是Windows平台，且已经选择了账号
	if m.ctx.Current != nil {
		log.Debug().Str("account", m.ctx.Current.Name).Uint32("pid", m.ctx.Current.PID).Msg("非Windows平台，直接尝试获取密钥")
		if _, err := m.wechat.GetDataKey(m.ctx.Current); err != nil {
			return err
		}
		m.ctx.Refresh()
		m.ctx.UpdateConfig()
		return nil
	}

	// 如果不是Windows平台，且没有选择账号
	return fmt.Errorf("未选择任何账号，请先选择微信账号")
}

func (m *GRPCManager) DecryptDBFiles() error {
	if m.ctx.DataKey == "" {
		if m.ctx.Current == nil {
			return fmt.Errorf("未选择任何账号")
		}
		if err := m.GetDataKey(); err != nil {
			return err
		}
	}
	if m.ctx.WorkDir == "" {
		m.ctx.WorkDir = util.DefaultWorkDir(m.ctx.Account)
	}

	if err := m.wechat.DecryptDBFiles(); err != nil {
		return err
	}
	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}

func (m *GRPCManager) StartAutoDecrypt() error {
	if m.ctx.DataKey == "" || m.ctx.DataDir == "" {
		return fmt.Errorf("请先获取密钥")
	}
	if m.ctx.WorkDir == "" {
		return fmt.Errorf("请先执行解密数据")
	}

	if err := m.wechat.StartAutoDecrypt(); err != nil {
		return err
	}

	m.ctx.SetAutoDecrypt(true)
	return nil
}

func (m *GRPCManager) StopAutoDecrypt() error {
	if err := m.wechat.StopAutoDecrypt(); err != nil {
		return err
	}

	m.ctx.SetAutoDecrypt(false)
	return nil
}

func (m *GRPCManager) RefreshSession() error {
	if m.db.GetDB() == nil {
		if err := m.db.Start(); err != nil {
			return err
		}
	}
	resp, err := m.db.GetSessions("", 1, 0)
	if err != nil {
		return err
	}
	if len(resp.Items) == 0 {
		return nil
	}
	m.ctx.LastSession = resp.Items[0].NTime
	return nil
}

func (m *GRPCManager) CommandKey(configPath string, pid int, force bool, showXorKey bool) (string, error) {

	var err error
	m.ctx, err = ctx.New(configPath)
	if err != nil {
		return "", err
	}

	m.wechat = wechat.NewService(m.ctx)

	m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
	if len(m.ctx.WeChatInstances) == 0 {
		return "", fmt.Errorf("wechat process not found")
	}

	if len(m.ctx.WeChatInstances) == 1 {
		key, imgKey := m.ctx.DataKey, m.ctx.ImgKey
		if len(key) == 0 || len(imgKey) == 0 || force {
			key, imgKey, err = m.ctx.WeChatInstances[0].GetKey(context.Background())
			if err != nil {
				return "", err
			}
			m.ctx.Refresh()
			m.ctx.UpdateConfig()
		}

		result := fmt.Sprintf("Data Key: [%s]\nImage Key: [%s]", key, imgKey)
		if m.ctx.Version == 4 && showXorKey {
			if b, err := dat2img.ScanAndSetXorKey(m.ctx.DataDir); err == nil {
				result += fmt.Sprintf("\nXor Key: [0x%X]", b)
			}
		}

		return result, nil
	}
	if pid == 0 {
		str := "Select a process:\n"
		for _, ins := range m.ctx.WeChatInstances {
			str += fmt.Sprintf("PID: %d. %s[Version: %s Data Dir: %s ]\n", ins.PID, ins.Name, ins.FullVersion, ins.DataDir)
		}
		return str, nil
	}
	for _, ins := range m.ctx.WeChatInstances {
		if ins.PID == uint32(pid) {
			key, imgKey := ins.Key, ins.ImgKey
			if len(key) == 0 || len(imgKey) == 0 || force {
				key, imgKey, err = ins.GetKey(context.Background())
				if err != nil {
					return "", err
				}
				m.ctx.Refresh()
				m.ctx.UpdateConfig()
			}
			result := fmt.Sprintf("Data Key: [%s]\nImage Key: [%s]", key, imgKey)
			if m.ctx.Version == 4 && showXorKey {
				if b, err := dat2img.ScanAndSetXorKey(m.ctx.DataDir); err == nil {
					result += fmt.Sprintf("\nXor Key: [0x%X]", b)
				}
			}
			return result, nil
		}
	}
	return "", fmt.Errorf("wechat process not found")
}

func (m *GRPCManager) CommandDecrypt(configPath string, cmdConf map[string]any) error {

	var err error
	m.sc, m.scm, err = conf.LoadServiceConfig(configPath, cmdConf)
	if err != nil {
		return err
	}

	dataDir := m.sc.GetDataDir()
	if len(dataDir) == 0 {
		return fmt.Errorf("dataDir is required")
	}

	dataKey := m.sc.GetDataKey()
	if len(dataKey) == 0 {
		return fmt.Errorf("dataKey is required")
	}

	m.wechat = wechat.NewService(m.sc)

	if err := m.wechat.DecryptDBFiles(); err != nil {
		return err
	}

	return nil
}

func (m *GRPCManager) CommandHTTPServer(configPath string, cmdConf map[string]any) error {

	var err error
	m.sc, m.scm, err = conf.LoadServiceConfig(configPath, cmdConf)
	if err != nil {
		return err
	}

	dataDir := m.sc.GetDataDir()
	workDir := m.sc.GetWorkDir()
	if len(dataDir) == 0 && len(workDir) == 0 {
		return fmt.Errorf("dataDir or workDir is required")
	}

	dataKey := m.sc.GetDataKey()
	if len(dataKey) == 0 {
		return fmt.Errorf("dataKey is required")
	}

	// 如果是 4.0 版本，处理图片密钥
	version := m.sc.GetVersion()
	if version == 4 && len(dataDir) != 0 {
		if m.sc.GetImageAESKey() != "" {
			dat2img.SetAesKey(m.sc.GetImageAESKey())
		} else {
			dat2img.SetAesKey(m.sc.GetImgKey())
		}

		if m.sc.GetImageXORKey() != "" {
			dat2img.SetXorKey(m.sc.GetImageXORKey())
		} else {
			go dat2img.ScanAndSetXorKey(dataDir)
		}
	}

	log.Info().Msgf("server config: %+v", m.sc)

	m.wechat = wechat.NewService(m.sc)

	m.db = database.NewService(m.sc)

	m.http = http.NewService(m.sc, m.db)

	if m.sc.GetAutoDecrypt() {
		if err := m.wechat.StartAutoDecrypt(); err != nil {
			return err
		}
		log.Info().Msg("auto decrypt is enabled")
	}

	// init db
	go func() {
		// 如果工作目录为空，则解密数据
		if entries, err := os.ReadDir(workDir); err == nil && len(entries) == 0 {
			log.Info().Msgf("work dir is empty, decrypt data.")
			m.db.SetDecrypting()
			if err := m.wechat.DecryptDBFiles(); err != nil {
				log.Info().Msgf("decrypt data failed: %v", err)
				return
			}
			log.Info().Msg("decrypt data success")
		}

		// 按依赖顺序启动服务
		if err := m.db.Start(); err != nil {
			log.Info().Msgf("start db failed, try to decrypt data.")
			m.db.SetDecrypting()
			if err := m.wechat.DecryptDBFiles(); err != nil {
				log.Info().Msgf("decrypt data failed: %v", err)
				return
			}
			log.Info().Msg("decrypt data success")
			if err := m.db.Start(); err != nil {
				log.Info().Msgf("start db failed: %v", err)
				m.db.SetError(err.Error())
				return
			}
		}
	}()

	return m.http.ListenAndServe()
}

func (m *GRPCManager) GetWeChatInstances() []*iwechat.Account {
	return m.wechat.GetWeChatInstances()
}

func (m *GRPCManager) GetKey(configPath string, pid int, force bool, showXorKey bool) (*KeyData, error) {

	var err error
	m.ctx, err = ctx.New(configPath)
	if err != nil {
		return nil, err
	}

	m.wechat = wechat.NewService(m.ctx)

	m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
	if len(m.ctx.WeChatInstances) == 0 {
		return nil, fmt.Errorf("wechat process not found")
	}

	if len(m.ctx.WeChatInstances) == 1 {
		key, imgKey := m.ctx.DataKey, m.ctx.ImgKey
		if len(key) == 0 || len(imgKey) == 0 || force {
			key, imgKey, err = m.ctx.WeChatInstances[0].GetKey(context.Background())
			if err != nil {
				return nil, err
			}
			m.ctx.Refresh()
			m.ctx.UpdateConfig()
		}
		result := &KeyData{
			DataKey:  key,
			ImageKey: imgKey,
		}
		if m.ctx.Version == 4 && showXorKey {
			if b, err := dat2img.ScanAndSetXorKey(m.ctx.DataDir); err == nil {
				result.XorKey = fmt.Sprintf("0x%X", b)
			}

		}

		return result, nil
	}
	if pid == 0 {
		str := "Select a process:\n"
		for _, ins := range m.ctx.WeChatInstances {
			str += fmt.Sprintf("PID: %d. %s[Version: %s Data Dir: %s ]\n", ins.PID, ins.Name, ins.FullVersion, ins.DataDir)
		}
		return nil, nil
	}
	for _, ins := range m.ctx.WeChatInstances {
		if ins.PID == uint32(pid) {
			key, imgKey := ins.Key, ins.ImgKey
			if len(key) == 0 || len(imgKey) == 0 || force {
				key, imgKey, err = ins.GetKey(context.Background())
				if err != nil {
					return nil, err
				}
				m.ctx.Refresh()
				m.ctx.UpdateConfig()
			}
			result := &KeyData{
				DataKey:  key,
				ImageKey: imgKey,
			}
			if m.ctx.Version == 4 && showXorKey {
				if b, err := dat2img.ScanAndSetXorKey(m.ctx.DataDir); err == nil {
					result.XorKey = fmt.Sprintf("0x%X", b)
				}
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("wechat process not found")
}

func (m *GRPCManager) Decrypt(configPath string, cmdConf map[string]any) error {

	var err error
	m.sc, m.scm, err = conf.LoadServiceConfig(configPath, cmdConf)
	if err != nil {
		return err
	}

	dataDir := m.sc.GetDataDir()
	if len(dataDir) == 0 {
		return fmt.Errorf("dataDir is required")
	}

	dataKey := m.sc.GetDataKey()
	if len(dataKey) == 0 {
		return fmt.Errorf("dataKey is required")
	}

	m.wechat = wechat.NewService(m.sc)

	if err := m.wechat.DecryptDBFiles(); err != nil {
		return err
	}

	return nil
}
