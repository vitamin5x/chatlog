package ctx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/pkg/config"
	"github.com/sjzar/chatlog/pkg/util"
)

const (
	DefalutHTTPAddr = "127.0.0.1:5030"
)

// Context is a context for a chatlog.
// It is used to store information about the chatlog.
type Context struct {
	conf *conf.TUIConfig
	cm   *config.Manager
	mu   sync.RWMutex

	History map[string]conf.ProcessConfig

	// 微信账号相关状态
	Account     string
	Platform    string
	Version     int
	FullVersion string
	DataDir     string
	DataKey     string
	DataUsage   string
	ImgKey      string
	ImageAESKey string
	ImageXORKey string

	// 工作目录相关状态
	WorkDir   string
	WorkUsage string

	// HTTP服务相关状态
	HTTPEnabled bool
	HTTPAddr    string

	// 自动解密
	AutoDecrypt bool
	LastSession time.Time

	// 当前选中的微信实例
	Current *wechat.Account
	PID     int
	ExePath string
	Status  string

	// 所有可用的微信实例
	WeChatInstances []*wechat.Account
}

func New(configPath string) (*Context, error) {

	conf, tcm, err := conf.LoadTUIConfig(configPath)
	if err != nil {
		return nil, err
	}

	ctx := &Context{
		conf: conf,
		cm:   tcm,
	}

	ctx.loadConfig()

	return ctx, nil
}

func (c *Context) loadConfig() {
	c.History = c.conf.ParseHistory()
	c.SwitchHistory(c.conf.LastAccount)
	c.Refresh()
}

func (c *Context) SwitchHistory(account string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Current = nil
	c.PID = 0
	c.ExePath = ""
	c.Status = ""

	log.Debug().Str("account", account).Msg("尝试切换到历史账号")

	// 首先尝试使用账号名称匹配
	history, ok := c.History[account]
	if ok {
		log.Debug().Str("account", account).Msg("使用账号名称匹配到历史记录")
		c.loadHistory(history)
		return
	}

	// 如果没有匹配到，尝试使用数据目录匹配
	log.Debug().Str("account", account).Msg("未使用账号名称匹配到历史记录，尝试使用数据目录匹配")

	// 遍历所有微信实例，查找当前登录的微信实例
	for _, instance := range c.WeChatInstances {
		if instance.Name == account {
			log.Debug().Str("dataDir", instance.DataDir).Msg("找到当前登录的微信实例，使用其数据目录查找历史记录")
			// 使用数据目录查找历史记录
			for _, h := range c.History {
				if h.DataDir == instance.DataDir && h.DataDir != "" {
					log.Debug().Str("dataDir", instance.DataDir).Msg("使用数据目录匹配到历史记录")
					// 更新历史记录的账号名称为当前登录的账号名称
					h.Account = account
					c.loadHistory(h)
					// 更新配置
					c.UpdateConfig()
					return
				}
			}

			// 如果没有找到历史记录，但找到了微信实例，使用该实例的信息
			log.Debug().Str("dataDir", instance.DataDir).Msg("未找到历史记录，使用微信实例的信息")
			c.Account = instance.Name
			c.Platform = instance.Platform
			c.Version = instance.Version
			c.FullVersion = instance.FullVersion
			c.DataDir = instance.DataDir
			c.Refresh()
			return
		}
	}

	// 如果仍然没有匹配到，清除当前账号信息
	log.Debug().Str("account", account).Msg("未找到匹配的历史记录和微信实例，清除当前账号信息")
	c.clearAccountInfo()
}

// loadHistory 加载历史账号信息
func (c *Context) loadHistory(history conf.ProcessConfig) {
	c.Account = history.Account
	c.Platform = history.Platform
	c.Version = history.Version
	c.FullVersion = history.FullVersion
	c.DataKey = history.DataKey
	c.ImgKey = history.ImgKey
	c.ImageAESKey = history.ImageAESKey
	c.ImageXORKey = history.ImageXORKey
	c.DataDir = history.DataDir
	c.WorkDir = history.WorkDir
	c.HTTPEnabled = history.HTTPEnabled
	c.HTTPAddr = history.HTTPAddr
}

// clearAccountInfo 清除账号信息
func (c *Context) clearAccountInfo() {
	c.Account = ""
	c.Platform = ""
	c.Version = 0
	c.FullVersion = ""
	c.DataKey = ""
	c.ImgKey = ""
	c.ImageAESKey = ""
	c.ImageXORKey = ""
	c.DataDir = ""
	c.WorkDir = ""
	c.HTTPEnabled = false
	c.HTTPAddr = ""
}

func (c *Context) SwitchCurrent(info *wechat.Account) {
	// 先检查该账号是否在历史记录中有记录
	c.mu.Lock()
	defer c.mu.Unlock()

	// 直接设置当前账号信息
	c.Current = info

	// 加载历史记录（如果有）
	if history, ok := c.History[info.Name]; ok {
		log.Debug().Str("account", info.Name).Msg("找到账号的历史记录，使用历史配置")
		c.loadHistory(history)
		// 如果历史记录的数据目录不完整，使用当前账号的数据目录
		if history.DataDir == "" || history.DataDir == "unknown_wechat" || strings.Contains(history.DataDir, "unknown_wechat") {
			log.Debug().Str("oldDataDir", history.DataDir).Msg("历史记录数据目录不完整")
		}
	} else {
		log.Debug().Str("account", info.Name).Msg("未找到账号的历史记录")
		// 如果是新的有效账号（非unknown），且不在历史记录中，应该清除之前的账号信息
		if info.Name != "" && info.Name != "unknown_wechat" && !strings.Contains(info.Name, "unknown_wechat") {
			log.Info().Str("account", info.Name).Msg("切换到新的未知账号，清除旧的上下文信息")
			c.clearAccountInfo()
			c.Account = info.Name
		}
	}

	// 无论是否有历史记录，都使用当前微信实例的数据目录（如果存在且更完整）
	if info.DataDir != "" {
		// 只有当info.DataDir比当前DataDir更完整时才更新
		if c.DataDir == "" ||
			c.DataDir == "unknown_wechat" ||
			strings.Contains(c.DataDir, "unknown_wechat") ||
			filepath.Base(c.DataDir) == "xwechat_files" ||
			(strings.Contains(info.DataDir, "xwechat_files") && !strings.Contains(c.DataDir, "xwechat_files")) {
			c.DataDir = info.DataDir
			log.Debug().Str("newDataDir", c.DataDir).Msg("使用当前微信实例的更完整数据目录")
		}
	}

	// 更新当前账号名称为实际账号名
	if info.Name != "" &&
		info.Name != "unknown_wechat" &&
		!strings.Contains(info.Name, "unknown_wechat") {
		c.Account = info.Name
		log.Debug().Str("newAccount", info.Name).Msg("更新账号名称为实际账号名")
	}

	// 刷新上下文
	c.Refresh()
}
func (c *Context) Refresh() {
	if c.Current != nil {
		c.Account = c.Current.Name
		c.Platform = c.Current.Platform
		c.Version = c.Current.Version
		c.FullVersion = c.Current.FullVersion
		c.PID = int(c.Current.PID)
		c.ExePath = c.Current.ExePath
		c.Status = c.Current.Status
		if c.Current.Key != "" && c.Current.Key != c.DataKey {
			c.DataKey = c.Current.Key
		}
		if c.Current.ImgKey != "" && c.Current.ImgKey != c.ImgKey {
			c.ImgKey = c.Current.ImgKey
		}
		if c.Current.ImageAESKey != "" && c.Current.ImageAESKey != c.ImageAESKey {
			c.ImageAESKey = c.Current.ImageAESKey
		}
		if c.Current.ImageXORKey != "" && c.Current.ImageXORKey != c.ImageXORKey {
			c.ImageXORKey = c.Current.ImageXORKey
		}
		// 如果当前账号的数据目录更完整或包含真实的微信账号名，则更新用户设置的数据目录
		if c.Current.DataDir != "" {
			// 如果用户没有设置数据目录，或者当前账号的数据目录更完整
			if c.DataDir == "" ||
				c.DataDir == "unknown_wechat" ||
				strings.Contains(c.DataDir, "unknown_wechat") ||
				filepath.Base(c.DataDir) == "xwechat_files" ||
				(strings.Contains(c.Current.DataDir, "xwechat_files") && !strings.Contains(c.DataDir, "xwechat_files")) {
				// 更新用户设置的数据目录为当前账号的更完整目录
				oldDataDir := c.DataDir
				c.DataDir = c.Current.DataDir
				log.Debug().Str("oldDataDir", oldDataDir).Str("newDataDir", c.DataDir).Msg("从当前账号更新数据目录")
			}
		}
	}
	if c.DataUsage == "" && c.DataDir != "" {
		go func() {
			c.DataUsage = util.GetDirSize(c.DataDir)
		}()
	}
	if c.WorkUsage == "" && c.WorkDir != "" {
		go func() {
			c.WorkUsage = util.GetDirSize(c.WorkDir)
		}()
	}
}

func (c *Context) GetDataDir() string {
	if c.DataDir != "" {
		return c.DataDir
	}
	// 如果有当前账号，返回包含账号名的完整数据目录
	if c.Current != nil && c.Current.DataDir != "" {
		return c.Current.DataDir
	}
	// 如果没有设置数据目录，返回当前用户主目录下的xwechat_files目录
	if homeDir, err := os.UserHomeDir(); err == nil {
		// 如果有账号名，返回包含账号名的完整数据目录
		if c.Account != "" {
			return filepath.Join(homeDir, "xwechat_files", c.Account)
		}
		return filepath.Join(homeDir, "xwechat_files")
	}
	// 如果无法获取用户主目录，返回空字符串
	return ""
}

func (c *Context) GetWorkDir() string {
	return c.WorkDir
}

func (c *Context) GetPlatform() string {
	return c.Platform
}

func (c *Context) GetVersion() int {
	return c.Version
}

func (c *Context) GetDataKey() string {
	return c.DataKey
}

func (c *Context) GetHTTPAddr() string {
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefalutHTTPAddr
	}
	return c.HTTPAddr
}

func (c *Context) GetWebhook() *conf.Webhook {
	return c.conf.Webhook
}

func (c *Context) SetHTTPEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HTTPEnabled == enabled {
		return
	}
	c.HTTPEnabled = enabled
	c.UpdateConfig()
}

func (c *Context) SetHTTPAddr(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HTTPAddr == addr {
		return
	}
	c.HTTPAddr = addr
	c.UpdateConfig()
}

func (c *Context) SetWorkDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.WorkDir == dir {
		return
	}
	c.WorkDir = dir
	c.UpdateConfig()
	c.Refresh()
}

func (c *Context) SetDataDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.DataDir == dir {
		return
	}
	c.DataDir = dir
	c.UpdateConfig()
	c.Refresh()
}

func (c *Context) SetImgKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ImgKey == key {
		return
	}
	c.ImgKey = key
	c.UpdateConfig()
}

func (c *Context) SetImageAESKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ImageAESKey == key {
		return
	}
	c.ImageAESKey = key
	c.UpdateConfig()
}

func (c *Context) SetImageXORKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ImageXORKey == key {
		return
	}
	c.ImageXORKey = key
	c.UpdateConfig()
}

func (c *Context) SetAutoDecrypt(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.AutoDecrypt == enabled {
		return
	}
	c.AutoDecrypt = enabled
	c.UpdateConfig()
}

// 更新配置
func (c *Context) UpdateConfig() {

	pconf := conf.ProcessConfig{
		Type:        "wechat",
		Account:     c.Account,
		Platform:    c.Platform,
		Version:     c.Version,
		FullVersion: c.FullVersion,
		DataDir:     c.DataDir,
		DataKey:     c.DataKey,
		ImgKey:      c.ImgKey,
		ImageAESKey: c.ImageAESKey,
		ImageXORKey: c.ImageXORKey,
		WorkDir:     c.WorkDir,
		HTTPEnabled: c.HTTPEnabled,
		HTTPAddr:    c.HTTPAddr,
		LastTime:    time.Now().Unix(),
	}

	if c.conf.History == nil {
		c.conf.History = make([]conf.ProcessConfig, 0)
	}

	// 查找并更新历史记录
	isFind := false
	for i, v := range c.conf.History {
		// 优先使用账号名称匹配
		if v.Account == c.Account {
			isFind = true
			c.conf.History[i] = pconf
			break
		}
		// 如果账号名称不匹配，但数据目录相同，也认为是同一个账号
		if v.DataDir == c.DataDir && v.DataDir != "" {
			isFind = true
			// 更新账号名称为当前的账号名称
			pconf.Account = c.Account
			c.conf.History[i] = pconf
			break
		}
	}

	// 如果没有找到匹配的历史记录，添加新的记录
	if !isFind {
		c.conf.History = append(c.conf.History, pconf)
	}

	// 保存最后使用的账号
	if err := c.cm.SetConfig("last_account", c.Account); err != nil {
		log.Error().Err(err).Msg("set last_account failed")
		return
	}

	// 保存历史记录
	if err := c.cm.SetConfig("history", c.conf.History); err != nil {
		log.Error().Err(err).Msg("set history failed")
		return
	}

	// 在数据目录中保存配置文件
	if len(pconf.DataDir) != 0 {
		if b, err := json.Marshal(pconf); err == nil {
			if err := os.WriteFile(filepath.Join(pconf.DataDir, "chatlog.json"), b, 0644); err != nil {
				log.Error().Err(err).Msg("save chatlog.json failed")
			}
		}
	}
}
