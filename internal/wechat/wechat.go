package wechat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/key"
	"github.com/sjzar/chatlog/internal/wechat/key/image"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

// Account 表示一个微信账号
type Account struct {
	Name        string
	Platform    string
	Version     int
	FullVersion string
	DataDir     string
	Key         string
	ImgKey      string
	ImageAESKey string
	ImageXORKey string
	ScanDir     string
	PID         uint32
	ExePath     string
	Status      string
}

// NewAccount 创建新的账号对象
func NewAccount(proc *model.Process) *Account {
	return &Account{
		Name:        proc.AccountName,
		Platform:    proc.Platform,
		Version:     proc.Version,
		FullVersion: proc.FullVersion,
		DataDir:     proc.DataDir,
		PID:         proc.PID,
		ExePath:     proc.ExePath,
		Status:      proc.Status,
	}
}

// RefreshStatus 刷新账号的进程状态
func (a *Account) RefreshStatus() error {
	// 查找所有微信进程
	Load()

	process, err := GetProcess(a.Name)
	if err != nil {
		a.Status = model.StatusOffline
		return nil
	}

	if process.AccountName == a.Name {
		// 更新进程信息
		a.PID = process.PID
		a.ExePath = process.ExePath
		a.Platform = process.Platform
		a.Version = process.Version
		a.FullVersion = process.FullVersion
		a.Status = process.Status
		// 只有当process.DataDir不为空时才更新，避免覆盖已有的正确数据目录
		if process.DataDir != "" {
			a.DataDir = process.DataDir
		}
	}

	return nil
}

// GetImageKey 获取账号的图片密钥
func (a *Account) GetImageKey(ctx context.Context) (string, string, error) {
	// 仅支持 Windows V4
	if a.Platform != "windows" || a.Version != 4 {
		return "", "", fmt.Errorf("only support windows v4")
	}

	extractor := image.NewExtractor()
	aesKey, xorKey, err := extractor.GetImageKey(a.DataDir, a.PID)
	if err != nil {
		return "", "", err
	}

	a.ImageAESKey = aesKey
	a.ImageXORKey = xorKey

	return aesKey, xorKey, nil
}

// GetKey 获取账号的密钥
func (a *Account) GetKey(ctx context.Context) (string, string, error) {
	// 如果已经有密钥，直接返回
	if a.Key != "" && (a.ImgKey != "" || a.Version == 3) {
		return a.Key, a.ImgKey, nil
	}

	// 检查当前账号信息是否完整
	accountName := a.Name
	dataDir := a.DataDir

	// 如果账号名不完整或使用了默认名称，尝试重新获取微信进程信息
	if accountName == "" || accountName == "unknown_wechat" || dataDir == "" {
		log.Debug().Msg("账号信息不完整，尝试重新获取微信进程信息")

		// 重新加载微信进程信息
		Load()

		// 尝试查找当前账号对应的微信进程
		foundAccount := false
		accounts := GetAccounts()
		for _, acc := range accounts {
			if acc.PID == a.PID {
				// 更新账号信息
				accountName = acc.Name
				dataDir = acc.DataDir
				foundAccount = true
				log.Debug().Str("accountName", accountName).Str("dataDir", dataDir).Msg("从微信进程中获取到完整的账号信息")
				break
			}
		}

		// 如果仍然无法获取完整的账号信息，提示用户登录微信后再尝试
		if !foundAccount || accountName == "" || accountName == "unknown_wechat" || dataDir == "" {
			return "", "", fmt.Errorf("无法获取完整的微信账号信息，请确保微信已登录并处于运行状态，然后重新尝试获取密钥")
		}

		// 更新当前账号的信息
		a.Name = accountName
		a.DataDir = dataDir
	}

	// 创建密钥提取器 - 使用新的接口，传入平台和版本信息
	extractor, err := key.NewExtractor(a.Platform, a.Version)
	if err != nil {
		return "", "", err
	}

	// 尝试获取进程信息
	var process *model.Process
	process, err = GetProcess(a.Name)
	if err != nil {
		// 如果找不到进程，重新加载微信进程信息
		Load()

		// 尝试使用PID查找进程
		accounts := GetAccounts()
		for _, acc := range accounts {
			if acc.PID == a.PID {
				process, _ = GetProcess(acc.Name)
				break
			}
		}

		// 如果仍然找不到进程，创建一个新的进程信息
		if process == nil {
			process = &model.Process{
				PID:         a.PID,
				ExePath:     a.ExePath,
				Platform:    a.Platform,
				Version:     a.Version,
				FullVersion: a.FullVersion,
				Status:      model.StatusOnline,
				AccountName: a.Name,
				DataDir:     a.DataDir,
			}
			log.Debug().Uint32("pid", a.PID).Msg("使用现有信息创建新的进程信息")
		}
	}

	// 使用Account的DataDir而不是process的DataDir，确保使用正确的完整路径
	validatorDataDir := a.DataDir
	if validatorDataDir == "" {
		validatorDataDir = process.DataDir
	}

	// 如果仍然没有数据目录，尝试构建默认的微信数据目录路径
	if validatorDataDir == "" && a.Platform == "windows" && a.Version == 4 {
		// 微信4.0版本的默认数据目录路径格式：C:\Users\用户名\xwechat_files\账号名
		if homeDir, err := os.UserHomeDir(); err == nil {
			xwechatFilesDir := a.ScanDir
			if xwechatFilesDir == "" {
				xwechatFilesDir = filepath.Join(homeDir, "xwechat_files")
			}

			// 尝试查找扫描目录中的真实微信账号名目录
			realAccountName := ""
			var dataDirs []string // 存储所有可能的数据目录

			if entries, err := os.ReadDir(xwechatFilesDir); err == nil {
				log.Debug().Str("xwechatFilesDir", xwechatFilesDir).Msg("打开xwechat_files目录成功，开始查找微信账号名目录")
				var bestMatchDir string
				var bestMatchScore int

				for _, entry := range entries {
					if entry.IsDir() {
						entryName := entry.Name()
						entryPath := filepath.Join(xwechatFilesDir, entryName)

						// 排除系统目录、临时目录和备份目录
						lowerName := strings.ToLower(entryName)
						if lowerName != "all_users" && lowerName != "temp" && lowerName != "unknown_wechat" && lowerName != "backup" {
							// 检查目录是否包含db_storage子目录
							dbStoragePath := filepath.Join(entryPath, "db_storage")
							if _, errStat := os.Stat(dbStoragePath); errStat == nil {
								// 计算匹配分数
								score := 0
								// 包含db_storage子目录，加分
								score += 10

								// 检查是否包含message子目录
								messagePath := filepath.Join(dbStoragePath, "message")
								if _, err := os.Stat(messagePath); err == nil {
									// 包含message子目录，加分
									score += 5
									// 检查是否包含message_0.db文件
									message0DBPath := filepath.Join(messagePath, "message_0.db")
									if _, err := os.Stat(message0DBPath); err == nil {
										// 包含message_0.db文件，加分
										score += 10
									}
								}

								// 检查是否包含session子目录
								sessionPath := filepath.Join(dbStoragePath, "session")
								if _, err := os.Stat(sessionPath); err == nil {
									// 包含session子目录，加分
									score += 5
								}

								// 如果是当前账号名，加分
								if entryName == a.Name && a.Name != "unknown_wechat" {
									score += 15
								}

								// 更新最佳匹配
								if score > bestMatchScore {
									bestMatchScore = score
									bestMatchDir = entryPath
									realAccountName = entryName
								}

								log.Debug().Str("entryName", entryName).Str("entryPath", entryPath).Int("score", score).Msg("找到包含db_storage子目录的目录，计算匹配分数")

								// 如果找到包含message_0.db的目录，直接使用
								if score >= 25 {
									log.Debug().Str("entryName", entryName).Str("entryPath", entryPath).Int("score", score).Msg("找到包含message_0.db的目录，直接使用")
									break
								}
							} else {
								// 如果不包含db_storage子目录，可能是其他微信账号目录，先记录下来
								dataDirs = append(dataDirs, entryPath)
								log.Debug().Str("entryName", entryName).Str("entryPath", entryPath).Msg("找到目录，但不包含db_storage子目录")
							}
						}
					}
				}

				// 如果找到最佳匹配目录，使用它
				if bestMatchDir != "" {
					dataDirs = append(dataDirs, bestMatchDir)
					log.Debug().Str("bestMatchDir", bestMatchDir).Int("bestMatchScore", bestMatchScore).Msg("找到最佳匹配的微信账号目录")
				}
			}

			// 如果没有找到包含db_storage的目录，使用第一个找到的目录
			if realAccountName == "" && len(dataDirs) > 0 {
				realAccountName = filepath.Base(dataDirs[0])
				log.Debug().Str("realAccountName", realAccountName).Msg("使用第一个找到的微信账号名目录")
			}

			// 使用找到的真实账号名或当前账号名
			accountName := a.Name
			if realAccountName != "" {
				accountName = realAccountName
			}

			// 构建数据目录
			if realAccountName != "" {
				// 如果找到了真实账号名，优先使用它
				validatorDataDir = filepath.Join(xwechatFilesDir, realAccountName)
				log.Debug().Str("realAccountName", realAccountName).Str("defaultDataDir", validatorDataDir).Msg("使用真实账号名构建微信数据目录")

				// 如果当前账号名是 unknown_wechat，更新为真实账号名
				if a.Name == "" || a.Name == "unknown_wechat" || strings.Contains(a.Name, "unknown_wechat") {
					a.Name = realAccountName
					log.Info().Str("newName", a.Name).Msg("探测到真实账号名，更新账号信息")
				}
			} else if accountName != "" && accountName != "unknown_wechat" {
				// 如果没有找到真实账号名，但当前账号名有效，使用当前账号名
				validatorDataDir = filepath.Join(xwechatFilesDir, accountName)
				log.Debug().Str("accountName", accountName).Str("defaultDataDir", validatorDataDir).Msg("使用当前账号名构建微信数据目录")
			} else if len(dataDirs) > 0 {
				// 如果以上都失败，使用第一个找到的数据目录
				validatorDataDir = dataDirs[0]
				log.Debug().Str("defaultDataDir", validatorDataDir).Msg("使用第一个找到的数据目录")
			}
		} else {
			log.Err(err).Msg("获取用户主目录失败")
		}
	}

	// 最后检查：如果数据目录中仍然包含"unknown_wechat"，尝试替换为真实的微信账号名
	if strings.Contains(validatorDataDir, "unknown_wechat") {
		log.Debug().Str("validatorDataDir", validatorDataDir).Msg("数据目录中包含unknown_wechat，尝试替换为真实的微信账号名")

		// 查找扫描目录中的真实微信账号名目录
		if homeDir, err := os.UserHomeDir(); err == nil {
			xwechatFilesDir := a.ScanDir
			if xwechatFilesDir == "" {
				xwechatFilesDir = filepath.Join(homeDir, "xwechat_files")
			}
			if entries, err := os.ReadDir(xwechatFilesDir); err == nil {
				// ... (same loop as before but with xwechatFilesDir)
				for _, entry := range entries {
					if entry.IsDir() {
						entryName := entry.Name()
						if strings.ToLower(entryName) != "all_users" && strings.ToLower(entryName) != "temp" && strings.ToLower(entryName) != "unknown_wechat" {
							// 替换数据目录中的unknown_wechat为真实的微信账号名
							validatorDataDir = strings.Replace(validatorDataDir, "unknown_wechat", entryName, 1)
							log.Debug().Str("realAccountName", entryName).Str("newDataDir", validatorDataDir).Msg("成功替换数据目录中的unknown_wechat为真实的微信账号名")
							break
						}
					}
				}
			}
		}
	}

	log.Debug().Str("account", a.Name).Str("dataDir", validatorDataDir).Msg("准备使用的数据目录")
	validator, err := decrypt.NewValidator(process.Platform, process.Version, validatorDataDir)
	if err != nil {
		return "", "", err
	}

	extractor.SetValidate(validator)

	// 提取密钥
	dataKey, imgKey, err := extractor.Extract(ctx, process)
	if err != nil {
		return "", "", err
	}

	if dataKey != "" {
		a.Key = dataKey
	}

	if imgKey != "" {
		a.ImgKey = imgKey
	}

	// 更新当前账号的数据目录为获取密钥时使用的目录
	if validatorDataDir != "" {
		// 保存旧的数据目录用于日志
		oldDataDir := a.DataDir

		// 无论当前DataDir的状态如何，都更新为获取密钥时使用的正确目录
		// 因为获取密钥时使用的目录已经过验证，包含了正确的微信账号名
		a.DataDir = validatorDataDir

		// 更新账号名称为目录中的实际账号名
		if a.Name == "" || a.Name == "unknown_wechat" || strings.Contains(a.Name, "unknown_wechat") {
			a.Name = filepath.Base(validatorDataDir)
			log.Debug().Str("oldAccountName", a.Name).Str("newAccountName", filepath.Base(validatorDataDir)).Msg("更新账号名称为目录中的实际账号名")
		}

		log.Debug().Str("oldDataDir", oldDataDir).Str("newDataDir", a.DataDir).Msg("更新账号数据目录为获取密钥时使用的目录")
	}

	return dataKey, imgKey, nil
}

// DecryptDatabase 解密数据库
func (a *Account) DecryptDatabase(ctx context.Context, dbPath, outputPath string) error {
	// 获取密钥
	hexKey, _, err := a.GetKey(ctx)
	if err != nil {
		return err
	}

	// 创建解密器 - 传入平台信息和版本
	decryptor, err := decrypt.NewDecryptor(a.Platform, a.Version)
	if err != nil {
		return err
	}

	// 创建输出文件
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	// 解密数据库
	return decryptor.Decrypt(ctx, dbPath, hexKey, output)
}
