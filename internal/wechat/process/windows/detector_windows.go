package windows

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/sjzar/chatlog/internal/wechat/model"
)

// initializeProcessInfo 获取进程的数据目录和账户名
func initializeProcessInfo(p *process.Process, info *model.Process) error {
	log.Debug().Msgf("开始初始化进程 %d 的数据目录和账户名", p.Pid)
	files, err := p.OpenFiles()
	if err != nil {
		log.Err(err).Msgf("获取进程 %d 的打开文件失败", p.Pid)
		return err
	}
	log.Debug().Int("fileCount", len(files)).Msgf("获取到进程 %d 的 %d 个打开文件", p.Pid, len(files))

	dbPath := V3DBFile
	if info.Version == 4 {
		dbPath = V4DBFile
		log.Debug().Int("version", info.Version).Str("dbPath", dbPath).Msg("使用微信4.0版本的数据库文件路径")
	} else {
		log.Debug().Int("version", info.Version).Str("dbPath", dbPath).Msg("使用微信3.0版本的数据库文件路径")
	}

	// 遍历所有打开的文件，查找微信数据库文件
	for _, f := range files {
		log.Debug().Str("filePath", f.Path).Str("dbPath", dbPath).Msg("检查文件路径")

		// 尝试多种方式匹配数据库文件
		isMatch := strings.HasSuffix(f.Path, dbPath)
		if !isMatch && info.Version == 4 {
			// 对于微信4.0版本，尝试匹配其他可能的数据库文件路径
			isMatch = strings.Contains(f.Path, "db_storage") && strings.HasSuffix(f.Path, ".db")
			if isMatch {
				log.Debug().Str("filePath", f.Path).Msg("匹配到微信4.0版本的db_storage数据库文件")
			}
		}

		if isMatch {
			filePath := f.Path
			// 移除可能的前缀
			if strings.HasPrefix(filePath, "\\\\?\\") {
				filePath = filePath[4:]
			}
			log.Debug().Str("filePath", filePath).Int("version", info.Version).Msg("找到目标数据库文件")

			// 规范化路径分隔符
			filePath = filepath.ToSlash(filePath)
			parts := strings.Split(filePath, "/")
			log.Debug().Int("partsLen", len(parts)).Msgf("路径分解结果: %v", parts)

			info.Status = model.StatusOnline
			if info.Version == 4 {
				// 微信4.0版本的路径结构：...\xwechat_files\账户名\db_storage\session\session.db
				// 尝试多种方式提取账号名称
				accountName, dataDir := extractWeChatV4AccountInfo(parts)
				log.Debug().Str("accountName", accountName).Str("dataDir", dataDir).Msg("提取微信4.0账户信息结果")
				if accountName != "" && dataDir != "" {
					info.AccountName = accountName
					info.DataDir = dataDir
					log.Debug().Str("accountName", info.AccountName).Str("dataDir", info.DataDir).Msg("成功解析微信4.0版本的账户信息")
					log.Debug().Msgf("完整数据目录: %s", info.DataDir)
				} else {
					log.Debug().Msg("无法解析微信4.0版本的账户信息，尝试使用其他数据库文件")
					continue
				}
			} else {
				// 微信3.0版本的路径结构：...\WeChat Files\账户名\Msg\Misc.db
				if len(parts) >= 3 {
					info.DataDir = strings.Join(parts[:len(parts)-2], string(filepath.Separator))
					info.AccountName = parts[len(parts)-3]
					log.Debug().Str("accountName", info.AccountName).Str("dataDir", info.DataDir).Msg("成功解析微信3.0版本的账户信息")
				} else {
					log.Debug().Msg("无效的微信3.0版本文件路径")
					continue
				}
			}
			return nil
		}
	}

	log.Debug().Msgf("未找到微信进程 %d 的数据库文件", p.Pid)
	return nil
}

// extractWeChatV4AccountInfo 从微信4.0版本的路径中提取账户名和数据目录
func extractWeChatV4AccountInfo(parts []string) (accountName, dataDir string) {
	// 输出完整的路径分解结果，帮助调试
	log.Debug().Int("partsLen", len(parts)).Msgf("完整路径分解结果: %v", parts)

	// 尝试多种方式提取账号名称

	// 方式1：查找db_storage目录，账号名是其前一级目录
	dbStorageIndex := -1
	for i, part := range parts {
		log.Debug().Int("index", i).Str("part", part).Msg("检查路径部分")
		if strings.ToLower(part) == "db_storage" {
			log.Debug().Int("dbStorageIndex", i).Msg("找到db_storage目录")
			dbStorageIndex = i
			break
		}
	}

	if dbStorageIndex >= 2 {
		// 检查db_storage前两级目录，可能是...wechat_files号名b_storage结构
		// 先尝试前一级目录
		accountName = strings.TrimSpace(parts[dbStorageIndex-1])
		log.Debug().Str("accountName", accountName).Msg("尝试使用db_storage前一级目录作为账号名")
		// 构建数据目录：从根目录到账号名目录
		dataDirParts := parts[:dbStorageIndex]
		dataDir = strings.Join(dataDirParts, string(filepath.Separator))
		log.Debug().Str("dataDir", dataDir).Msg("尝试使用构建的数据目录")
		// 确保账号名不是空字符串或系统目录
		if accountName != "" && accountName != "xwechat_files" && accountName != "WeChat Files" {
			log.Debug().Str("accountName", accountName).Msg("成功使用db_storage前一级目录作为账号名")
			return
		}
		// 如果前一级是xwechat_files，则使用前两级目录
		if dbStorageIndex >= 3 {
			log.Debug().Str("prevPart", parts[dbStorageIndex-2]).Msg("检查db_storage前两级目录")
			if strings.ToLower(parts[dbStorageIndex-2]) == "xwechat_files" {
				accountName = strings.TrimSpace(parts[dbStorageIndex-1])
				log.Debug().Str("accountName", accountName).Msg("使用db_storage前两级目录作为账号名")
				dataDirParts = parts[:dbStorageIndex]
				dataDir = strings.Join(dataDirParts, string(filepath.Separator))
				log.Debug().Str("dataDir", dataDir).Msg("使用构建的数据目录")
				return
			}
		}
	}

	// 方式2：查找xwechat_files目录，账号名是其下一级目录
	xwechatIndex := -1
	for i, part := range parts {
		if strings.ToLower(part) == "xwechat_files" {
			xwechatIndex = i
			break
		}
	}

	if xwechatIndex >= 0 && xwechatIndex+1 < len(parts) {
		// 方式2.1：尝试xwechat_files/账号名结构
		accountName = strings.TrimSpace(parts[xwechatIndex+1])
		// 构建数据目录：从根目录到xwechat_files/账号名
		dataDirParts := parts[:xwechatIndex+2]
		dataDir = strings.Join(dataDirParts, string(filepath.Separator))
		// 确保账号名不是空字符串或系统目录
		if accountName != "" && accountName != "db_storage" && accountName != "session" && accountName != "message" && accountName != "unknown_wechat" {
			log.Debug().Str("accountName", accountName).Str("dataDir", dataDir).Msg("成功使用xwechat_files下一级目录作为账号名")
			return
		}

		// 方式2.2：如果下一级不是有效的账号名，尝试下下一级目录
		if xwechatIndex+2 < len(parts) {
			accountName = strings.TrimSpace(parts[xwechatIndex+2])
			dataDirParts = parts[:xwechatIndex+3]
			dataDir = strings.Join(dataDirParts, string(filepath.Separator))
			if accountName != "" && accountName != "db_storage" && accountName != "session" && accountName != "message" && accountName != "unknown_wechat" {
				log.Debug().Str("accountName", accountName).Str("dataDir", dataDir).Msg("成功使用xwechat_files下两级目录作为账号名")
				return
			}
		}

		// 方式2.3：如果以上方式都失败，尝试查找xwechat_files下的所有子目录
		// 这里我们只记录日志，不实际执行，因为我们没有文件系统访问权限
		log.Debug().Str("xwechatIndex", strconv.Itoa(xwechatIndex)).Msg("无法从xwechat_files目录提取有效的账号名，尝试其他方法")
	}

	// 方式3：查找WeChat Files目录，账号名是其下一级目录
	wechatFilesIndex := -1
	for i, part := range parts {
		if strings.ToLower(part) == "wechat files" {
			wechatFilesIndex = i
			break
		}
	}

	if wechatFilesIndex >= 0 && wechatFilesIndex+1 < len(parts) {
		accountName = strings.TrimSpace(parts[wechatFilesIndex+1])
		// 构建数据目录：从根目录到WeChat Files/账号名
		dataDirParts := parts[:wechatFilesIndex+2]
		dataDir = strings.Join(dataDirParts, string(filepath.Separator))
		return
	}

	// 方式4：从完整路径中查找可能的账号名目录
	// 账号名通常是xwechat_files或WeChat Files目录下的子目录
	for i := range parts {
		// 检查是否是用户目录下的目录
		if i >= 2 && strings.ToLower(parts[i-1]) == "users" {
			// 查找xwechat_files或WeChat Files目录
			for j := i; j < len(parts); j++ {
				currentPart := strings.ToLower(parts[j])
				if currentPart == "xwechat_files" || currentPart == "wechat files" {
					// 账号名是下一级目录
					if j+1 < len(parts) {
						accountName = strings.TrimSpace(parts[j+1])
						dataDirParts := parts[:j+2]
						dataDir = strings.Join(dataDirParts, string(filepath.Separator))
						return
					}
				}
			}
		}
	}

	// 方式5：查找包含微信账号特征的目录名（通常是手机号或微信号）
	// 这里我们尝试找到最后一个可能是账号名的目录
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		// 排除一些明显不是账号名的目录
		if part != "" && part != "db_storage" && part != "session" && part != "Msg" && part != "FileStorage" && part != "message" && part != "xwechat_files" && part != "WeChat Files" {
			accountName = part
			// 构建数据目录：从根目录到该目录
			dataDirParts := parts[:i+1]
			dataDir = strings.Join(dataDirParts, string(filepath.Separator))
			return
		}
	}

	// 如果以上方式都失败，尝试使用可执行文件目录作为参考
	// 这里返回空字符串，让调用者处理
	return "", ""
}
