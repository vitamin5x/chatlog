package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
)

// handleGetAccounts 获取微信账号列表
func (s *Service) handleGetAccounts(c *gin.Context) {
	status := c.Query("status") // online, offline, all

	accounts := s.ctx.GetWeChatInstances()
	if accounts == nil {
		c.JSON(http.StatusOK, gin.H{"accounts": []interface{}{}})
		return
	}

	type AccountResponse struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
		Version  string `json:"version"`
		DataDir  string `json:"data_dir"`
		PID      uint32 `json:"pid"`
		Status   string `json:"status"`
	}

	result := make([]AccountResponse, 0)
	for _, acc := range accounts {
		// 根据 status 参数过滤
		if status != "" && status != "all" && acc.Status != status {
			continue
		}

		result = append(result, AccountResponse{
			Name:     acc.Name,
			Platform: acc.Platform,
			Version:  acc.FullVersion,
			DataDir:  acc.DataDir,
			PID:      acc.PID,
			Status:   acc.Status,
		})
	}

	c.JSON(http.StatusOK, gin.H{"accounts": result})
}

// handleUpdateWebhookTalker 更新 webhook talker 配置
func (s *Service) handleUpdateWebhookTalker(c *gin.Context) {
	type UpdateRequest struct {
		Index  *int   `json:"index"`  // Webhook item index (optional)
		URL    string `json:"url"`    // Webhook URL (optional, alternative to index)
		Talker string `json:"talker"` // New talker value
	}

	var req UpdateRequest
	if err := c.BindJSON(&req); err != nil {
		errors.Err(c, errors.InvalidArg("request body"))
		return
	}

	if req.Talker == "" {
		errors.Err(c, errors.InvalidArg("talker cannot be empty"))
		return
	}

	webhook := s.ctx.GetWebhook()
	if webhook == nil || len(webhook.Items) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No webhook configuration found"})
		return
	}

	// 查找要更新的 webhook item
	var targetIndex int = -1
	if req.Index != nil {
		// 通过 index 查找
		if *req.Index >= 0 && *req.Index < len(webhook.Items) {
			targetIndex = *req.Index
		}
	} else if req.URL != "" {
		// 通过 URL 查找
		for i, item := range webhook.Items {
			if item.URL == req.URL {
				targetIndex = i
				break
			}
		}
	}

	if targetIndex == -1 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Webhook item not found"})
		return
	}

	// 更新 talker
	oldTalker := webhook.Items[targetIndex].Talker
	webhook.Items[targetIndex].Talker = req.Talker

	// 持久化配置
	s.ctx.UpdateConfig()

	log.Info().
		Int("index", targetIndex).
		Str("url", webhook.Items[targetIndex].URL).
		Str("old_talker", oldTalker).
		Str("new_talker", req.Talker).
		Msg("Webhook talker updated")

	c.JSON(http.StatusOK, gin.H{
		"message":    "Webhook talker updated successfully",
		"index":      targetIndex,
		"url":        webhook.Items[targetIndex].URL,
		"old_talker": oldTalker,
		"new_talker": req.Talker,
	})
}
