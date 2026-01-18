package model

import "time"

// 注意，v4 session 是独立数据库文件
// CREATE TABLE SessionTable(
// username TEXT PRIMARY KEY,
// type INTEGER,
// unread_count INTEGER,
// unread_first_msg_srv_id INTEGER,
// is_hidden INTEGER,
// summary TEXT,
// draft TEXT,
// status INTEGER,
// last_timestamp INTEGER,
// sort_timestamp INTEGER,
// last_clear_unread_timestamp INTEGER,
// last_msg_locald_id INTEGER,
// last_msg_type INTEGER,
// last_msg_sub_type INTEGER,
// last_msg_sender TEXT,
// last_sender_display_name TEXT,
// last_msg_ext_type INTEGER
// )
type SessionV4 struct {
	Username              string `json:"username"`
	Summary               string `json:"summary"`
	LastTimestamp         int    `json:"last_timestamp"`
	LastMsgSender         string `json:"last_msg_sender"`
	LastSenderDisplayName string `json:"last_sender_display_name"`

	// Type                     int    `json:"type"`
	// UnreadCount              int    `json:"unread_count"`
	// UnreadFirstMsgSrvID      int    `json:"unread_first_msg_srv_id"`
	// IsHidden                 int    `json:"is_hidden"`
	// Draft                    string `json:"draft"`
	// Status                   int    `json:"status"`
	// SortTimestamp            int    `json:"sort_timestamp"`
	// LastClearUnreadTimestamp int    `json:"last_clear_unread_timestamp"`
	// LastMsgLocaldID          int    `json:"last_msg_locald_id"`
	// LastMsgType              int    `json:"last_msg_type"`
	// LastMsgSubType           int    `json:"last_msg_sub_type"`
	// LastMsgExtType           int    `json:"last_msg_ext_type"`
}

func (s *SessionV4) Wrap() *Session {
	var ntime time.Time

	// 检查时间戳的数量级，区分秒级和毫秒级
	// 1e11 是 2001年左右的毫秒级时间戳，当前时间约为 1.8e12 毫秒
	if s.LastTimestamp > 100000000000 { // 如果时间戳大于1e11，判断为毫秒级
		ntime = time.Unix(int64(s.LastTimestamp)/1000, int64(s.LastTimestamp)%1000*1000000)
	} else { // 否则判断为秒级
		ntime = time.Unix(int64(s.LastTimestamp), 0)
	}

	return &Session{
		UserName: s.Username,
		NOrder:   s.LastTimestamp,
		NickName: s.LastSenderDisplayName,
		Content:  s.Summary,
		NTime:    ntime,
	}
}
