package main

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog"
)

func main() {
	m := chatlog.New()
	ret, err := m.CommandKeyForGRPC("", 0, false, false)
	if err != nil {
		log.Err(err).Msg("failed to get key")
		return
	}
	fmt.Println(ret)
}
