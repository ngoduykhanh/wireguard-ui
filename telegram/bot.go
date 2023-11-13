package telegram

import (
	"fmt"
	"sync"
	"time"

	"github.com/NicoNex/echotron/v3"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
)

type BuildClientConfig func(client model.Client, server model.Server, setting model.GlobalSetting) string

var (
	TelegramToken            string
	TelegramAllowConfRequest bool
	TelegramFloodWait        int
	LogLevel                 log.Lvl

	TgBot      *echotron.API
	TgBotMutex sync.RWMutex

	floodWait = make(map[int64]int64, 0)
)

func Start(db store.IStore, buildClientConfig BuildClientConfig) (err error) {
	defer func() {
		TgBotMutex.Lock()
		TgBot = nil
		TgBotMutex.Unlock()
		if r := recover(); r != nil {
			err = fmt.Errorf("[PANIC] recovered from panic: %v", r)
		}
	}()

	token := TelegramToken
	if token == "" || len(token) < 30 {
		return
	}

	bot := echotron.NewAPI(token)

	res, err := bot.GetMe()
	if !res.Ok || err != nil {
		log.Warnf("[Telegram] Unable to connect to bot.\n%v\n%v", res.Description, err)
		return
	}

	TgBotMutex.Lock()
	TgBot = &bot
	TgBotMutex.Unlock()

	if LogLevel <= log.INFO {
		fmt.Printf("[Telegram] Authorized as %s\n", res.Result.Username)
	}

	if !TelegramAllowConfRequest {
		return
	}

	ticker := time.NewTicker(time.Minute)
	go func() {
		for range ticker.C {
			updateFloodWait()
		}
	}()

	updatesChan := echotron.PollingUpdatesOptions(token, false, echotron.UpdateOptions{AllowedUpdates: []echotron.UpdateType{echotron.MessageUpdate}})
	for update := range updatesChan {
		if update.Message != nil {
			floodWait[update.Message.Chat.ID] = time.Now().Unix()
		}
	}
	return err
}

func SendConfig(userid int64, clientName string, confData, qrData []byte) error {
	TgBotMutex.RLock()
	defer TgBotMutex.RUnlock()

	if TgBot == nil {
		return fmt.Errorf("telegram bot is not configured or not available")
	}

	if _, wait := floodWait[userid]; wait {
		return fmt.Errorf("this client already got their config less than %d minutes ago", TelegramFloodWait)
	}

	qrAttachment := echotron.NewInputFileBytes("qr.png", qrData)
	_, err := TgBot.SendPhoto(qrAttachment, userid, &echotron.PhotoOptions{Caption: clientName})
	if err != nil {
		log.Error(err)
		return fmt.Errorf("unable to send qr picture")
	}

	confAttachment := echotron.NewInputFileBytes(clientName+".conf", confData)
	_, err = TgBot.SendDocument(confAttachment, userid, nil)
	if err != nil {
		log.Error(err)
		return fmt.Errorf("unable to send conf file")
	}

	floodWait[userid] = time.Now().Unix()
	return nil
}

func updateFloodWait() {
	thresholdTS := time.Now().Unix() - 60000*int64(TelegramFloodWait)
	for userid, ts := range floodWait {
		if ts < thresholdTS {
			delete(floodWait, userid)
		}
	}
}
