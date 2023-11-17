package telegram

import (
	"fmt"
	"sync"
	"time"

	"github.com/NicoNex/echotron/v3"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/store"
)

type SendRequestedConfigsToTelegram func(db store.IStore, userid int64) []string

type TgBotInitDependencies struct {
	DB                             store.IStore
	SendRequestedConfigsToTelegram SendRequestedConfigsToTelegram
}

var (
	TelegramToken            string
	TelegramAllowConfRequest bool
	TelegramFloodWait        int
	LogLevel                 log.Lvl

	TgBot      *echotron.API
	TgBotMutex sync.RWMutex

	floodWait = make(map[int64]int64, 0)
)

func Start(initDeps TgBotInitDependencies) (err error) {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		TgBotMutex.Lock()
		TgBot = nil
		TgBotMutex.Unlock()
		ticker.Stop()
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

	go func() {
		for range ticker.C {
			updateFloodWait()
		}
	}()

	if !TelegramAllowConfRequest {
		return
	}

	updatesChan := echotron.PollingUpdatesOptions(token, false, echotron.UpdateOptions{AllowedUpdates: []echotron.UpdateType{echotron.MessageUpdate}})
	for update := range updatesChan {
		if update.Message != nil {
			userid := update.Message.Chat.ID
			if _, wait := floodWait[userid]; wait {
				bot.SendMessage(
					fmt.Sprintf("You can only request your configs once per %d minutes", TelegramFloodWait),
					userid,
					&echotron.MessageOptions{
						ReplyToMessageID: update.Message.ID,
					})
				continue
			}
			floodWait[userid] = time.Now().Unix()

			failed := initDeps.SendRequestedConfigsToTelegram(initDeps.DB, userid)
			if len(failed) > 0 {
				messageText := "Failed to send configs:\n"
				for _, f := range failed {
					messageText += f + "\n"
				}
				bot.SendMessage(
					messageText,
					userid,
					&echotron.MessageOptions{
						ReplyToMessageID: update.Message.ID,
					})
			}
		}
	}
	return err
}

func SendConfig(userid int64, clientName string, confData, qrData []byte, ignoreFloodWait bool) error {
	TgBotMutex.RLock()
	defer TgBotMutex.RUnlock()

	if TgBot == nil {
		return fmt.Errorf("telegram bot is not configured or not available")
	}

	if _, wait := floodWait[userid]; wait && !ignoreFloodWait {
		return fmt.Errorf("this client already got their config less than %d minutes ago", TelegramFloodWait)
	}

	if !ignoreFloodWait {
		floodWait[userid] = time.Now().Unix()
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
	return nil
}

func updateFloodWait() {
	thresholdTS := time.Now().Unix() - 60*int64(TelegramFloodWait)
	for userid, ts := range floodWait {
		if ts < thresholdTS {
			delete(floodWait, userid)
		}
	}
}
