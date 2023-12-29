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
	Token            string
	AllowConfRequest bool
	FloodWait        int
	LogLevel         log.Lvl

	Bot      *echotron.API
	BotMutex sync.RWMutex

	floodWait        = make(map[int64]int64)
	floodMessageSent = make(map[int64]struct{})
)

func Start(initDeps TgBotInitDependencies) (err error) {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		if err != nil {
			BotMutex.Lock()
			Bot = nil
			BotMutex.Unlock()
			ticker.Stop()
		}
		if r := recover(); r != nil {
			err = fmt.Errorf("[PANIC] recovered from panic: %v", r)
		}
	}()

	token := Token
	if token == "" || len(token) < 30 {
		return
	}

	bot := echotron.NewAPI(token)

	res, err := bot.GetMe()
	if !res.Ok || err != nil {
		log.Warnf("[Telegram] Unable to connect to bot.\n%v\n%v", res.Description, err)
		return
	}

	BotMutex.Lock()
	Bot = &bot
	BotMutex.Unlock()

	if LogLevel <= log.INFO {
		fmt.Printf("[Telegram] Authorized as %s\n", res.Result.Username)
	}

	go func() {
		for range ticker.C {
			updateFloodWait()
		}
	}()

	if !AllowConfRequest {
		return
	}

	updatesChan := echotron.PollingUpdatesOptions(token, false, echotron.UpdateOptions{AllowedUpdates: []echotron.UpdateType{echotron.MessageUpdate}})
	for update := range updatesChan {
		if update.Message != nil {
			userid := update.Message.Chat.ID
			if _, wait := floodWait[userid]; wait {
				if _, notified := floodMessageSent[userid]; notified {
					continue
				}
				floodMessageSent[userid] = struct{}{}
				_, err := bot.SendMessage(
					fmt.Sprintf("You can only request your configs once per %d minutes", FloodWait),
					userid,
					&echotron.MessageOptions{
						ReplyToMessageID: update.Message.ID,
					})
				if err != nil {
					log.Errorf("Failed to send telegram message. Error %v", err)
				}
				continue
			}
			floodWait[userid] = time.Now().Unix()

			failed := initDeps.SendRequestedConfigsToTelegram(initDeps.DB, userid)
			if len(failed) > 0 {
				messageText := "Failed to send configs:\n"
				for _, f := range failed {
					messageText += f + "\n"
				}
				_, err := bot.SendMessage(
					messageText,
					userid,
					&echotron.MessageOptions{
						ReplyToMessageID: update.Message.ID,
					})
				if err != nil {
					log.Errorf("Failed to send telegram message. Error %v", err)
				}
			}
		}
	}
	return err
}

func SendConfig(userid int64, clientName string, confData, qrData []byte, ignoreFloodWait bool) error {
	BotMutex.RLock()
	defer BotMutex.RUnlock()

	if Bot == nil {
		return fmt.Errorf("telegram bot is not configured or not available")
	}

	if _, wait := floodWait[userid]; wait && !ignoreFloodWait {
		return fmt.Errorf("this client already got their config less than %d minutes ago", FloodWait)
	}

	if !ignoreFloodWait {
		floodWait[userid] = time.Now().Unix()
	}

	qrAttachment := echotron.NewInputFileBytes("qr.png", qrData)
	_, err := Bot.SendPhoto(qrAttachment, userid, &echotron.PhotoOptions{Caption: clientName})
	if err != nil {
		log.Error(err)
		return fmt.Errorf("unable to send qr picture")
	}

	confAttachment := echotron.NewInputFileBytes(clientName+".conf", confData)
	_, err = Bot.SendDocument(confAttachment, userid, nil)
	if err != nil {
		log.Error(err)
		return fmt.Errorf("unable to send conf file")
	}
	return nil
}

func updateFloodWait() {
	thresholdTS := time.Now().Unix() - 60*int64(FloodWait)
	for userid, ts := range floodWait {
		if ts < thresholdTS {
			delete(floodWait, userid)
			delete(floodMessageSent, userid)
		}
	}
}
