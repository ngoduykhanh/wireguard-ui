package telegram

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/NicoNex/echotron/v3"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/skip2/go-qrcode"
)

type BuildClientConfig func(client model.Client, server model.Server, setting model.GlobalSetting) string

type TgBotInitDependencies struct {
	DB                      store.IStore
	BuildClientConfig       BuildClientConfig
	TgUseridToClientID      map[int64]([]string)
	TgUseridToClientIDMutex *sync.RWMutex
}

var (
	TelegramToken            string
	TelegramAllowConfRequest bool
	TelegramFloodWait        int
	LogLevel                 log.Lvl

	TgBot      *echotron.API
	TgBotMutex sync.RWMutex

	floodWait = make(map[int64]int64, 0)

	qrCodeSettings = model.QRCodeSettings{
		Enabled:    true,
		IncludeDNS: true,
		IncludeMTU: true,
	}
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

			initDeps.TgUseridToClientIDMutex.RLock()
			if clids, found := initDeps.TgUseridToClientID[userid]; found && len(clids) > 0 {
				initDeps.TgUseridToClientIDMutex.RUnlock()

				for _, clid := range clids {
					func(clid string) {
						clientData, err := initDeps.DB.GetClientByID(clid, qrCodeSettings)
						if err != nil {
							return
						}

						// build config
						server, _ := initDeps.DB.GetServer()
						globalSettings, _ := initDeps.DB.GetGlobalSettings()
						config := initDeps.BuildClientConfig(*clientData.Client, server, globalSettings)
						configData := []byte(config)
						var qrData []byte

						if clientData.Client.PrivateKey != "" {
							qrData, err = qrcode.Encode(config, qrcode.Medium, 512)
							if err != nil {
								return
							}
						}

						userid, err := strconv.ParseInt(clientData.Client.TgUserid, 10, 64)
						if err != nil {
							return
						}

						SendConfig(userid, clientData.Client.Name, configData, qrData, true)
					}(clid)
					time.Sleep(2 * time.Second)
				}
			} else {
				initDeps.TgUseridToClientIDMutex.RUnlock()
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
	thresholdTS := time.Now().Unix() - 60000*int64(TelegramFloodWait)
	for userid, ts := range floodWait {
		if ts < thresholdTS {
			delete(floodWait, userid)
		}
	}
}
