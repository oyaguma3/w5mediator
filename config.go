package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

type wFiveConf struct {
	fileName             string
	maxSize              int
	maxBackups           int
	maxAge               int
	localTime            bool
	compress             bool
	logLevel             int
	sensitiveInfo        bool
	sharedSecret         string
	allowedClientAddress string
	userNameAddition     bool
	nwNameForKDF         string
	atKDFInput           string
	udrAddress           string
	apiVersion           string
	responseBodyType     int
	allowdPLMN           string
}

func getConfYaml() (wFiveConf, error) {
	var confSet wFiveConf
	var readConf struct {
		ConfFilename             string `yaml:"filename"`
		ConfMaxSize              int    `yaml:"maxSize"`
		ConfMaxBackups           int    `yaml:"maxBackups"`
		ConfMaxAge               int    `yaml:"maxAge"`
		ConfLocalTime            bool   `yaml:"localTime"`
		ConfCompress             bool   `yaml:"compress"`
		ConfLogLevel             int    `yaml:"logLevel"`
		ConfSensitiveInfo        bool   `yaml:"sensitiveInfo"`
		ConfSharedSecret         string `yaml:"sharedSecret"`
		ConfAllowedClientAddress string `yaml:"allowedClientAddress"`
		ConfUserNameAddition     bool   `yaml:"userNameAddition"`
		ConfNwNameForKDF         string `yaml:"nwNameForKDF"`
		ConfAtKDFInput           string `yaml:"atKDFInput"`
		ConfUdrAddress           string `yaml:"udrAddress"`
		ConfApiVersion           string `yaml:"apiVersion"`
		ConfResponseBodyType     int    `yaml:"responseBodyType"`
		ConfAllowedPLMN          string `yaml:"allowedPLMN"`
	}
	rf, err := os.ReadFile("w5conf.yaml")
	if err != nil {
		log.Printf("Failed to read configuration file. / %v\n", err)
		return confSet, err
	}
	unmarshalErr := yaml.Unmarshal(rf, &readConf)
	if unmarshalErr != nil {
		log.Printf("Failed to unmarshal config items. / %v\n", err)
		return confSet, err
	}
	confSet.fileName = readConf.ConfFilename
	confSet.maxSize = readConf.ConfMaxSize
	confSet.maxBackups = readConf.ConfMaxBackups
	confSet.maxAge = readConf.ConfMaxAge
	confSet.localTime = readConf.ConfLocalTime
	confSet.compress = readConf.ConfCompress
	confSet.logLevel = readConf.ConfLogLevel
	confSet.sensitiveInfo = readConf.ConfSensitiveInfo
	confSet.sharedSecret = readConf.ConfSharedSecret
	confSet.allowedClientAddress = readConf.ConfAllowedClientAddress
	confSet.userNameAddition = readConf.ConfUserNameAddition
	confSet.nwNameForKDF = readConf.ConfNwNameForKDF
	confSet.atKDFInput = readConf.ConfAtKDFInput
	confSet.udrAddress = readConf.ConfUdrAddress
	confSet.apiVersion = readConf.ConfApiVersion
	confSet.responseBodyType = readConf.ConfResponseBodyType
	confSet.allowdPLMN = readConf.ConfAllowedPLMN
	// validation check after loading config items.
	confSetErr := confValidationCheck(confSet)
	if confSetErr != nil {
		log.Printf("invalid config item / %v\n", confSetErr)
		confSet = wFiveConf{}
		return confSet, confSetErr
	}
	return confSet, nil
}

func confValidationCheck(cf wFiveConf) error {
	// filename check
	if len(cf.fileName) < 1 {
		fileNameErr := fmt.Errorf("log filename not specified")
		return fileNameErr
	}
	// maxsize check
	if cf.maxSize < 1 || cf.maxSize > 1024 {
		maxSizeErr := fmt.Errorf("log maxsize too short or long")
		return maxSizeErr
	}
	// loglevel check
	if cf.logLevel < 0 || cf.logLevel > 4 {
		logLevelErr := fmt.Errorf("loglevel value is invalid")
		return logLevelErr
	}
	// sharedSecret check
	if len(cf.sharedSecret) < 8 || len(cf.sharedSecret) > 253 {
		sharedSecretErr := fmt.Errorf("shared secret is too short or long")
		return sharedSecretErr
	}
	// allowedClientAddress check
	if nil == net.ParseIP(cf.allowedClientAddress) {
		allowedClientAddrErr := fmt.Errorf("invalid client address")
		return allowedClientAddrErr
	}
	// nwNameForKDF check
	if len(cf.nwNameForKDF) > 200 {
		nwNameForKDFErr := fmt.Errorf("network name is too short or long")
		return nwNameForKDFErr
	}
	// atKDFInput check
	if len(cf.atKDFInput) > 200 {
		atKDFInputErr := fmt.Errorf("kdf input value is too short or long")
		return atKDFInputErr
	}
	// udrAddress check
	udrAddrChk, udrPort, sepChk := strings.Cut(cf.udrAddress, ":")
	udrPortChk, _ := strconv.Atoi(udrPort)
	if nil == net.ParseIP(udrAddrChk) || udrPortChk > 65535 || udrPortChk < 0 || !sepChk {
		udrAddrErr := fmt.Errorf("invalid udr address or port number")
		return udrAddrErr
	}
	// apiVersion check
	if !(cf.apiVersion == "v1" || cf.apiVersion == "v2") {
		apiVerErr := fmt.Errorf("invalid api version")
		return apiVerErr
	}
	// responseBodeType check
	switch cf.responseBodyType {
	case 1:
	default:
		respBodyTypeErr := fmt.Errorf("unsupported response body type")
		return respBodyTypeErr
	}
	// allowedPLMN check
	plmnChk := allowedPLMNcheck(cf.allowdPLMN)
	if plmnChk != nil {
		allowedPLMNErr := fmt.Errorf("invalid PLMN")
		return allowedPLMNErr
	}
	return nil
}

func setLoggerConfig(cf wFiveConf) (string, error) {
	log.SetOutput(&lumberjack.Logger{
		Filename:   cf.fileName,
		MaxSize:    cf.maxSize,
		MaxBackups: cf.maxBackups,
		MaxAge:     cf.maxAge,
		LocalTime:  cf.localTime,
		Compress:   cf.compress,
	})
	var logLevelStr string
	var errStr error
	switch cf.logLevel {
	case 1:
		slog.SetLogLoggerLevel(slog.LevelError)
		logLevelStr = "Log Level : Error"
	case 2:
		slog.SetLogLoggerLevel(slog.LevelWarn)
		logLevelStr = "Log Level : Warn"
	case 3:
		slog.SetLogLoggerLevel(slog.LevelInfo)
		logLevelStr = "Log Level : Info"
	case 4:
		slog.SetLogLoggerLevel(slog.LevelDebug)
		logLevelStr = "Log Level : Debug"
	default:
		errStr = fmt.Errorf("invalid log level value")
	}
	return logLevelStr, errStr
}

func confOutputToLog(confSet wFiveConf) {
	log.Println("[CONFIG] WLAN-5GC Mediator configuration loaded.")
	log.Println("----------configList----------")
	if confSet.logLevel != 4 {
		log.Println("[CONFIG] Config item is not displayed.(Debug Lv only)")
	}
	slog.Debug("config /", "fileName", confSet.fileName)
	slog.Debug("config /", "maxSize", confSet.maxSize)
	slog.Debug("config /", "maxBackups", confSet.maxBackups)
	slog.Debug("config /", "maxAge", confSet.maxAge)
	slog.Debug("config /", "localTime", confSet.localTime)
	slog.Debug("config /", "compress", confSet.compress)
	slog.Debug("config /", "logLevel", confSet.logLevel)
	slog.Debug("config /", "sensitiveInfo", confSet.sensitiveInfo)
	slog.Debug("config /", "sharedSecret", confSet.sharedSecret)
	slog.Debug("config /", "allowedClientAddress", confSet.allowedClientAddress)
	slog.Debug("config /", "userNameAddition", confSet.userNameAddition)
	slog.Debug("config /", "nwNameForKDF", confSet.nwNameForKDF)
	slog.Debug("config /", "udrAddress", confSet.udrAddress)
	slog.Debug("config /", "apiVersion", confSet.apiVersion)
	slog.Debug("config /", "responseBodyType", confSet.responseBodyType)
	slog.Debug("config /", "allowdPLMN", confSet.allowdPLMN)
	log.Println("------------------------------")
}

func allowedPLMNcheck(apstr string) error {
	var chkErr error
	trimmedStr := strings.ReplaceAll(apstr, " ", "")
	chkPLMN := strings.Split(trimmedStr, ",")
	elemNum := len(chkPLMN)
	for i := 0; i < elemNum; i++ {
		chkPLMNStr := ""
		chkPLMNStr = strings.ReplaceAll(chkPLMN[i], "-", "")
		if !(len(chkPLMNStr) == 5 || len(chkPLMNStr) == 6) {
			log.Println("[CONFIG] invalid plmn length")
			chkErr = fmt.Errorf("invalid plmn length")
		}
		_, err := strconv.Atoi(chkPLMNStr)
		if err != nil {
			log.Printf("%v", err)
			chkErr = err
			break
		}
	}
	return chkErr
}
