# Regarding w5mediator
w5mediator is application that runs EAP-AKA/AKA' using free5GC's UDR.  
This application acts as an intermediary between 5GC UDR and Wi-Fi AP (802.1X supported).  
Therefore, it is named "w5mediator"(WLAN-5GC mediator).  
[README in Japanese is here.](/README_JP.md)

## Spec and limitations
 - EAP-AKA and EAP-AKA' supported but EAP-SIM not supported.
 - Radius and EAP are minimal implementations for EAP-AKA/EAP-AKA' with 802.1X auth.
 - Milenage algorithm only supported.
 - Accounting and Status-Server are not supported in ver.1.0.
 - TLS and OAuth2.0 as 5GC NF are not supported in ver.1.0.  
(Therefore, free5GC v3.4.1 or earlier is recommended to use.)

## Build and activation
### Build
Go 1.22.1 or later install needed.   
Please build it with the following 8 files.  
If you want to run without building, simply use "`go run .`".  
 - authInfoCalcFunction.go
 - config.go
 - eapPacketHandling.go
 - eapServer.go
 - infoManagement.go
 - radiusUtil.go
 - udrQueryCaster.go
 - w5mediator.go
### Activation
Simply run executable file of w5mediator.  
(Don't forget set w5conf.yaml in the same folder)

## Summary 
### Node
<img src="https://github.com/oyaguma3/w5mediator/assets/170003128/269eae97-9a03-4f1f-901e-a0860099fdef" width="30%" />

### Config
Config file is `w5conf.yaml`, don't change the file name.  
Config file must be in the same folder as executable file.  
Regarding config items, please check comments and explanation in `w5conf.yaml`.  
But probably, the following items need to be set.  
 - sharedSecret
 - allowedClientAddress
 - udrAddress
 - allowedPLMN
### Using free5GC
version 3.4.1 or earlier is recommended. (it works confirmed only v3.4.1)  
And following items are point of change for free5GC NRF config.  
(target: /free5gc/config/nrfcfg.yaml)
 - oauth  
Please set `false` because this application does not supported OAuth2.0 as 5GC NF.
 - DefaultPlmnId  
Please set suitable PLMN for using SIM/eSIM.
 - Webconsole  
Please set `EAP-AKA'` in authentication type when you register SIM key information(IMSI/Ki/OPc) to free5GC by webconsole.  

## Development plan
The items at the top have higher priority.
 - ~~Improvement: SQN increment in sync-fail~~ 2025/03/23 fixed.
 - Support: Status-Server (Radius)
 - Support: Accounting (Radius message only)
 - Support: OAuth 2.0
 - Support: Registration as 5GC NF
 - Support: TUAK algorithm (if possible)

## Reference
### SIM card for investigation use (Milenage supported and IMSI/Ki/OPc revealed)
[https://sysmocom.de/index.html](https://sysmocom.de/index.html)
 - [sysmoISIM-SJA5-9FV SIM + USIM + ISIM Card (10-pack) with ADM keys; 9FV chip](https://shop.sysmocom.de/sysmoISIM-SJA5-9FV-SIM-USIM-ISIM-Card-10-pack-with-ADM-keys-9FV-chip/sysmoISIM-SJA5-9FV-10p-adm)
### used Golang package
 - [https://pkg.go.dev/layeh.com/radius](https://pkg.go.dev/layeh.com/radius)
 - [https://pkg.go.dev/github.com/google/gopacket](https://pkg.go.dev/github.com/google/gopacket)
 - [https://pkg.go.dev/gopkg.in/yaml.v3](https://pkg.go.dev/gopkg.in/yaml.v3)
 - [https://pkg.go.dev/github.com/wmnsk/milenage](https://pkg.go.dev/github.com/wmnsk/milenage)
 - [https://github.com/go-magma/magma](https://github.com/go-magma/magma)
 - [https://github.com/natefinch/lumberjack](https://github.com/natefinch/lumberjack)
