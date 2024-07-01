package main

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/google/gopacket/layers"
	"layeh.com/radius"
	"layeh.com/radius/vendors/microsoft"
)

// バージョン表記（ビルドにはGo 1.22以上が必要）
const currentVer string = "1.0.0"

// 設定を格納する構造体（の変数）
var conf wFiveConf

// 初期設定の読み込み＆適用を実行。
func init() {
	fmt.Printf("WLAN-5GC Mediator ver.%v reading configuration...\n", currentVer)
	var readConfErr error
	conf, readConfErr = getConfYaml()
	if readConfErr != nil {
		log.Fatalf("Configuration failed / %v\n", readConfErr)
	}
	logLv, setLogConfErr := setLoggerConfig(conf)
	if setLogConfErr != nil {
		log.Fatalf("Configuration failed / %v\n", setLogConfErr)
	}
	confOutputToLog(conf)
	fmt.Printf("%v\n", logLv)
}

// WLAN-5GC MediatorのRadiusサーバ機能を設定して起動。
func main() {
	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(mainHandle),
		SecretSource: radius.StaticSecretSource([]byte(conf.sharedSecret)),
	}
	fmt.Println("WLAN-5GC mediator start.")
	log.Println("WLAN-5GC mediator start.")
	go garbageIdCleaner()
	// 残置EAP-ID削除ルーチンを動かしてからサーバ起動。
	mediatorStartErr := server.ListenAndServe()
	if mediatorStartErr != nil {
		fmt.Println("WLAN-5GC mediator activation failed.")
		slog.Error("WLAN-5GC mediator activation failed /", "error", mediatorStartErr)
		log.Fatalln("WLAN-5GC mediator close.")
	}
}

/* ---------- ここから先はハンドラ処理のみ ---------- */

// RADIUSパケット受信時のハンドラ（かなり長い）
func mainHandle(w radius.ResponseWriter, r *radius.Request) {
	rejectFlag := false
	isNeedMsgAuthenticator := true
	var thisCase byte
	var replyMessage string = "null"
	var responsePacket *radius.Packet
	eapPacketFromClient := new(layers.EAP)
	var eapPacketToClient []byte
	//ハンドラ処理開始
	slog.Info("[RADIUS] Request message received /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "received_from", r.RemoteAddr)
	// 受信したRadiusパケットのSrcアドレス成否判定。
	valid := isSrcAddrValid(r.RemoteAddr.String())
	if !valid {
		slog.Warn("[RADIUS] silently discarded /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", "source address not allowed")
		return
	}
	// Proxy-State(33)の有無確認。各種判定前であるこのタイミングで実行しておく。
	var attr33 map[int][]byte
	var attr33Exist bool
	attr33, attr33Exist = multiAttrGet(r.Packet, 33)
	// 受信したRadiusパケットにEAP-Messageが含まれているか確認。同関数内でMACチェックも実施している。
	// 含まれているなら、戻り値をeapPacketに(*layer.EAP型で)格納する。
	pkt, isIncluded, isIncludedErr := isEAPMessageIncluded(r)
	if !isIncluded || isIncludedErr != nil {
		rejectFlag = true
		slog.Warn("[RADIUS] Response : Access rejected /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", isIncludedErr)
		return
	} else {
		eapPacketFromClient = pkt
	}
	// eapPacketを元にcase判定を実施
	if rejectFlag {
		thisCase = 0
		slog.Info("[RADIUS] case categorized /", "case", "nothing or invalid EAP packet")
	} else {
		thisCase = reqCaseCategorize(eapPacketFromClient)
	}
	// caseごとの処理関数を実行（n35呼び出しなど）
	// 各caseは、RADIUSのEAP-Message AVPに載せるパケットを導出して、eapPacketToClientを適切なRADIUSメッセージに載せるところまで。
	switch thisCase {
	case 1, 11, 12:
		// 返ってきたerrの中身を見て判断。err == nil ならAKA-Challenge/AKA-Identity、errあるならEAP-Failureになる。
		// AKA-Challenge/AKA-Identityは、replyMsgが"null"か"FULLAUTH"かで判別する。
		eapPacketToClient, repMsg, actionEIErr := actionEapIdentity(thisCase, eapPacketFromClient)
		if actionEIErr != nil {
			slog.Info("[RADIUS] Response : Access rejected /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", actionEIErr)
			replyMessage = repMsg
			responsePacket = r.Response(radius.CodeAccessReject)
			responsePacket.Attributes.Add(79, eapPacketToClient)
		} else {
			switch repMsg {
			case "null":
				slog.Info("[RADIUS] Response : Access-Challenge/EAP-Request/AKA-Challenge /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier))
				responsePacket = r.Response(radius.CodeAccessChallenge)
				responsePacket.Attributes.Add(79, eapPacketToClient)
			case "FULLAUTH":
				slog.Info("[RADIUS] Response : Access-Challenge/EAP-Request/AKA-Identity /", "ReqMsg", r.Packet.Code, "ReqMId", fmt.Sprintf("0x%X", r.Packet.Identifier))
				responsePacket = r.Response(radius.CodeAccessChallenge)
				responsePacket.Attributes.Add(79, eapPacketToClient)
			default:
				slog.Error("[RADIUS] silently discarded /", "ReqMsg", r.Packet.Code, "ReqMId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", "undefined process")
			}
		}
	case 13, 14:
		// 何らかのerrが返ってくるならEAP-Failureとなり、actionACErr == nilならEAP-Successと判定。
		// EAP-Successなら、ここでMS-MPPE-recv/send-Keyを付与する。
		identity, _, err := eapIdTableLoad(eapPacketFromClient.Id)
		if err != nil {
			slog.Debug("[RADIUS] EAP-ID not found /", "error", err)
		}
		eapPacketToClient, repMsg, actionACErr := actionEapRespAkaChallenge(thisCase, eapPacketFromClient)
		if actionACErr != nil {
			slog.Info("[RADIUS] Response : Access rejected /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", actionACErr)
			replyMessage = repMsg
			responsePacket = r.Response(radius.CodeAccessReject)
			responsePacket.Attributes.Add(79, eapPacketToClient)
		} else {
			slog.Info("[RADIUS] Response : Access Accepted /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier))
			responsePacket = r.Response(radius.CodeAccessAccept)
			responsePacket.Attributes.Add(79, eapPacketToClient)
			// user-name付与（設定ONかつEAP-Success時のみ）
			if conf.userNameAddition {
				responsePacket.Attributes.Add(1, []byte(identity))
			}
			successUsr, exist := loadSubscInfo(identity)
			if !exist {
				slog.Debug("[RADIUS] valid subscInfo not found", "identity", identity)
			} else {
				recvKeyErr := microsoft.MSMPPERecvKey_Add(responsePacket, successUsr.msk[0:32])
				sendKeyErr := microsoft.MSMPPESendKey_Add(responsePacket, successUsr.msk[32:64])
				if recvKeyErr != nil || sendKeyErr != nil {
					slog.Warn("[RADIUS] MS-MPPE-Recv-Key generation failed /", "error", recvKeyErr)
					slog.Warn("[RADIUS] MS-MPPE-Send-Key generation failed /", "error", sendKeyErr)
				}
			}
		}
		deleteSubscInfo(identity)
		eapIdTableDelete(eapPacketFromClient.Id)
		isNeedMsgAuthenticator = true
	case 17, 18:
		eapPacketToClient, repMsg, actionResynchErr := actionEapRespAkaReSynch(thisCase, eapPacketFromClient)
		if actionResynchErr != nil {
			slog.Info("[RADIUS] Response : Access rejected /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", actionResynchErr)
			replyMessage = repMsg
			responsePacket = r.Response(radius.CodeAccessReject)
			responsePacket.Attributes.Add(79, eapPacketToClient)
			identity, _, err := eapIdTableLoad(eapPacketFromClient.Id)
			if err != nil {
				slog.Error("[RADIUS] EAP-ID not found /", "error", err)
			}
			deleteSubscInfo(identity)
			eapIdTableDelete(eapPacketFromClient.Id)
		} else {
			slog.Info("[RADIUS] Response : Access-Challenge/EAP-Request/AKA-Challenge (for Resynch) /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier))
			responsePacket = r.Response(radius.CodeAccessChallenge)
			responsePacket.Attributes.Add(79, eapPacketToClient)
		}
	case 15, 16, 19, 20:
		identity, _, err := eapIdTableLoad(eapPacketFromClient.Id)
		if err != nil {
			slog.Error("[RADIUS] EAP-ID not found /", "error", err)
		}
		deleteSubscInfo(identity)
		eapIdTableDelete(eapPacketFromClient.Id)
		eapPacketToClient, replyMessage = actionEapFail(thisCase)
		isNeedMsgAuthenticator = true
		slog.Info("[RADIUS] Response : Access rejected /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier))
		responsePacket = r.Response(radius.CodeAccessReject)
		responsePacket.Attributes.Add(79, eapPacketToClient)
	case 0, 253, 254, 255:
		isNeedMsgAuthenticator = false
		replyMessage = actionDirectReject(thisCase)
		slog.Info("[RADIUS] Response : Access rejected /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier))
		responsePacket = r.Response(radius.CodeAccessReject)
	default:
		slog.Error("[RADIUS] silently discarded /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", "undefined case")
		return
	}
	// Proxy-State付与処理
	if attr33Exist {
		for _, v := range attr33 {
			responsePacket.Attributes.Add(33, v)
		}
	}
	// Reply-Message付与。
	//"null"か"FULLAUTH"のときは付与せず、他のstringが入っているときは付与する）
	if !(replyMessage == "null" || replyMessage == "FULLAUTH") {
		responsePacket.Attributes.Add(18, []byte(replyMessage))
	}
	// Message-Authenticator付与（付与する必要がある場合のみ）
	if responsePacket != nil && isNeedMsgAuthenticator {
		zeroPadding := make([]byte, 16)
		responsePacket.Attributes.Add(80, zeroPadding)
		calculatedMAC, err := messageAuthenticatorCalc(responsePacket, conf.sharedSecret)
		if err != nil {
			slog.Error("[RADIUS] Message-Authenticator AVP generation error /", "error", err)
			slog.Error("[RADIUS] silently discarded /", "ReqMsg", r.Packet.Code, "ReqId", fmt.Sprintf("0x%X", r.Packet.Identifier), "error", "Message-Authenticator AVP generation error")
			return
		} else {
			responsePacket.Attributes.Set(80, calculatedMAC)
		}
	}
	// ここまで来たら、正常ケースのresponsePacket完成。
	// RADIUS ResponsePacketをw.Write()する。
	writingErr := w.Write(responsePacket)
	if writingErr != nil {
		slog.Error("[RADIUS] Response message failed to send /", "RespMsg", responsePacket.Code, "RespId", fmt.Sprintf("0x%X", responsePacket.Identifier), "error", writingErr)
	} else {
		slog.Info("[RADIUS] Response message send /", "RespMsg", responsePacket.Code, "RespId", fmt.Sprintf("0x%X", responsePacket.Identifier), "send_to", r.RemoteAddr)
	}
}
