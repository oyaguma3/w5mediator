package main

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

const (
	case01  = "EAP-Response/Identity"
	case11  = "EAP-Response/AKA-Identity"
	case12  = "EAP-Response/AKA'-Identity"
	case13  = "EAP-Response/AKA-Challenge"
	case14  = "EAP-Response/AKA'-Challenge"
	case15  = "EAP-Response/AKA-Authentication-Reject"
	case16  = "EAP-Response/AKA'-Authentication-Reject"
	case17  = "EAP-Response/AKA-Synchronization-Failure"
	case18  = "EAP-Response/AKA'-Synchronization-Failure"
	case19  = "EAP-Response/AKA-Client-Error"
	case20  = "EAP-Response/AKA'-Client-Error"
	case253 = "invalid EAP code"
	case254 = "invalid or unsupported EAP type"
	case255 = "invalid or unsupported EAP subtype"
)

// 受信したRadiusパケットのSourceアドレスが、設定した許容IPアドレスと一致しているか確認する。
func isSrcAddrValid(remoteAddr string) bool {
	var result bool
	chkAddr, _, _ := strings.Cut(remoteAddr, ":")
	if !(chkAddr == conf.allowedClientAddress) {
		result = false
		slog.Warn("[radutl] Client IP Address not Allowed /", "source_address", remoteAddr)
	} else {
		result = true
	}
	return result
}

// Proxy-StateやEAP-Messageなど、同一Typeに複数のAttributeが存在する場合のAttritube抽出を行う。
// 引数に対象Radiusパケットとradius.Type型（実利用時はintをそのまま入れる)を指定する。
// 指定したTypeが存在しない場合、nilとfalseが返る。存在すれば、map型で値が戻ってtrueが入る。
func multiAttrGet(rp *radius.Packet, t radius.Type) (map[int][]byte, bool) {
	attrSet := map[int][]byte{}
	var isExist bool
	num := 0
	for in := 0; in < len(rp.Attributes); in++ {
		if rp.Attributes[in].Type == t {
			attrSet[num] = rp.Attributes[in].Attribute
			num++
		}
	}
	if len(attrSet) > 0 {
		isExist = true
	}
	slog.Debug("[radutl] multi attribute existence check /", "attribute_type", t, "count", num)
	return attrSet, isExist
}

// 引数のRADIUSパケットからMessage-Authenticatorを算出する。Message-Authenticatorが含まれていなければエラーとなる。
// 戻り値は「期待するMessage-AuthenticatorのByteスライス」である。
// なお、Responseパケットに適切なMessage-Authenticatorを追加するための算出で使うには、引数に取るResponseパケットに
// あらかじめresponsePacket.Attributes.Add(80, msgAuthOverwriteZero)等でAttributeを追加しておく必要があることに注意。
func messageAuthenticatorCalc(rp *radius.Packet, sharedSecret string) ([]byte, error) {
	slog.Debug("[radutl] Message-Authenticator AVP calculation", "process", "start")
	expectedMAC := []byte{}
	var err error
	byteSS := []byte(sharedSecret)
	_, msgAuthLookUpErr := rfc2869.MessageAuthenticator_Lookup(rp)
	if msgAuthLookUpErr != nil {
		slog.Error("[radutl] Message-Authenticator for calculation not found /", "error", msgAuthLookUpErr)
		err = msgAuthLookUpErr
		return expectedMAC, err
	}
	chBytes, chBytesErr := rp.MarshalBinary()
	if chBytesErr != nil {
		slog.Error("[radutl] RADIUS packet marshaling error for Message-Authenticator calculation /", "error", chBytesErr)
		err = chBytesErr
		return expectedMAC, err
	}
	mac := hmac.New(md5.New, byteSS)
	mac.Write(chBytes)
	expectedMAC = mac.Sum(nil)
	slog.Debug("[radutl] Message-Authenticator calculated /", "value", fmt.Sprintf("%X", expectedMAC))
	return expectedMAC, nil
}

// Message-Authenticatorを算出してチェックする。計算したいRadiusパケット（のポインタ）とShared Secretを引数に取る。
// チェックOKであればerr=nilで返し、NGならerrに何らかのエラーを入れて返す。
func messageAuthenticatorCheck(rp *radius.Packet, sharedSecret string) error {
	slog.Debug("[radutl] Message-Authenticator AVP check", "process", "start")
	var err error
	byteSS := []byte(sharedSecret)
	msgAuth, msgAuthLookUpErr := rfc2869.MessageAuthenticator_Lookup(rp)
	if msgAuthLookUpErr != nil {
		slog.Error("[radutl] Message-Authenticator for check not found /", "error", msgAuthLookUpErr)
		err = msgAuthLookUpErr
		return err
	}
	var chPkt *radius.Packet = rp
	zeroPadding := make([]byte, 16)
	chPkt.Attributes.Set(80, zeroPadding)
	chBytes, chBytesErr := chPkt.MarshalBinary()
	if chBytesErr != nil {
		slog.Error("[radutl] RADIUS packet marshaling error for Message-Authenticator check /", "error", chBytesErr)
		err = chBytesErr
		return err
	}
	mac := hmac.New(md5.New, byteSS)
	mac.Write(chBytes)
	expectedMAC := mac.Sum(nil)
	matchResult := hmac.Equal(expectedMAC, msgAuth)
	if !matchResult {
		slog.Error("[radutl] Message-Authenticator check failure / ", "error", "not matched", "expected", fmt.Sprintf("%X", expectedMAC), "received", fmt.Sprintf("%X", msgAuth))
		err = fmt.Errorf("message authenticator not matched")
		return err
	}
	slog.Debug("[radutl] Message-Authenticator check success", "expected", fmt.Sprintf("%X", expectedMAC), "received", fmt.Sprintf("%X", msgAuth))
	return nil
}

// radiusパケットからEAP-Message有無を確認し、あればeapPacketSourceにデコード結果（のlayers.EAP構造体）を返す。
// なお、この関数にはEAP-Messageがある場合のMessage-Authenticatorチェック処理も含まれている。
func isEAPMessageIncluded(r *radius.Request) (*layers.EAP, bool, error) {
	slog.Debug("[radutl] EAP-Message AVP existence check", "process", "start")
	eapPktSrc := new(layers.EAP)
	var included bool = false
	var df gopacket.DecodeFeedback
	var returnAttr79 radius.Attribute
	returnAttr79, _ = r.Packet.Attributes.Lookup(79)
	if returnAttr79 == nil {
		included = false
		err := fmt.Errorf("eap-message not found")
		return eapPktSrc, included, err
	} else {
		included = true
	}
	slog.Info("[radutl] EAP-Message AVP found /", "included", included)
	slog.Debug("[radutl] EAP-Message AVP found /", "raw_data", fmt.Sprintf("%X", returnAttr79))
	msgAuthChkErr := messageAuthenticatorCheck(r.Packet, conf.sharedSecret)
	if msgAuthChkErr != nil {
		err := msgAuthChkErr
		included = true
		return eapPktSrc, included, err
	}
	decodeErr := eapPktSrc.DecodeFromBytes(returnAttr79, df)
	if decodeErr != nil {
		err := msgAuthChkErr
		included = true
		slog.Error("[radutl] EAP Packet decoding failure for check", "error", msgAuthChkErr)
		return eapPktSrc, included, err
	}
	slog.Debug("EAP Packet :", "Code", fmt.Sprintf("%X", eapPktSrc.Code))
	slog.Debug("EAP Packet :", "Id", fmt.Sprintf("%X", eapPktSrc.Id))
	slog.Debug("EAP Packet :", "Length", fmt.Sprintf("%X", eapPktSrc.Length))
	slog.Debug("EAP Packet :", "EAPType", fmt.Sprintf("%X", eapPktSrc.Type))
	slog.Debug("EAP Packet :", "TypeData", fmt.Sprintf("%X", eapPktSrc.TypeData))
	slog.Debug("[radutl] EAP-Message AVP existence check /", "process", "end")
	return eapPktSrc, included, nil
}

// 受信したRADIUSパケットに含まれるEAP-Message AVPから、どの処理ケースに該当するかを識別する。
func reqCaseCategorize(ep *layers.EAP) uint8 {
	slog.Debug("[radutl] case categorize /", "process", "start")
	var caseNumber uint8
	ec := ep.Code
	et := ep.Type
	var est uint8 = ep.TypeData[0]
	if ec != 2 {
		caseNumber = 253
		slog.Warn("[radutl] case categorized /", "case", case253)
		slog.Debug("[radutl] EAP Code /", "value", fmt.Sprintf("0x%X", ec))
		slog.Debug("[radutl] EAP Type /", "value", fmt.Sprintf("0x%X", et))
		slog.Debug("[radutl] EAP SubType/ ", "value", fmt.Sprintf("0x%X", est))
		return caseNumber
	}
	switch et {
	case 1:
		caseNumber = 1
		slog.Info("[radutl] case categorized /", "case", case01)
	case 23:
		switch est {
		case 1:
			caseNumber = 13
			slog.Info("[radutl] case categorized /", "case", case13)
		case 2:
			caseNumber = 15
			slog.Info("[radutl] case categorized /", "case", case15)
		case 4:
			caseNumber = 17
			slog.Info("[radutl] case categorized /", "case", case17)
		case 5:
			caseNumber = 11
			slog.Info("[radutl] case categorized /", "case", case11)
		case 14:
			caseNumber = 19
			slog.Warn("[radutl] case categorized /", "case", case19)
		default:
			caseNumber = 255
			slog.Warn("[radutl] case categorized /", "case", case255)
		}
	case 50:
		switch est {
		case 1:
			caseNumber = 14
			slog.Info("[radutl] case categorized.", "case", case14)
		case 2:
			caseNumber = 16
			slog.Info("[radutl] case categorized.", "case", case16)
		case 4:
			caseNumber = 18
			slog.Info("[radutl] case categorized.", "case", case18)
		case 5:
			caseNumber = 12
			slog.Info("[radutl] case categorized.", "case", case12)
		case 14:
			caseNumber = 20
			slog.Warn("[radutl] case categorized.", "case", case20)
		default:
			caseNumber = 255
			slog.Warn("[radutl] case categorized.", "case", case255)
		}
	default:
		caseNumber = 254
		slog.Warn("[radutl] case categorized /", "case", case254)
		slog.Debug("EAP Code :", "value", fmt.Sprintf("0x%X", ec))
		slog.Debug("EAP Type :", "value", fmt.Sprintf("0x%X", et))
		slog.Debug("EAP SubType :", "value", fmt.Sprintf("0x%X", est))
	}
	return caseNumber
}

// EAP-IdentityやAKA-Identityで受領したuser@realmのバリデーションチェック用関数。
// realm部分は、設定ファイルで指定したPLMNに対するチェックも実施している。
// user部分はaka/aka'判別も実施しており、戻り値1でEAP Type(23か50)を返すようにしている。
// 戻り値2はIMSIを返すが、この関数実行後にUDR問い合わせる想定なのでstringで返している。
func identityValidationCheck(id []byte, plmnList string) (byte, string, error) {
	slog.Debug("[radutl] identity validation check /", "process", "start", "identity", fmt.Sprintf("%v", string(id)))
	var akaFlag byte = 0
	var imsi string
	var chkErr error
	formerPart, latterPart, chk := strings.Cut(string(id), "@")
	slog.Debug("[radutl] user|realm part divided /", "user", formerPart, "realm", latterPart)
	if !chk {
		slog.Error("[radutl] unknown or unsupported identity /", "value", fmt.Sprintf("%v", string(id)))
		chkErr = fmt.Errorf("unknown or unsupported identity")
		return akaFlag, imsi, chkErr
	}
	latterPartChk := realmValidationCheck(latterPart, plmnList)
	if !latterPartChk {
		slog.Error("[radutl] Realm check failed /", "value", fmt.Sprintf("%v", string(id)))
		chkErr = fmt.Errorf("invalid realm found in identity")
		return akaFlag, imsi, chkErr
	}
	akaFlag, imsi, formerPartChk := userValidationCheck(formerPart)
	if formerPartChk != nil {
		slog.Error("[radutl] User part check failed /", "value", fmt.Sprintf("%v", string(id)))
		chkErr = fmt.Errorf("invalid user part in identity")
		return akaFlag, imsi, chkErr
	}
	slog.Debug("[radutl] identity validation check success /", "process", "end")
	return akaFlag, imsi, chkErr
}

// Identityチェックのうち、user部分のバリデーションチェックを行う関数。
func userValidationCheck(formerPart string) (byte, string, error) {
	slog.Debug("[radutl] identity for user part validation check /", "process", "start", "userPart", formerPart)
	var eapType byte
	var imsi string
	var userChk error
	switch {
	case len(formerPart) == 16 && formerPart[0] == 0x30:
		eapType = 23
	case len(formerPart) == 16 && formerPart[0] == 0x36:
		eapType = 50
	case formerPart[0] == 0x37 || formerPart[0] == 0x38:
		eapType = 8
		imsi = formerPart
		slog.Info("[radutl] User part seems to be Pseudonym or Fast-Reauth case for EAP-AKA prime /", "value", formerPart)
		slog.Debug("[radutl] identity for user part validation check /", "process", "end")
		return eapType, imsi, userChk
	case len(formerPart) == 16 && formerPart[0] == 0x31:
		eapType = 18
		slog.Warn("[radutl] User part seems to be EAP-SIM identity /", "value", formerPart)
	default:
		eapType = 7
		imsi = formerPart
		slog.Info("[radutl] User part seems to be Pseudonym or Fast-Reauth case /", "value", formerPart)
		slog.Debug("[radutl] identity for user part validation check /", "process", "end")
		return eapType, imsi, userChk
	}
	imsi = formerPart[1:16]
	_, err := strconv.Atoi(imsi)
	if err != nil {
		slog.Error("[radutl] User part contains invalid imsi value /", "value", imsi)
		userChk := fmt.Errorf("invalid imsi")
		return eapType, imsi, userChk
	}
	slog.Debug("[radutl] IMSI in User part /", "imsi", imsi)
	slog.Debug("[radutl] identity for user part validation check /", "process", "end")
	return eapType, imsi, userChk
}

// Identityチェックのうち、realm部分のバリデーションチェックを行う関数。
// 有効ならtrue、無効ならfalseを返す。
func realmValidationCheck(latterPart, list string) bool {
	slog.Debug("[radutl] identity for realm part validation check /", "process", "start", "realmPart", latterPart)
	var realmChk bool
	latterPartLen := len(latterPart)
	if latterPartLen != 34 {
		slog.Error("[radutl] unacceptable realm : length /", "value", latterPart)
		realmChk = false
		return realmChk
	}
	latterPartElement := strings.SplitN(latterPart, ".", 4)
	if !(latterPartElement[0] == "wlan" && latterPartElement[3] == "3gppnetwork.org") {
		slog.Error("[radutl] unacceptable realm : domain /", "value", latterPart)
		realmChk = false
		return realmChk
	}
	latterPartElementMNClen := len(latterPartElement[1])
	latterPartElementMCClen := len(latterPartElement[2])
	if !(latterPartElementMNClen == 6 && latterPartElementMCClen == 6) {
		slog.Error("[radutl] unacceptable realm : invalid PLMN length /", "value", latterPart)
		realmChk = false
		return realmChk
	}
	mcc := latterPartElement[2][3:6]
	// ver.1時点ではハードコーディングしているが、将来的にはw5confから取得させる。
	specialMCCList := []string{"441", "999", "310"}
	listLen := len(specialMCCList)
	threeDigitMNC := false
	for i := 0; i < listLen; i++ {
		if mcc == specialMCCList[i] {
			threeDigitMNC = true
			break
		}
	}
	var mnc string
	if threeDigitMNC {
		mnc = latterPartElement[1][3:6]
	} else {
		mnc = latterPartElement[1][4:6]
	}
	plmn := mcc + "-" + mnc
	slog.Debug("[radutl] PLMN in user part", "value", plmn)
	plmnList := strings.Split(strings.ReplaceAll(list, " ", ""), ",")
	slog.Debug("[radutl] PLMN List from w5conf /", "list", plmnList)
	plmnListLen := len(plmnList)
	var plmnMatch bool
	for i := 0; i < plmnListLen; i++ {
		if plmn == plmnList[i] {
			plmnMatch = true
			break
		}
	}
	if !plmnMatch {
		slog.Error("[radutl] identity for realm part validation check error /", "error", "plmn not matched in allowed plmn list")
		realmChk = false
		return realmChk
	}
	slog.Debug("[radutl] identity for realm part validation check /", "process", "end")
	return true
}
