package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/wmnsk/milenage"
)

func actionEapIdentity(caseId byte, eapPktFromC *layers.EAP) ([]byte, string, error) {
	slog.Debug("[EAP-Server] received EAP-Identity or EAP-Response_AKA-Identity /", "process", "start")
	var eapPktToC []byte
	var replyMsg string = "null"
	var err error
	var akaFlag byte
	var imsiString string
	var idChkErr error
	switch caseId {
	case 1:
		akaFlag, imsiString, idChkErr = identityValidationCheck(eapPktFromC.TypeData, conf.allowdPLMN)
		if idChkErr != nil {
			slog.Error("[EAP Server] EAP-Identity check failed /", "error", idChkErr)
			eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
			replyMsg = "invalid or unsupported identity"
			return eapPktToC, replyMsg, idChkErr
		}
		// This version doesn't support EAP-SIM and it returns EAP-Failure.
		if akaFlag == 18 {
			slog.Error("[EAP Server] EAP-Identity check failed /", "error", "parmanent EAP-SIM identity detected")
			eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
			replyMsg = "EAP-SIM not supported"
			return eapPktToC, replyMsg, fmt.Errorf("eap-sim not supported")
		}
		if akaFlag == 7 || akaFlag == 8 {
			var eapType byte
			switch akaFlag {
			case 7:
				eapType = 0x17
			case 8:
				eapType = 0x32
			}
			slog.Info("[EAP-Server] AT_FULLAUTH_ID_REQ needed /", "user", imsiString)
			eapPktToC = []byte{0x01, generateEAPId(), 0x00, 0x0c, eapType, 0x05, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00}
			replyMsg = "FULLAUTH"
			return eapPktToC, replyMsg, err
		}
	case 11, 12:
		idActualLen := binary.BigEndian.Uint16(eapPktFromC.TypeData[2:4])
		atIdentity := eapPktFromC.TypeData[8 : idActualLen+8]
		akaFlag, imsiString, idChkErr = identityValidationCheck(atIdentity, conf.allowdPLMN)
		if idChkErr != nil {
			slog.Error("[EAP Server] AT_IDENTITY check failed /", "error", idChkErr)
			eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
			replyMsg = "invalid or unsupported identity"
			return eapPktToC, replyMsg, idChkErr
		}
		switch akaFlag {
		case 7, 8:
			slog.Error("[EAP Server] AT_IDENTITY check failed /", "error", "unknown identity", "identity", imsiString)
			eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
			replyMsg = "unknown identity"
			return eapPktToC, replyMsg, fmt.Errorf("unknown identity")
		default:
			slog.Error("[EAP Server] AT_IDENTITY check failed /", "error", "unspecified", "identity", imsiString)
			eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
			replyMsg = "EAP-Server process error"
			return eapPktToC, replyMsg, fmt.Errorf("unspecified")
		}
	default:
		slog.Error("[EAP-Server] undefined case /", "caseId", fmt.Sprintf("0x%X", caseId))
		eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
		replyMsg = "EAP-Server process error"
		return eapPktToC, replyMsg, fmt.Errorf("undefined case")
	}
	ki, opc, sqn, amf, authSubscGetErr := authSubscGet(imsiString, conf.udrAddress, conf.apiVersion, conf.responseBodyType)
	if authSubscGetErr != nil {
		slog.Error("[EAP Server] Getting key info failed /", "imsi", imsiString, "error", authSubscGetErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}

	thisCaseId := string(eapPktFromC.TypeData)
	updInfo := initializeSubscInfo(thisCaseId)

	rnd, rndGenErr := generateRAND()
	if rndGenErr != nil {
		slog.Error("[EAP-Server] generating RAND failed /", "error", rndGenErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}

	sqnByte := make([]byte, 8)
	_ = copy(sqnByte[2:8], sqn)
	sqn64 := binary.BigEndian.Uint64(sqnByte)
	amf16 := binary.BigEndian.Uint16(amf)
	mil := milenage.NewWithOPc(ki, opc, rnd, sqn64, amf16)
	resV, ckV, ikV, akV, milErr := mil.F2345()
	if milErr != nil {
		slog.Error("[EAP-Server] Milenage F2345 calculation failed /", "error", milErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}
	var kAut []byte
	var mskV []byte
	switch akaFlag {
	case 23:
		_, kAutTemp, mskTemp, _ := akaCalc(eapPktFromC.TypeData, ikV, ckV)
		kAut = kAutTemp
		mskV = mskTemp
	case 50:
		ckP, ikP := deriveCKIKPrime(ckV, ikV, sqn, akV, conf.nwNameForKDF)
		_, kAutTemp, _, mskTemp, _, akaPrimErr := akaPrimeCalc(ikP, ckP, thisCaseId)
		if akaPrimErr != nil {
			slog.Error("[EAP-Server] MSK derivation failed /", "error", akaPrimErr)
			eapPktToC, replyMsg, err = eapServerFailTemplate()
			deleteSubscInfo(thisCaseId)
			return eapPktToC, replyMsg, err
		}
		kAut = kAutTemp
		mskV = mskTemp
	default:
		slog.Error("[EAP-Server] MSK derivation failed /", "error", "invalid akaFlag", "akaFlag", fmt.Sprintf("0x%X", akaFlag))
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}

	updInfo.akaFlag = akaFlag
	updInfo.ki = ki
	updInfo.opc = opc
	updInfo.sqn = sqn
	updInfo.amf = amf
	updInfo.rand = rnd
	updInfo.res = resV
	updInfo.msk = mskV
	allUpdateErr := setAllSubscInfo(thisCaseId, updInfo)
	if allUpdateErr != nil {
		slog.Error("[EAP-Server] SubscInfo update failed /", "id", thisCaseId, "error", allUpdateErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}
	sqnStr, sqnIncrErr := sqnIncrement(sqn)
	if sqnIncrErr != nil {
		slog.Error("[EAP-Server] SQN increment process failed /", "id", thisCaseId, "error", sqnIncrErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}
	sqnUpdateErr := sqnUdrUpdate(imsiString, conf.udrAddress, conf.apiVersion, sqnStr)
	if sqnUpdateErr != nil {
		slog.Error("[EAP-Server] SQN-UDR update failed /", "id", thisCaseId, "error", sqnUpdateErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}
	eapPktToC, unixTimeNow, encodeErr := encodeEapPacketChallenge(updInfo.akaFlag, updInfo.ki, updInfo.opc, updInfo.rand, updInfo.sqn, updInfo.amf, kAut)
	if encodeErr != nil {
		slog.Error("[EAP-Server] EAP Packet construction failure /", "error", encodeErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}
	slog.Debug("[EAP-Server] EAP packet construction success /", "eapId", fmt.Sprintf("0x%X", eapPktToC[1]))
	eapIdStoreErr := eapIdTableStore(eapPktToC[1], thisCaseId, unixTimeNow)
	if eapIdStoreErr != nil {
		slog.Error("[EAP-Server] EAP-ID Table store failed /", "id", thisCaseId, "error", eapIdStoreErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(thisCaseId)
		return eapPktToC, replyMsg, err
	}
	return eapPktToC, replyMsg, err
}

func actionEapRespAkaChallenge(caseId byte, eapPktFromC *layers.EAP) ([]byte, string, error) {
	slog.Debug("[EAP-Server] Authentication vector verification start /", "caseId", fmt.Sprintf("0x%X", caseId))
	var eapPktToC []byte
	var replyMsg string = "null"
	var err error
	eapPktAll := []byte(string(eapPktFromC.BaseLayer.Contents) + string(eapPktFromC.BaseLayer.Payload))
	atResData, atMacData, _, _, decodeErr := decodeEapTypeData(eapPktFromC.TypeData)
	if decodeErr != nil {
		slog.Error("[EAP Server] EAP packet decoding failure /", "error", decodeErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}
	identity, _, loadErr := eapIdTableLoad(eapPktFromC.Id)
	if loadErr != nil {
		slog.Error("[EAP Server] identity bound with EAP-ID loading failure /", "error", loadErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}
	info, exist := loadSubscInfo(identity)
	if !exist {
		slog.Error("[EAP Server] AV verification process failed / no user information /", "identity", identity)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}

	sqnByte := make([]byte, 8)
	_ = copy(sqnByte[2:8], info.sqn)
	sqn64 := binary.BigEndian.Uint64(sqnByte)
	amf16 := binary.BigEndian.Uint16(info.amf)
	mil := milenage.NewWithOPc(info.ki, info.opc, info.rand, sqn64, amf16)
	xres, ckV, ikV, akV, milErr := mil.F2345()
	if milErr != nil {
		slog.Error("[EAP-Server] Milenage F2345 calculation failed /", "error", milErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	if !(string(xres) == string(atResData)) {
		slog.Warn("[EAP-Server] XRES/RES not matched /", "id", identity)
		slog.Debug("[EAP-Server] XRES/RES not matched /", "XRES", fmt.Sprintf("0x%X", xres), "AT_RES_data", fmt.Sprintf("0x%X", atResData))
		eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
		replyMsg = "Authentication vector unmatched"
		err = fmt.Errorf("authentication vector unmatched")
		return eapPktToC, replyMsg, err
	}

	index := strings.Index(string(eapPktAll), string(atMacData))
	_ = copy(eapPktAll[index:index+16], make([]byte, 16))
	var xMac []byte
	switch info.akaFlag {
	case 23:
		_, kAut, _, _ := akaCalc([]byte(identity), ikV, ckV)
		xMac = calculateAtMACdataForAka(kAut, eapPktAll)
	case 50:
		ckP, ikP := deriveCKIKPrime(ckV, ikV, info.sqn, akV, conf.nwNameForKDF)
		_, kAut, _, _, _, akaPCalcErr := akaPrimeCalc(ikP, ckP, identity)
		if akaPCalcErr != nil {
			slog.Error("[EAP Server] expected MAC calculation failed /", "error", akaPCalcErr)
			eapPktToC, replyMsg, err = eapServerFailTemplate()
			return eapPktToC, replyMsg, err
		}
		xMac = calculateAtMACdataForAkaP(kAut, eapPktAll)
	default:
		slog.Error("[EAP-Server] expected MAC calculation failed /", "error", "invalid akaFlag", "akaFlag", fmt.Sprintf("0x%X", info.akaFlag))
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	if !(string(atMacData) == string(xMac)) {
		slog.Error("[EAP-Server] invalid AT_MAC /", "id", identity)
		slog.Debug("[EAP-Server] invalid AT_MAC /", "expectedMAC", fmt.Sprintf("0x%X", xMac), "AT_MAC_data", fmt.Sprintf("0x%X", atMacData))
		eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
		replyMsg = "invalid AT_MAC received"
		err = fmt.Errorf("invalid at_mac")
		return eapPktToC, replyMsg, err
	}
	eapPktToC = []byte{0x03, generateEAPId(), 0x00, 0x04}
	slog.Info("[EAP-Server] Authentication success /", "id", identity)
	return eapPktToC, replyMsg, nil
}

func actionEapRespAkaReSynch(caseId byte, eapPktFromC *layers.EAP) ([]byte, string, error) {
	slog.Debug("[EAP-Server] Re-synchronization needed /", "process", "start", "caseId", fmt.Sprintf("0x%X", caseId))
	var eapPktToC []byte
	var replyMsg string = "null"
	var err error
	_, _, _, atAutsData, decodeErr := decodeEapTypeData(eapPktFromC.TypeData)
	if decodeErr != nil {
		slog.Error("[EAP Server] EAP packet decoding failure /", "error", decodeErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}
	concSQNms := atAutsData[0:6]

	identity, _, loadErr := eapIdTableLoad(eapPktFromC.Id)
	if loadErr != nil {
		slog.Error("[EAP Server] identity bound with EAP-ID loading failure /", "error", loadErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}
	info, exist := loadSubscInfo(identity)
	if !exist {
		slog.Error("[EAP Server] AV verification process failed /", "error", "no user information", "identity", identity)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		return eapPktToC, replyMsg, err
	}

	sqnByte := make([]byte, 8)
	_ = copy(sqnByte[2:8], info.sqn)
	sqn64 := binary.BigEndian.Uint64(sqnByte)
	amf16 := binary.BigEndian.Uint16(info.amf)
	mil := milenage.NewWithOPc(info.ki, info.opc, info.rand, sqn64, amf16)
	computeAllErr := mil.ComputeAll()
	if computeAllErr != nil {
		slog.Error("[EAP-Server] Milenage full calculation failed /", "error", computeAllErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}

	sqnMS := xor(concSQNms, mil.AKS)
	sqnByte = make([]byte, 8)
	amfZero := make([]byte, 2)
	_ = copy(sqnByte[2:8], sqnMS)
	sqn64 = binary.BigEndian.Uint64(sqnByte)
	amf16 = binary.BigEndian.Uint16(amfZero)
	milResync := milenage.NewWithOPc(info.ki, info.opc, info.rand, sqn64, amf16)
	resyncComputeAllErr := milResync.ComputeAll()
	if resyncComputeAllErr != nil {
		slog.Error("[EAP-Server] Milenage full calculation failed /", "error", resyncComputeAllErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	expectedAUTS, genAutsErr := milResync.GenerateAUTS()
	if genAutsErr != nil {
		slog.Error("[EAP-Server] expected AUTS generation failed /", "error", genAutsErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	if !(string(expectedAUTS) == string(atAutsData)) {
		slog.Error("[EAP-Server] AUTS not matched /", "error", genAutsErr)
		slog.Debug("[EAP-Server] AUTS not matched /", "expectedAUTS", fmt.Sprintf("0x%X", expectedAUTS), "AT_AUTS_data", fmt.Sprintf("0x%X", atAutsData))
		eapPktToC = []byte{0x04, generateEAPId(), 0x00, 0x04}
		replyMsg = "AUTS unmathed"
		err = fmt.Errorf("auts unmathed")
		return eapPktToC, replyMsg, err
	}
	sqnMSstr, incrErr := sqnIncrement(sqnMS)
	if incrErr != nil {
		slog.Error("[EAP-Server] SQN increment for Resynch failed /", "error", incrErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	sqnMSnew, sqnReDecErr := hex.DecodeString(sqnMSstr)
	if sqnReDecErr != nil {
		slog.Error("[EAP-Server] SQN increment for Resynch failed /", "error", sqnReDecErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	slog.Debug("[EAP-Server] SQN(UDR) update for Resynch /", "before", fmt.Sprintf("0x%X", sqnMS), "after", fmt.Sprintf("0x%X", sqnMSnew))
	sqnMS = sqnMSnew
	sqnMsUpdErr := sqnUdrUpdate(identity[1:16], conf.udrAddress, conf.apiVersion, hex.EncodeToString(sqnMS))
	if sqnMsUpdErr != nil {
		slog.Error("[EAP-Server] SQN(UDR) update for Re-Synch failed /", "error", sqnMsUpdErr)
	}

	newRAND, genRndErr := generateRAND()
	if genRndErr != nil {
		slog.Error("[EAP-Server] new RAND generation failed /", "error", genRndErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	sqnByte = make([]byte, 8)
	_ = copy(sqnByte[2:8], sqnMS)
	sqn64 = binary.BigEndian.Uint64(sqnByte)
	amf16 = binary.BigEndian.Uint16(info.amf)
	milFinal := milenage.NewWithOPc(info.ki, info.opc, newRAND, sqn64, amf16)
	milFinalErr := milFinal.ComputeAll()
	if milFinalErr != nil {
		slog.Error("[EAP-Server] Milenage full calculation failed /", "error", milFinalErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}

	var kAut []byte
	var msk []byte
	switch info.akaFlag {
	case 23:
		_, kAut, msk, _ = akaCalc([]byte(identity), milFinal.IK, milFinal.CK)
	case 50:
		ckP, ikP := deriveCKIKPrime(milFinal.CK, milFinal.IK, milFinal.SQN, milFinal.AK, conf.nwNameForKDF)
		_, kAutTemp, _, mskTemp, _, akaPCalcErr := akaPrimeCalc(ikP, ckP, identity)
		if akaPCalcErr != nil {
			slog.Error("[EAP Server] K_Aut for EAP-AKA' ReSynch derivation is failed /", "error", akaPCalcErr)
			eapPktToC, replyMsg, err = eapServerFailTemplate()
			return eapPktToC, replyMsg, err
		}
		kAut = kAutTemp
		msk = mskTemp
	default:
		slog.Error("[EAP-Server] K_Aut for ReSynch derivation is failed /", "error", "invalid akaFlag", "akaFlag", fmt.Sprintf("0x%X", info.akaFlag))
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	eapPktToCreSynch, timeStamp, resyncPktErr := encodeEapPacketChallenge(info.akaFlag, info.ki, info.opc, newRAND, sqnMS, info.amf, kAut)
	if resyncPktErr != nil {
		slog.Error("[EAP-Server] EAP Packet construction for ReSynch is failed /", "error", resyncPktErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	slog.Debug("[EAP-Server] EAP packet construction for Resynch success /", "eapId", fmt.Sprintf("0x%X", eapPktToCreSynch[1]))
	eapIdStoreErr := eapIdTableStore(eapPktToCreSynch[1], identity, timeStamp)
	if eapIdStoreErr != nil {
		slog.Error("[EAP-Server] EAP-ID Table store failed /", "id", identity, "error", eapIdStoreErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	info.sqn = milFinal.SQN
	info.rand = milFinal.RAND
	info.res = milFinal.RES
	info.msk = msk
	allUpdateErr := setAllSubscInfo(identity, info)
	if allUpdateErr != nil {
		slog.Error("[EAP-Server] SubscInfo update failed /", "id", identity, "error", allUpdateErr)
		eapPktToC, replyMsg, err = eapServerFailTemplate()
		deleteSubscInfo(identity)
		return eapPktToC, replyMsg, err
	}
	eapPktToC = eapPktToCreSynch
	return eapPktToC, replyMsg, nil
}

func actionEapFail(caseId byte) ([]byte, string) {
	slog.Debug("[EAP-Server] EAP-Failure due to error/reject in UE/STA side /", "caseId", fmt.Sprintf("0x%X", caseId))
	var reply string = "null"
	eapFailurePacket := []byte{0x04, generateEAPId(), 0x00, 0x04}
	switch caseId {
	case 15:
		reply = "AKA-Authentication-Reject received from UE/STA"
	case 16:
		reply = "AKA'-Authentication-Reject received from UE/STA"
	case 19:
		reply = "AKA-Client-Error received from UE/STA"
	case 20:
		reply = "AKA'-Client-Error received from UE/STA"
	default:
		slog.Warn("[EAP Server] undefined case for EAP-Failure /", "caseId", fmt.Sprintf("0x%X", caseId))
		reply = "undefined case for EAP-Failure"
	}
	return eapFailurePacket, reply
}

func actionDirectReject(caseId byte) string {
	slog.Debug("[EAP-Server] EAP-Failure due to invalid parameter /", "caseId", fmt.Sprintf("0x%X", caseId))
	var reply string = "null"
	switch caseId {
	case 0:
		reply = "nothing or invalid EAP packet"
	case 253:
		reply = "invalid EAP code"
	case 254:
		reply = "invalid or unsupported EAP type"
	case 255:
		reply = "invalid or unsupported EAP subtype"
	}
	return reply
}

func eapServerFailTemplate() ([]byte, string, error) {
	eapPktToC := []byte{0x04, generateEAPId(), 0x00, 0x04}
	replyMsg := "EAP-Server failure"
	err := fmt.Errorf("eap-server failure")
	return eapPktToC, replyMsg, err
}

func xor(b1, b2 []byte) []byte {
	var l int
	if len(b1)-len(b2) < 0 {
		l = len(b1)
	} else {
		l = len(b2)
	}

	// don't update b1
	out := make([]byte, l)
	for i := 0; i < l; i++ {
		out[i] = b1[i] ^ b2[i]
	}
	return out
}
