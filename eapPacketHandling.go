package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/wmnsk/milenage"
)

func encodeEapPacketChallenge(akaFlag byte, ki, opc, rand, sqn, amf, kAut []byte) ([]byte, int64, error) {
	slog.Debug("[EAP-Server] AKA-Challenge construction /", "process", "start")
	var timeStamp int64
	eapPk := []byte{}
	// Type of argument "SQN"/"AMF" in "milenage" package is uint64/uint16, it needs to change from byte slice to these type.
	sqnByte := make([]byte, 8)
	_ = copy(sqnByte[2:8], sqn)
	sqn64 := binary.BigEndian.Uint64(sqnByte)
	amf16 := binary.BigEndian.Uint16(amf)
	mil := milenage.NewWithOPc(ki, opc, rand, sqn64, amf16)
	comPuteErr := mil.ComputeAll()
	if comPuteErr != nil {
		slog.Error("[EAP-Server] milenage computeAll for EAP packet failed /", "error", comPuteErr)
		return eapPk, timeStamp, comPuteErr
	}
	autnData, autnGenErr := mil.GenerateAUTN()
	if autnGenErr != nil {
		slog.Error("[EAP-Server] milenage generate AUTN data for EAP packet failed /", "error", autnGenErr)
		return eapPk, timeStamp, autnGenErr
	}
	// Start derivation process of "AT_xxx".
	atRand := make([]byte, 20)
	_ = copy(atRand[0:4], []byte{0x01, 0x05, 0x00, 0x00})
	_ = copy(atRand[4:20], rand)
	slog.Debug("[EAP-Server] generate /", "AT_RAND", fmt.Sprintf("0x%X", atRand))
	atAutn := make([]byte, 20)
	_ = copy(atAutn[0:4], []byte{0x02, 0x05, 0x00, 0x00})
	_ = copy(atAutn[4:20], autnData)
	slog.Debug("[EAP-Server] generate /", "AT_AUTN", fmt.Sprintf("0x%X", atAutn))
	atMac := make([]byte, 20)
	_ = copy(atMac[0:4], []byte{0x0B, 0x05, 0x00, 0x00})
	// Case divided by EAP-AKA(23) and EAP-AKA'(50) due to difference of AT_MAC derivation and presence of AT_KDF/AT_KDF_INPUT.
	switch akaFlag {
	case 23:
		eapPktTemp := make([]byte, 68)
		genId := generateEAPId()
		t := time.Now()
		timeStamp = t.Unix()
		_ = copy(eapPktTemp[:8], []byte{0x01, genId, 0x00, 0x44, 0x17, 0x01, 0x00, 0x00})
		_ = copy(eapPktTemp[8:28], atRand)
		_ = copy(eapPktTemp[28:48], atAutn)
		_ = copy(eapPktTemp[48:68], atMac)
		atMacData := calculateAtMACdataForAka(kAut, eapPktTemp)
		_ = copy(atMac[4:20], atMacData)
		_ = copy(eapPktTemp[48:68], atMac)
		slog.Debug("[EAP-Server] generate /", "AT_MAC", fmt.Sprintf("0x%X", atMac))
		eapPk = eapPktTemp
	case 50:
		// AT_KDF generation
		atKdf := []byte{0x18, 0x01, 0x00, 0x01}
		slog.Debug("[EAP-Server] generate /", "AT_KDF", fmt.Sprintf("0x%X", atKdf))
		// AT_KDF_INPUT generation
		atKdfInput, err := generateAtKdfInput(conf.atKDFInput)
		if err != nil {
			slog.Error("[EAP-Server] generate failure / AT_KDF_INPUT /", "error", err)
			return eapPk, timeStamp, err
		}
		slog.Debug("[EAP-Server] generate /", "AT_KDF_INPUT", fmt.Sprintf("0x%X", atKdfInput))
		eapPktLen := len(atKdfInput) + 72
		lenUintOneSix := intToByteArray(eapPktLen)
		eapPktTemp := make([]byte, eapPktLen)
		genId := generateEAPId()
		t := time.Now()
		timeStamp = t.Unix()
		_ = copy(eapPktTemp[:8], []byte{0x01, genId, lenUintOneSix[0], lenUintOneSix[1], 0x32, 0x01, 0x00, 0x00})
		_ = copy(eapPktTemp[8:28], atRand)
		_ = copy(eapPktTemp[28:48], atAutn)
		_ = copy(eapPktTemp[48:68], atMac)
		_ = copy(eapPktTemp[68:72], atKdf)
		_ = copy(eapPktTemp[72:eapPktLen], atKdfInput)
		atMacData := calculateAtMACdataForAkaP(kAut, eapPktTemp)
		_ = copy(atMac[4:20], atMacData)
		_ = copy(eapPktTemp[48:68], atMac)
		slog.Debug("[EAP-Server] generate /", "AT_MAC", fmt.Sprintf("0x%X", atMac))
		eapPk = eapPktTemp
	default:
		slog.Error("[EAP-Server] invalid argument /", "akaFlag", fmt.Sprintf("0x%X", akaFlag))
		return eapPk, timeStamp, autnGenErr
	}
	slog.Debug("[EAP-Server] AKA-Challenge construction /", "process", "end")
	return eapPk, timeStamp, nil
}

func generateAtKdfInput(nwName string) ([]byte, error) {
	nameLen := len(nwName)
	if nameLen == 0 {
		slog.Error("[EAP-Server] Network Name seems to be empty /", "length", nameLen)
		return nil, fmt.Errorf("empty netwrok name")
	}
	lengthBlock := (nameLen + 3) / 4
	if lengthBlock > 255 {
		slog.Error("[EAP-Server] Network Name is too long /", "length", nameLen)
		return nil, fmt.Errorf("netwrok name is too long")
	}
	nwNameLen := intToByteArray(nameLen)
	atKdfInput := make([]byte, (lengthBlock+1)*4)
	_ = copy(atKdfInput[0:4], []byte{0x17, byte(lengthBlock + 1), nwNameLen[0], nwNameLen[1]})
	_ = copy(atKdfInput[4:nameLen+4], []byte(nwName))
	return atKdfInput, nil
}

func intToByteArray(i int) []byte {
	r := make([]byte, 2)
	binary.BigEndian.PutUint16(r, uint16(i))
	return r
}

func calculateAtMACdataForAkaP(kAut []byte, input []byte) []byte {
	h := hmac.New(sha256.New, kAut)
	if _, err := h.Write(input); err != nil {
		slog.Error("[EAP-Server] AT_MAC calculation for EAP-AKA' failed /", "error", err)
	}
	sum := h.Sum(nil)
	return sum[:16]
}

func calculateAtMACdataForAka(kAut []byte, input []byte) []byte {
	h := hmac.New(sha1.New, kAut)
	if _, err := h.Write(input); err != nil {
		slog.Error("[EAP-Server] AT_MAC calculation for EAP-AKA failed /", "error", err)
	}
	sum := h.Sum(nil)
	return sum[:16]
}

// This function returns Value part of "AT_xxx" in TypeData of EAP Packet. (it means that no Type and Length included)
// And it is in case of "EAP-Response/AKA-Challenge" or "EAP-Response/AKA-Synchronization-Failure", so AT_RES, AT_AUTS, AT_MAC, AT_CHCEKCODE, AT_KDF return if they are included.
// if no included, it returns nil slice.
func decodeEapTypeData(typeData []byte) (atResData, atMacData, atCheckcodeData, atAutsData []byte, err error) {
	slog.Debug("[EAP-Server] AKA-Challenge or AKA-Synch-Fail decode /", "process", "start")
	var data []byte
	switch typeData[0] {
	case 0x01:
		slog.Debug("[EAP-Server] targer packet is AKA-Challenge /", "SubType_value", fmt.Sprintf("0x%X", typeData[0]))
	case 0x04:
		slog.Debug("[EAP-Server] targer packet is AKA-Synchronization-Failure /", "SubType_value", fmt.Sprintf("0x%X", typeData[0]))
	default:
		slog.Error("[EAP-Server] targer packet is not AKA-Challenge or AKA-Synch-Fail /", "SubType_value", fmt.Sprintf("0x%X", typeData[0]))
		return nil, nil, nil, nil, fmt.Errorf("invalid subtype found")
	}
	data = typeData[3:]
	slog.Debug("[EAP-Server] AT_xxx decoding target /", "data", fmt.Sprintf("0x%X", data))
	dataLen := len(data)
	if dataLen < 4 {
		slog.Error("[EAP-Server] AKA-Challenge/AKA-Synch-Fail from UE/STA decoding error", "length", dataLen)
		return nil, nil, nil, nil, fmt.Errorf("data length too short")
	}
	var atIdentified byte
	atResDecoded := false
	atMacDecoded := false
	atCheccodeDecoded := false
	atAutsDecoded := false
	for i := 0; i < dataLen; {
		atIdentified = data[i]
		slog.Debug("[EAP-Server] AT_xxx decode /", "Tag", fmt.Sprintf("0x%X", atIdentified))
		switch atIdentified {
		case 3: // AT_RES
			if atResDecoded {
				slog.Warn("[EAP-Server] multi AT_RES detected /", "byte_index", i)
				i = i + (int(data[i+1]) * 4)
				break
			}
			resActualLen := binary.BigEndian.Uint16(data[i+2 : i+4])
			// Lenth of RES is flexible in standard spec, but this part set fixed 64bit temporary.
			atResData = data[i+4 : i+int(resActualLen/8)+4]
			slog.Debug("[EAP-Server] AT_RES decoded /", "data", fmt.Sprintf("0x%X", atResData))
			atResDecoded = true
			i = i + (int(data[i+1]) * 4)
		case 4: // AT_AUTS
			if atAutsDecoded {
				slog.Warn("[EAP-Server] multi AT_AUTS detected /", "byte_index", i)
				i = i + (int(data[i+1]) * 4)
				break
			}
			atAutsData = data[i+2 : i+16]
			slog.Debug("[EAP-Server] AT_AUTS decoded /", "data", fmt.Sprintf("0x%X", atAutsData))
			atAutsDecoded = true
			i = i + (int(data[i+1]) * 4)
		case 11: // AT_MAC
			if atMacDecoded {
				slog.Warn("[EAP-Server] multi AT_MAC detected /", "byte_index", i)
				i = i + (int(data[i+1]) * 4)
				break
			}
			atMacData = data[i+4 : i+20]
			slog.Debug("[EAP-Server] AT_MAC decoded /", "data", fmt.Sprintf("0x%X", atMacData))
			atMacDecoded = true
			i = i + (int(data[i+1]) * 4)
		case 134: // AT_CHECKCODE
			if atCheccodeDecoded {
				slog.Warn("[EAP-Server] multi AT_CHECKCODE detected", "byte_index", i)
				i = i + (int(data[i+1]) * 4)
				break
			}
			chkcodeActualLen := (int(data[i+1]) * 4) - 4
			if chkcodeActualLen == 0 {
				atCheckcodeData = []byte{}
				slog.Debug("[EAP-Server] AT_CHECKCODE decoded but no check code /", "data", "(null)")
			} else {
				atCheckcodeData = data[i+4 : i+chkcodeActualLen]
				slog.Debug("[EAP-Server] AT_CHECKCODE decoded /", "data", fmt.Sprintf("0x%X", atCheckcodeData))
			}
			atCheccodeDecoded = true
			i = i + (int(data[i+1]) * 4)
		default: // others
			atData := data[i+2 : i+(int(data[i+1])*4)]
			slog.Debug("[EAP-Server] other AT_xxx detected /", "type", fmt.Sprintf("0x%X", data[i]), "length", fmt.Sprintf("0x%X", data[i+1]), "data", fmt.Sprintf("0x%X", atData))
			i = i + (int(data[i+1]) * 4)
		}
	}
	return atResData, atMacData, atCheckcodeData, atAutsData, nil
}
