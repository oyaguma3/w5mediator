package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

// 開発当初はfree5GC v3.4.1以前のresponseBodyTypeのみ対応するが、将来的には設定に合わせてcase分類する。
type authSubscInfoOne struct {
	AuthenticationManagementField string `json:"authenticationManagementField"`
	AuthenticationMethod          string `json:"authenticationMethod"`
	Milenage                      struct {
		Op struct {
			EncryptionAlgorithm int    `json:"encryptionAlgorithm"`
			EncryptionKey       int    `json:"encryptionKey"`
			OpValue             string `json:"opValue"`
		} `json:"op"`
	} `json:"milenage"`
	Opc struct {
		EncryptionAlgorithm int    `json:"encryptionAlgorithm"`
		EncryptionKey       int    `json:"encryptionKey"`
		OpcValue            string `json:"opcValue"`
	} `json:"opc"`
	PermanentKey struct {
		EncryptionAlgorithm int    `json:"encryptionAlgorithm"`
		EncryptionKey       int    `json:"encryptionKey"`
		PermanentKeyValue   string `json:"permanentKeyValue"`
	} `json:"permanentKey"`
	SequenceNumber string `json:"sequenceNumber"`
	TenantID       string `json:"tenantId"`
	UeID           string `json:"ueId"`
}

// UDRへAuthenticationSubscriptionを送り、Ki, OPc, SQN, AMFを取得する。
// 引数imsiは15桁stringで入ることを想定。残り2つは conf.udrAddress と conf.apiVersion を参照する。
// 最後の引数は conf.responseBodyType を参照する。
func authSubscGet(imsi, udrAddr, apiVer string, respType int) ([]byte, []byte, []byte, []byte, error) {
	var ki []byte
	var opc []byte
	var sqn []byte
	var amf []byte
	slog.Info("[N35 IF] AuthenticationSubscription GET / process start /", "IMSI", imsi)
	var n35uri string = "http://" + udrAddr + "/nudr-dr/" + apiVer + "/subscription-data/imsi-" + imsi + "/authentication-data/authentication-subscription"
	slog.Debug("[N35 IF] AuthenticationSubscription GET / URI generated /", "URI", n35uri)
	reqBodyReader := bytes.NewReader([]byte(""))
	req, reqGenerateErr := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		n35uri,
		reqBodyReader,
	)
	if reqGenerateErr != nil {
		slog.Error("[N35 IF] AuthenticationSubscription GET / request generation error /", "error", reqGenerateErr)
		return ki, opc, sqn, amf, reqGenerateErr
	}
	req.Header.Add("content-type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("accept", "application/problem+json")
	// requestパケット完成したので、HTTP clientを生成して送信。
	client := http.Client{
		Timeout: 3 * time.Second,
	}
	slog.Info("[N35 IF] AuthenticationSubscription GET / request send /", "for", imsi)
	res, sendRequestErr := client.Do(req)
	if sendRequestErr != nil {
		slog.Error("[N35 IF] AuthenticationSubscription GET / request failed to send /", "error", sendRequestErr)
		return ki, opc, sqn, amf, sendRequestErr
	}
	// 正しくresponseを受信できているなら、bodyを忘れずcloseする（遅延実行）
	defer res.Body.Close()
	// 受信したresponseのBodyを読み込む。
	slog.Info("[N35 IF] AuthenticationSubscription GET / response received /", "for", imsi, "status", res.Status)
	resBodyBytes, readBodyErr := io.ReadAll(res.Body)
	if readBodyErr != nil {
		slog.Error("[N35 IF] AuthenticationSubscription GET / response received but failed to read body /", "error", readBodyErr)
		return ki, opc, sqn, amf, readBodyErr
	}
	// responseパケットのステータスコードを見て200 OK以外を弾く。
	if !(res.StatusCode == 200) {
		unexpectedStCodeErr := fmt.Errorf("status code of failure case received")
		slog.Error("[N35 IF] AuthenticationSubscription GET / response received but failure case /", "status_code", res.Status)
		if conf.sensitiveInfo {
			slog.Debug("[N35 IF] AuthenticationSubscription GET / received response body of failure case /", "content", string(resBodyBytes))
		}
		return ki, opc, sqn, amf, unexpectedStCodeErr
	}
	// responseのbody部分をstringに変換。
	// これでauthSubscRespDecode()を使って戻り値4つを取得する。
	resBodyStr := string(resBodyBytes)
	ki, opc, sqn, amf, retrieveErr := authSubscRespDecode(resBodyStr, respType)
	if retrieveErr != nil {
		slog.Error("[N35 IF] AuthenticationSubscription GET / failed to retrieve key info from response body /", "error", retrieveErr)
		return ki, opc, sqn, amf, retrieveErr
	}
	slog.Info("[N35 IF] AuthenticationSubscription GET / success to retrieve key info from response body /", "imsi", imsi)
	if conf.sensitiveInfo {
		slog.Debug("[N35 IF] AuthenticationSubscription GET / key info /", "Ki", fmt.Sprintf("%X", ki))
		slog.Debug("[N35 IF] AuthenticationSubscription GET / key info /", "OPc", fmt.Sprintf("%X", opc))
		slog.Debug("[N35 IF] AuthenticationSubscription GET / key info /", "SQN", fmt.Sprintf("%X", sqn))
		slog.Debug("[N35 IF] AuthenticationSubscription GET / key info /", "AMF", fmt.Sprintf("%X", amf))
	}
	return ki, opc, sqn, amf, nil
}

// AuthenticationSubscriptionで返ってきたResponse Bodyをデコードして鍵情報を取得するための関数。
// 対向5GCによってResponse Bodyが異なるため、将来の機能追加を踏まえて、authSubscGet()のデコード部分だけを切り出して関数化した。
func authSubscRespDecode(respBody string, respType int) ([]byte, []byte, []byte, []byte, error) {
	var ki []byte
	var opc []byte
	var sqn []byte
	var amf []byte
	// respBodyTypeの判別（開発当初はfree5GC v3.4.1以前のみサポート）
	slog.Debug("[N35 IF] AuthenticationSubscription GET / response body type selected /", "Type", respType)
	switch respType {
	case 1:
		var typeOneJson authSubscInfoOne
		decoder := json.NewDecoder(strings.NewReader(respBody))
		jsonDecodeErr := decoder.Decode(&typeOneJson)
		if jsonDecodeErr != nil {
			slog.Error("[N35 IF] AuthenticationSubscription GET / response body JSON decoding error /", "error", jsonDecodeErr)
			if conf.sensitiveInfo {
				slog.Debug("[N35 IF] AuthenticationSubscription GET / response body JSON decoding error /", "content", respBody)
			}
			return ki, opc, sqn, amf, jsonDecodeErr
		}
		// Response内のki/OPc/SQN/AMFはstringなので、それぞれhex.DecodeStringする。
		kiBytes, kiDecodeErr := hex.DecodeString(typeOneJson.PermanentKey.PermanentKeyValue)
		opcBytes, opcDecodeErr := hex.DecodeString(typeOneJson.Opc.OpcValue)
		sqnBytes, sqnDecodeErr := hex.DecodeString(typeOneJson.SequenceNumber)
		amfBytes, amfDecodeErr := hex.DecodeString(typeOneJson.AuthenticationManagementField)
		if kiDecodeErr != nil || opcDecodeErr != nil || sqnDecodeErr != nil || amfDecodeErr != nil {
			slog.Error("[N35 IF] AuthenticationSubscription GET / string to byte array decoding failure /", "error", "invalid key info found")
			slog.Error("[N35 IF] Ki error /", "error", kiDecodeErr)
			slog.Error("[N35 IF] OPc error/", "error", opcDecodeErr)
			slog.Error("[N35 IF] SQN error/", "error", sqnDecodeErr)
			slog.Error("[N35 IF] AMF error/", "error", amfDecodeErr)
			if conf.sensitiveInfo {
				slog.Debug("[N35 IF] Ki error /", "value", typeOneJson.PermanentKey.PermanentKeyValue)
				slog.Debug("[N35 IF] OPc error/", "value", typeOneJson.Opc.OpcValue)
				slog.Debug("[N35 IF] SQN error/", "value", typeOneJson.SequenceNumber)
				slog.Debug("[N35 IF] AMF error/", "value", typeOneJson.AuthenticationManagementField)
			}
			byteDecodeErr := fmt.Errorf("invalid key info found")
			return ki, opc, sqn, amf, byteDecodeErr
		}
		if len(kiBytes) != 16 || len(opcBytes) != 16 || len(sqnBytes) != 6 || len(amfBytes) != 2 {
			slog.Error("[N35 IF] AuthenticationSubscription GET / length check failure /", "error", "invalid length in key info")
			if conf.sensitiveInfo {
				slog.Debug("[N35 IF] Ki error /", "value", typeOneJson.PermanentKey.PermanentKeyValue)
				slog.Debug("[N35 IF] OPc error/", "value", typeOneJson.Opc.OpcValue)
				slog.Debug("[N35 IF] SQN error/", "value", typeOneJson.SequenceNumber)
				slog.Debug("[N35 IF] AMF error/", "value", typeOneJson.AuthenticationManagementField)
			}
			invalidLenErr := fmt.Errorf("invalid key info found")
			return ki, opc, sqn, amf, invalidLenErr
		}
		ki = kiBytes
		opc = opcBytes
		sqn = sqnBytes
		amf = amfBytes
	default:
		slog.Error("[N35 IF] AuthenticationSubscription GET / response body not identified /", "error", "unsupported Response Type", "value", respType)
		err := fmt.Errorf("unsupported response type")
		return ki, opc, sqn, amf, err
	}
	return ki, opc, sqn, amf, nil
}

// UDRに対してSQN更新用のPACTHを投げて、UDR内のSQNを更新する。
// 引数に取るのは「更新後のSQN」とする。
func sqnUdrUpdate(imsi, udrAddr, apiVer, sqn string) error {
	var updateErr error
	var n35uri string = "http://" + udrAddr + "/nudr-dr/" + apiVer + "/subscription-data/imsi-" + imsi + "/authentication-data/authentication-subscription"
	slog.Info("[N35 IF] AuthenticationSubscription PATCH / process start /", "for", imsi)
	// 更新するためのBody部分を生成
	if !(len(sqn) == 12) {
		slog.Error("argument SQN length is invalid /", "value", sqn)
		updateErr = fmt.Errorf("invalid argument in sqn update")
		return updateErr
	}
	slog.Debug("[N35 IF] AuthenticationSubscription PATCH / SQN-UDR update to /", "value", sqn)
	reqBodyStr := `[{"op":"replace","path":"/sequenceNumber","value":"` + sqn + `"}]`
	reqBodyReader := bytes.NewReader([]byte(reqBodyStr))
	// Requestを生成
	req, reqGenerateErr := http.NewRequestWithContext(
		context.Background(),
		http.MethodPatch,
		n35uri,
		reqBodyReader,
	)
	if reqGenerateErr != nil {
		slog.Error("[N35 IF] AuthenticationSubscription PATCH / request generation error /", "error", reqGenerateErr)
		return reqGenerateErr
	}
	req.Header.Add("content-type", "application/json-patch+json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("accept", "application/problem+json")
	client := http.Client{
		Timeout: 3 * time.Second,
	}
	slog.Info("[N35 IF] AuthenticationSubscription PATCH / request send /", "for", imsi)
	res, sendRequestErr := client.Do(req)
	if sendRequestErr != nil {
		slog.Error("[N35 IF] AuthenticationSubscription PATCH / request failed to send /", "error", sendRequestErr)
		return sendRequestErr
	}
	// 正しくresponseを受信できているなら、bodyを忘れずcloseする（遅延実行）
	defer res.Body.Close()
	slog.Info("[N35 IF] AuthenticationSubscription PATCH / response received /", "for", imsi, "status", res.Status)
	// responseパケットのステータスコードを見て204 No Content以外を弾く。
	if !(res.StatusCode == 204) {
		// 204 No Contentでなければbodyに何か入っているので読み込みを実施。
		resBodyBytes, readBodyErr := io.ReadAll(res.Body)
		if readBodyErr != nil {
			slog.Error("[N35 IF] AuthenticationSubscription PATCH / failed to read response body /", "error", readBodyErr)
			return readBodyErr
		}
		unexpectedStCodeErr := fmt.Errorf("status code of fail case received")
		slog.Error("[N35 IF] AuthenticationSubscription PATCH / response received but failure case /", "status_code", res.Status)
		slog.Debug("[N35 IF] AuthenticationSubscription PATCH / received body of failure case /", "content", string(resBodyBytes))
		return unexpectedStCodeErr
	}
	slog.Info("[N35 IF] AuthenticationSubscription PATCH / SQN update success /", "for", imsi)
	return nil
}

// SQNを1インクリメントする。引数は6byteのsqnを入れることを想定している。
// 戻り値はstringとしているが、これは上記sqnUdrUpdate()内でUDRに投げる際にHTTP APIを使うためである。
func sqnIncrement(sqn []byte) (string, error) {
	if !(len(sqn) == 6) {
		slog.Error("SQN increment process failed : invalid argument")
		slog.Debug("invalid SQN length", "SQN", fmt.Sprintf("%X", sqn))
		sqnLengthErr := fmt.Errorf("invalid sqn length")
		return "", sqnLengthErr
	}
	sqnCountMax := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if slices.Equal(sqn, sqnCountMax) {
		return "000000000000", nil
	}
	// byteスライスではインクリメントできないので、スライス長を8にした上でuint64型に変換し、インクリメントしている。
	updateSQNbyte := make([]byte, 8)
	_ = copy(updateSQNbyte[2:8], sqn)
	var updateSqnNum uint64
	bRead := bytes.NewReader(updateSQNbyte)
	chgUintErr := binary.Read(bRead, binary.BigEndian, &updateSqnNum)
	if chgUintErr != nil {
		slog.Error("SQN update process failed /", "error", chgUintErr)
		return "", chgUintErr
	}
	slog.Debug("SQN increment process", "before", fmt.Sprintf("%012v", updateSqnNum))
	updateSqnNum++
	slog.Debug("SQN increment process", "after ", fmt.Sprintf("%012v", updateSqnNum))
	// インクリメントしたSQNを再びスライス長6に戻し、戻り値のためにstring（かつ0パディングして12桁）に変換。
	sqnBytesOct := make([]byte, 8)
	binary.BigEndian.PutUint64(sqnBytesOct, updateSqnNum)
	sqnBytes := sqnBytesOct[2:8]
	sqnEncoded := hex.EncodeToString(sqnBytes)
	sqnStr := fmt.Sprintf("%012v", sqnEncoded)
	return sqnStr, nil
}
