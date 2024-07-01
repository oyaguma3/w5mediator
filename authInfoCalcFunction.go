package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/go-magma/magma/modules/feg/gateway/services/eap/providers/aka"
)

/*
EAP-AKA/AKA'の各種認証情報を導出する機能のコード群
magmaプロジェクトのeapパッケージはここにインポートする
ここの関数を使う前に、MilenageパッケージでIK/CK導出を忘れずに。
*/

func generateRAND() ([]byte, error) {
	r := make([]byte, 16)
	_, err := rand.Read(r)
	if err != nil {
		slog.Error("[EAP-Server] RAND generation failed /", "error", err)
		return r, err
	}
	return r, err
}

// magmaプロジェクトのEAP-AKA関連コードを使って計算。
// 引数のidentityはEAP-Identityなどに入っていたInner-identityそのままを入れる。
func akaCalc(identity, IK, CK []byte) (K_encr, K_aut, MSK, EMSK []byte) {
	K_encr, K_aut, MSK, EMSK = aka.MakeAKAKeys(identity, IK, CK)
	if conf.sensitiveInfo {
		slog.Debug("[EAP-Server] Make AKA keys /", "K_encr", fmt.Sprintf("0x%X", K_encr))
		slog.Debug("[EAP-Server] Make AKA keys /", "K_aut", fmt.Sprintf("0x%X", K_aut))
		slog.Debug("[EAP-Server] Make AKA keys /", "MSK", fmt.Sprintf("0x%X", MSK))
		slog.Debug("[EAP-Server] Make AKA keys /", "EMSK", fmt.Sprintf("0x%X", EMSK))
	}
	return K_encr, K_aut, MSK, EMSK
}

// CK'/IK'からMK（MasterKey）を導出し、各エレメントに分割する。
// ここもfree5GCのソースコードをほぼ流用した。
func akaPrimeCalc(ikPrime, ckPrime []byte, identity string) ([]byte, []byte, []byte, []byte, []byte, error) {
	keyAp := string(ikPrime) + string(ckPrime)
	key := []byte(keyAp)
	sBase := []byte("EAP-AKA'" + identity)
	MK := []byte("")
	prev := []byte("")
	prfRounds := 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		h := hmac.New(sha256.New, key)
		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)
		if _, err := h.Write(s); err != nil {
			slog.Error("[EAP-Server] hash value for MK writing failed /", "error", err)
			return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
		}
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}
	// MKが導出されたので、各鍵エレメントに分割する。
	K_encr := MK[0:16]  // 0..127
	K_aut := MK[16:48]  // 128..383
	K_re := MK[48:80]   // 384..639
	MSK := MK[80:144]   // 640..1151
	EMSK := MK[144:208] // 1152..1663
	if conf.sensitiveInfo {
		slog.Debug("[EAP-Server] Make AKA' keys /", "K_encr", fmt.Sprintf("0x%X", K_encr))
		slog.Debug("[EAP-Server] Make AKA' keys /", "K_aut", fmt.Sprintf("0x%X", K_aut))
		slog.Debug("[EAP-Server] Make AKA' keys /", "K_re", fmt.Sprintf("0x%X", K_re))
		slog.Debug("[EAP-Server] Make AKA' keys /", "MSK", fmt.Sprintf("0x%X", MSK))
		slog.Debug("[EAP-Server] Make AKA' keys /", "EMSK", fmt.Sprintf("0x%X", EMSK))
	}
	return K_encr, K_aut, K_re, MSK, EMSK, nil
}

// CK'/IK'を導出する。free5GCのソースコードをほぼ流用した。
// nwNameは conf.nwNameForKDF を入れることを想定している。
func deriveCKIKPrime(ck, ik, sqn, ak []byte, nwName string) (ckPrime, ikPrime []byte) {
	sqnXorAK := make([]byte, 6)
	for i := 0; i < len(sqn); i++ {
		sqnXorAK[i] = sqn[i] ^ ak[i]
	}
	key := append(ck, ik...)
	FC := "20"
	P0 := []byte(nwName)
	P1 := sqnXorAK
	kdfVal := GetKDFValue(key, FC, P0, KDFLen(P0), P1, KDFLen(P1))
	ckPrime = kdfVal[:len(kdfVal)/2]
	ikPrime = kdfVal[len(kdfVal)/2:]
	if conf.sensitiveInfo {
		slog.Debug("[EAP-Server] KDF value /", "CKprime", fmt.Sprintf("0x%X", ckPrime))
		slog.Debug("[EAP-Server] KDF value /", "IKprime", fmt.Sprintf("0x%X", ikPrime))
	}
	return ckPrime, ikPrime
}

// ----------

func KDFLen(input []byte) []byte {
	var r = make([]byte, 2)
	binary.BigEndian.PutUint16(r, uint16(len(input)))
	return r
}

func GetKDFValue(key []byte, FC string, param ...[]byte) []byte {
	kdf := hmac.New(sha256.New, key)
	var S []byte
	if STmp, err := hex.DecodeString(string(FC)); err != nil {
		slog.Error("[EAP-Server] KDF calculation process failed /", "error", err)
	} else {
		S = STmp
	}
	for _, p := range param {
		S = append(S, p...)
	}
	if _, err := kdf.Write(S); err != nil {
		slog.Error("[EAP-Server] KDF writing failed /", "error", err)
	}
	sum := kdf.Sum(nil)
	return sum
}
