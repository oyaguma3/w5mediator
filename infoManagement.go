package main

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"
)

var subscInfo sync.Map
var eapIdTable sync.Map

type subscdata struct {
	akaFlag byte
	ki      []byte
	opc     []byte
	sqn     []byte
	amf     []byte
	res     []byte
	rand    []byte
	msk     []byte
}

type eapIdBinded struct {
	identity  string
	timeStamp int64
}

/*
【subscInfo】
	[key]
		identity string (cf. 0999002012345678@wlan.mnc002.mcc999.3gppnetwork.org)
	[value]
		subscdata
			akaFlag       1 byte
			Ki           16 byte
			OPc          16 byte
			SQN           6 byte
			AMF           2 byte
			RAND         16 byte
			RES           8 byte
			MSK          64 byte
【eapIdTable】
	[key]
		eapId byte
	[value]
		identity string (cf. 0999002012345678@wlan.mnc002.mcc999.3gppnetwork.org)
		timeStamp int64 (UNIXTIME)
*/

// idをキーとするSubscInfoを初期化する関数。
// SubscInfoを更新するsetXXX系関数は最初に元の値をLoadするので、setXXX系関数を使う前に初期化しておく必要がある。
// 初期化されたsubscdata構造体を返すが、不要ならアンダースコアで戻り値を潰しておく。
func initializeSubscInfo(id string) subscdata {
	var init subscdata
	init.akaFlag = 0x00
	init.ki = make([]byte, 16)
	init.opc = make([]byte, 16)
	init.sqn = make([]byte, 6)
	init.amf = make([]byte, 2)
	init.rand = make([]byte, 16)
	init.res = make([]byte, 8)
	init.msk = make([]byte, 64)
	subscInfo.Store(id, init)
	slog.Debug("[SubscInfo] INIT /", "identity", id)
	return init
}

func loadSubscInfo(id string) (subscdata, bool) {
	var subscInfoValue subscdata
	var load bool
	slog.Debug("[SubscInfo] LOAD /", "identity", id)
	assert, chk := subscInfo.Load(id)
	if !chk {
		slog.Warn("[SubscInfo] LOAD / value not found /", "identity", id)
		return subscInfoValue, load
	}
	loadedValue, ok := assert.(subscdata)
	if !ok {
		slog.Error("[SubscInfo] LOAD /", "error", "internal error / type assertion falied")
		return subscInfoValue, load
	}
	subscInfoValue = loadedValue
	load = true
	return subscInfoValue, load
}

func deleteSubscInfo(id string) {
	_, chk := subscInfo.LoadAndDelete(id)
	if !chk {
		slog.Warn("[SubscInfo] DELETE / target identity not exist /", "identity", id)
	} else {
		slog.Debug("[SubscInfo] DELETE /", "identity", id)
	}
}

// ----------SubscInfo各要素の更新を行う関数群----------

// 全てのsubscInfoを一挙に更新する。引数のallInfoには全て更新後の値を代入しておくこと。
// （でなければ初期化時の00パディングが入ったままになる）
func setAllSubscInfo(id string, allInfo subscdata) error {
	slog.Debug("[SubscInfo] UPDATE / all subscInfo /", "process", "start", "id", id)
	subscInfoAll, chk := loadSubscInfo(id)
	if !chk {
		slog.Error("[SubscInfo] UPDATE / all subscInfo /", "error", "target id not found", "id", id)
		err := fmt.Errorf("value not found in subscinfo")
		return err
	}
	if conf.sensitiveInfo {
		slog.Debug("[SubscInfo] UPDATE : AKA Flag /", "old", fmt.Sprintf("0x%X", subscInfoAll.akaFlag))
		slog.Debug("[SubscInfo] UPDATE / Identity /", "old", id)
		slog.Debug("[SubscInfo] UPDATE / Ki       /", "old", fmt.Sprintf("%X", subscInfoAll.ki))
		slog.Debug("[SubscInfo] UPDATE / OPc      /", "old", fmt.Sprintf("%X", subscInfoAll.opc))
		slog.Debug("[SubscInfo] UPDATE / SQN      /", "old", fmt.Sprintf("%X", subscInfoAll.sqn))
		slog.Debug("[SubscInfo] UPDATE / AMF      /", "old", fmt.Sprintf("%X", subscInfoAll.amf))
		slog.Debug("[SubscInfo] UPDATE / RAND     /", "old", fmt.Sprintf("%X", subscInfoAll.rand))
		slog.Debug("[SubscInfo] UPDATE / RES      /", "old", fmt.Sprintf("%X", subscInfoAll.res))
		slog.Debug("[SubscInfo] UPDATE / MSK      /", "old", fmt.Sprintf("%X", subscInfoAll.msk))
	} else {
		slog.Debug("[SubscInfo] UPDATE : Key Info / old value exist but not logged (sensitive info)", "id", id)
	}
	// 古い値を一通りログ出力したので値を更新。
	subscInfo.Store(id, allInfo)
	// 更新したので新しい値をログ出力。
	if conf.sensitiveInfo {
		slog.Debug("[SubscInfo] UPDATE / AKA Flag /", "new", fmt.Sprintf("0x%X", allInfo.akaFlag))
		slog.Debug("[SubscInfo] UPDATE / Ideneity /", "new", id)
		slog.Debug("[SubscInfo] UPDATE / Ki       /", "new", fmt.Sprintf("%X", allInfo.ki))
		slog.Debug("[SubscInfo] UPDATE / OPc      /", "new", fmt.Sprintf("%X", allInfo.opc))
		slog.Debug("[SubscInfo] UPDATE / SQN      /", "new", fmt.Sprintf("%X", allInfo.sqn))
		slog.Debug("[SubscInfo] UPDATE / AMF      /", "new", fmt.Sprintf("%X", allInfo.amf))
		slog.Debug("[SubscInfo] UPDATE : RAND     /", "new", fmt.Sprintf("%X", allInfo.rand))
		slog.Debug("[SubscInfo] UPDATE : RES      /", "new", fmt.Sprintf("%X", allInfo.res))
		slog.Debug("[SubscInfo] UPDATE : MSK      /", "new", fmt.Sprintf("%X", allInfo.msk))
	} else {
		slog.Debug("[SubscInfo] UPDATE : Key Info / updated new value but not logged (sensitive info)", "id", id)
	}
	slog.Debug("[SubscInfo] UPDATE / all subscInfo /", "process", "end", "id", id)
	return nil
}

//----------ここからeapIdTable関連----------

// EAP-ID生成
func generateEAPId() byte {
	var generatedId byte
	for {
		seed := time.Now().UnixNano()
		randGenerator := rand.New(rand.NewSource(seed))
		zeroToFFInt := randGenerator.Intn(255)
		_, ok := eapIdTable.Load(byte(zeroToFFInt))
		if !ok {
			generatedId = byte(zeroToFFInt)
			slog.Debug("[radutl] EAP-ID generated /", "value", fmt.Sprintf("0x%v", generatedId))
			break
		}
	}
	return generatedId
}

// eapIdTableから読み出し
func eapIdTableLoad(k byte) (string, int64, error) {
	var valueStr string
	var valueTime int64
	var err error
	value, ok := eapIdTable.Load(k)
	if ok {
		valueAssertion, assertOK := value.(eapIdBinded)
		if assertOK {
			valueStr = valueAssertion.identity
			valueTime = valueAssertion.timeStamp
			slog.Debug("[EAP-ID Table] LOAD /", "key", fmt.Sprintf("0x%v", k), "value", valueStr)
		} else {
			slog.Warn("[EAP-ID Table] LOAD / invalid value /", "key", fmt.Sprintf("0x%v", k), "value", valueAssertion)
			err = fmt.Errorf("invalid value for target key")
		}
	} else {
		slog.Warn("[EAP-ID Table] LOAD / key not found /", "target_ID", fmt.Sprintf("0x%v", k))
		err = fmt.Errorf("key not found")
	}
	return valueStr, valueTime, err
}

// eapIdTableへ書き込み
func eapIdTableStore(k byte, vi string, vt int64) error {
	var v eapIdBinded
	var err error
	value, ok := eapIdTable.Load(k)
	if ok {
		valueAssertion, assertOK := value.(eapIdBinded)
		if assertOK {
			slog.Debug("[EAP-ID Table] STORE / before /", "value1", valueAssertion.identity, "value2", valueAssertion.timeStamp)
		} else {
			slog.Warn("[EAP-ID Table] STORE / before /", "invalid_value", valueAssertion)
			err = fmt.Errorf("invalid value for target key")
		}
	} else {
		slog.Debug("[EAP-ID Table] STORE / before / value for EAP-ID not found /", "target_ID", fmt.Sprintf("0x%v", k))
	}
	v.identity = vi
	v.timeStamp = vt
	eapIdTable.Store(k, v)
	slog.Debug("[EAP-ID Table] STORE / after /", "value1", v.identity, "value2", v.timeStamp)
	return err
}

// eapIdTableからkey-Valueペア削除
func eapIdTableDelete(k byte) {
	_, ok := eapIdTable.LoadAndDelete(k)
	if ok {
		slog.Debug("[EAP-ID Table] DELETE /", "key", fmt.Sprintf("0x%v", k))
	} else {
		slog.Warn("[EAP-ID Table] DELETE /", "key", "not found")
	}
}

// eapIdTableの残置データ監視＆削除
// 20秒ごとにEAP-ID Tableの全IDを走査し、IDが存在していて現在時刻より10秒以上経過しているものをチェック。
// 該当するIDと、これに紐づくSubscInfoを削除する（端末からResponse返らず10秒以上浮いてしまったデータの消去）
// WLAN-5GC GW起動後にgoroutineで起動させる想定。
func garbageIdCleaner() {
	for {
		slog.Debug("[EAP-ID] periodic garbage ID cleaning...", "interval", "20sec")
		for i := 0; i < 256; i++ {
			value, ok := eapIdTable.Load(i)
			if ok {
				garbageData, assertOK := value.(eapIdBinded)
				if assertOK {
					t := time.Now()
					unixTimeNow := t.Unix()
					chk := unixTimeNow - garbageData.timeStamp
					if chk > 10 {
						deleteSubscInfo(garbageData.identity)
						eapIdTable.Delete(i)
						slog.Debug("[EAP-ID] garbage ID deleted /", "ID", i)
					}
				}
			}
		}
		time.Sleep(20 * time.Second)
	}
}
