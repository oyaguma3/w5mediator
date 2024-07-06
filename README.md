# w5mediatorについて
w5mediatorとは、free5GCのUDRを使って、SIM/eSIMを用いた802.1X認証(EAP-AKA/AKA')を動かすためのソフトウェアです。  
このソフトは、5GC UDRと802.1X対応無線LANアクセスポイントとの間で、RADIUS(EAP)とSBI HTTP APIを仲介する機能を担います。   
そのため、w5mediatorと名付けています。  
なお、このソフトはGo言語(1.22)で書きましたが、syncパッケージを使っているので少なくとも1.19以降が必要です。  
私自身はGo初学者ですので、安定動作やサポートに関しては不十分であるとご理解ください。  

## ■ ノード構成
ざっくりですが、以下のような構成で動かすことを想定しています。  
<img src="https://github.com/oyaguma3/w5mediator/assets/170003128/269eae97-9a03-4f1f-901e-a0860099fdef" width="30%" />

## ■ 機能や制限事項について
 - 必要スペックは特にありませんが、接続が殺到するような状況でもなければ、Rasberry Pi4でも動作します。
 - 802.1X認証におけるEAP-AKA/EAP-AKA'に対応しています。EAP-SIMは非対応です。  
 - RADIUSやEAP関連は、EAP-AKA/EAP-AKA'認証を機能させるための最低限の実装のみとなっています。Accountingは現状では未サポートですので、必要に応じてfreeRADIUSなど他ソフトを使って対応してください。
 - 鍵導出アルゴリズムは、Milenageのみ対応しています。将来的にはTUAKにも対応させたいと思っていますが……。
 - 接続する無線LANアクセスポイントは、802.1X認証かつEAP-AKA/EAP-AKA'に対応している必要があります。  
しかし、このソフトは複数クライアントとの接続には現状では非対応できていません。複数アクセスポイントからの接続を受けられるようにするには、中間にRADIUS Proxy(freeRADIUSなど)を置いてインターフェースを集約するとよいでしょう。
 - 対向5GCとしてfree5GC v3.4.1を用いて動作確認を行っていますが、他5GCでは動作しません。
このソフトはUDRに鍵情報を直接取りに行く実装としていますが、そのResponseの差異を吸収できていないためです（少なくともOpen5GSは非対応ですが、将来的にはサポートする予定です）

## ■ ビルドと実行
以下の8ファイルはいずれもmainパッケージに属しています。  
実行バイナリを生成するなら`go build .`で、走らせるだけなら`go run .`すればよいはずです。  
 - authInfoCalcFunction.go
 - config.go
 - eapPacketHandling.go
 - eapServer.go
 - infoManagement.go
 - radiusUtil.go
 - udrQueryCaster.go
 - w5mediator.go

あとは、適当なフォルダに実行バイナリと設定ファイル(w5conf.yaml)を置いて、バイナリをそのまま実行してください。特にオプション等も実装していません（できていません）。止めるときはCTRL+Cなどで終了させてください。

## ■ 設定項目について
設定ファイルは "w5conf.yaml" です。ファイル名は変更しないようお願いします。  
また、設定ファイルは実行バイナリと同じフォルダに設置しておいてください。  
設定項目については基本的にファイル内で説明を記載しています。ただし、以下の項目は環境に合わせてデフォルトから変更する必要があるものです。構築した環境に合わせて適切に設定項目の値を変更してください。
 - sharedSecret
 - allowedClientAddress
 - udrAddress
 - allowedPLMN

## ■ SIM認証を機能させるまでのステップ
前提として、設定ファイルに設定項目が適切にセットされ、使用SIMのIMSI/Ki/OPcが登録されているものとします。  
1. 無線LANアクセスポイントを起動し、端末側からSSIDが見えていることを確認する
2. free5GC（とmongoDB）を起動する
3. w5mediatorを起動する
4. 端末からSSIDを指定し、認証方式でEAP-AKAまたはEAP-AKA'を選択して接続を試みる
5. 認証成功したら、無線LANアクセスポイントとのアソシエーション完了となる
6. アクセスポイント等からIPアドレスが適切に割り振られ、通信可能であることを確認する。
 
## ■ free5GCの使用にあたって
### free5GCの設定ファイルに関する変更箇所
本ソフトのver.1.0.0時点では、free5GC v3.4.1を対向として動作させることを目的としています。  
（v3.0.0あたりでも恐らく動作するとは思いますが……）  
しかし、適切に動作させるには、free5GCの設定ファイル群を一部変更する必要があります。これは、使用するSIMのIMSIに含まれるPLMN番号に設定を合わせるといった、ごく基本的なものを含みます。  
変更対象は、~/free5gc/config配下の`nrfcfg.yaml`にある、以下の項目です。  

 - **oauth**  
   free5GC v3.4.0からOAuth 2.0が導入されていますが、本ソフトはOAuth 2.0そのものに対応できていないので`false`を設定してください。
 - **DefaultPlmnId**  
   SIMの属するPLMNに合わせて、MCC/MNCを追加もしくは更新してください。  
   なお、WebConsoleでSIM情報を登録する際にここの設定が適切に入っていないと、登録できないことがあります。

### free5GCのwebconsoleのSIM情報登録
free5GCのWebConsoleからIMSI/Ki/OPcを登録する際に、***認証タイプを`5G-AKA`から`EAP-AKA'`に変更***しておいてください。  
また、PLMN番号（IMSIの先頭5〜6桁）に合わせてPLMN項目も適切に変更しておく必要もあります。細かいところですが、GPSIは各SIMで被らないように適当な値を入れておくとよいでしょう。他の登録済みSIMとGPSIが被っていると登録できないようです。
ちなみに、本ソフトの認証機能のためだけに使うのであれば、NSSAIやDNNなど他の設定項目はデフォルトでも問題ありません。

## ■ 今後の機能開発予定（上から優先度高い）
 - daemon化は検討中
 - 複数クライアント接続可は対応予定
 - Open5GS対応は検討中
 - Accounting機能は検討中（別ログに出力する仕組みとセット）
 - 鍵計算アルゴリズムでXORは対応予定なし、TUAKは検討中
 - Status-Serverは検討中（優先度はかなり低い）

## ■ 参考情報
### EAP-AKA/EAP-AKA'を自前で動作検証するためのSIMカードについて
IMSI/Ki/OPcが分かっているSIMカードというものは、原則として研究用しかありません。定番どころとしてsysmocom製品を挙げておきます。  
[https://sysmocom.de/index.html](https://sysmocom.de/index.html)
オンラインショップだと以下の製品が該当します。  
2024年7月現在だと10枚1セットで81ユーロですが、日本で使うとなれば輸入することになるので、関税や手数料を考えると18,000円を少し超えるぐらいでしょうか。  
[sysmoISIM-SJA5-9FV SIM + USIM + ISIM Card (10-pack) with ADM keys; 9FV chip](https://shop.sysmocom.de/sysmoISIM-SJA5-9FV-SIM-USIM-ISIM-Card-10-pack-with-ADM-keys-9FV-chip/sysmoISIM-SJA5-9FV-10p-adm)
  
### 利用したGoの外部パッケージ
ソースコードを見れば分かるものではありますが、利用した外部パッケージを列記しておきます。

 - [https://pkg.go.dev/layeh.com/radius](https://pkg.go.dev/layeh.com/radius)
 - [https://pkg.go.dev/github.com/google/gopacket](https://pkg.go.dev/github.com/google/gopacket)
 - [https://pkg.go.dev/gopkg.in/yaml.v3](https://pkg.go.dev/gopkg.in/yaml.v3)
 - [https://pkg.go.dev/github.com/wmnsk/milenage](https://pkg.go.dev/github.com/wmnsk/milenage)
 - [https://github.com/go-magma/magma](https://github.com/go-magma/magma)
 - [https://github.com/natefinch/lumberjack](https://github.com/natefinch/lumberjack)

## ■ 環境構築例
### VirtualBoxを使った構成
ホストに本ソフトw5mediatorを置き、VirtualBoxで立てたVM上のfree5GCと接続する構成です。  
<img src="https://github.com/oyaguma3/w5mediator/assets/170003128/e8ab294e-3e7d-4d79-a8be-74e5a101cc96" width="30%" />

[free5GC公式サイトのUser Guide](https://free5gc.org/guide/)にある Build free5GC from scratch では、VirtualBoxでubuntu 22.04 LTSで立てたVMにfree5GCをインストールする手順が、動画リンク付きで掲載されています。本ソフトに必要なのは「Build and Install free5GC from source code and Test free5GC」のところまでですが、ここまで実行できれば環境構築まであと少しです。  
VM上にfree5GCを構築したあとは、以下の対応が必要になります。  

1. VMへのnginxインストール
   - nginxはリバースプロキシとして使用します。
   - ホスト側のw5mediatorからUDRに対して投げるSBI HTTP APIは、上記のfree5GC VM構成だとホストオンリーアダプタを通すことになるので、VM内のループバックアドレスが設定されているUDR（デフォルトでは127.0.0.4:8000のはず）に到達できません。しかし、free5GC NFsのセグメントを逐一変更するのは大変なので、代替案としてnginxをリバースプロキシとして導入し、ホストオンリーアダプタに到達したパケットをUDRアドレスへリダイレクトするように設定します。
   - nginxは最新版でなくともよく、上記free5GC VM構成であればubuntu上で`sudo apt install nginx`でインストールされるバージョンで十分です。
2. VMのホストオンリーアダプタに合わせたw5conf.yamlの設定記載
   - free5GC User Guideに従ってVirtualBoxでVMを立てているなら、ホストオンリーアダプタを作成してSSHログインする手順を通過しており、その際に`vboxnet0`に割り当てたIPアドレスは`192.168.56.101`となっているはずです。
   - これをw5mediatorの設定項目「udrAddress」のIPアドレスとして、合わせてポート番号の8000あたりを使っておきましょう。設定項目には`192.168.56.101:8000`と記載することになります。
3. VMへインストールしたnginxのリバースプロキシ設定ファイル作成
   - 適用したいリバースプロキシ設定を記載したファイルを`/etc/nginx/sites-available/`配下に作成します。
     ファイル名は仮に`w5medRevProxy`とでもしておきましょう。
   - `sudo nano /etc/nginx/sites-available/w5medRevProxy`でnanoエディタを開き、以下を記載して保存します。なお、この記載例は、ホストオンリーアダプタのIPアドレスが`192.168.56.101`であり、free5GC UDRアドレスがudrcfg.yaml内で`127.0.0.4:8000`と設定されているケースのものです。  
```
server {
	listen 192.168.56.101:8000 ;
	location / {
		proxy_pass http://127.0.0.4:8000/ ;
	}
}
```
4. 上記ファイルのシンボリックリンクを /etc/nginx/sites-enabled/ に作成して適用。
   - コマンドは `sudo ln -s /etc/nginx/sites-available/w5medRevProxy /etc/nginx/sites-enabled/`で。  
   - なお`/etc/nginx/sites-enabled/`に`default`が残っていると適切に動作しないかもしれないので、削除しておいたほうがいいかもしれません。
   - 最後にnginx自体を再起動し、設定を適用させます。コマンドは `sudo systemctl restart nginx`あたりで。

これで、ホスト側のw5mediatorから、VM上のfree5GC UDRにSIM鍵情報を取得するためのAPIが適切に通るようになるはずです。  
なお、VirtualBoxではなくWSL2でも同様の構成が可能です。
