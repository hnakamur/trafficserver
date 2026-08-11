# `no_dns_forward_to_parent` を「親が0台のときは無視してオリジンDNS解決」に変更(設定切替付き)

## 状況整理

- `parent.config` で複数親を `consistent_hash` 指定し、`no_dns_forward_to_parent`(config: `proxy.config.http.no_dns_just_forward_to_parent`) を有効化。
- 運用中に `parent.config` を空にして reload すると、`parent_table` が空になり `findParent()` が `PARENT_DIRECT`(「親なし」)を返す。
- このとき `no_dns_forward_to_parent` が有効だと、TSが「オリジンDNSをしない」ためにリクエストが **`PARENT_FAIL` → `HOST_NONE`** になり、より多くのケースでは **502/失敗** に落ちる。

## 目標

新規設定 **`proxy.config.http.disable_just_forward_to_parent_when_empty`** を導入し、**これを有効(=1)にしたときだけ**以下の挙動を有効にする。

- 親が**1台も存在しない**(親設定が空)場合は、`no_dns_forward_to_parent` を**無視**して通常どおりオリジンへDNS解決してリクエストを送る。
- 親が存在する(または新設定が無効)場合は従来どおり `no_dns_forward_to_parent` の挙動(親へ転送・親が無ければ失敗)を維持する。

→ 既存運用の挙動を変えずに、新設定を有効にした環境だけ挙動を変えられるようにする。

## 変更点の一覧(実コード)

### 0. 新設定項目の追加

`MgmtByte disable_just_forward_to_parent_when_empty` を追加する。既存 `no_dns_forward_to_parent` の宣言/登録/マッピングと同じ3箇所に追記する。

**HttpConfig.h — `HttpConfigParams` 構造体(既存 `no_dns_forward_to_parent` の並び、HttpConfig.h:820付近)**
```cpp
  MgmtByte no_dns_forward_to_parent = 0;
  MgmtByte disable_just_forward_to_parent_when_empty = 0; // 追加
```

**HttpConfig.cc — レコード登録(既存 `no_dns_just_forward_to_parent` の並び、HttpConfig.cc:1179付近)**
```cpp
  HttpEstablishStaticConfigByte(c.no_dns_forward_to_parent, "proxy.config.http.no_dns_just_forward_to_parent");
  HttpEstablishStaticConfigByte(c.disable_just_forward_to_parent_when_empty,
                                "proxy.config.http.disable_just_forward_to_parent_when_empty"); // 追加
```

**HttpConfig.cc — `HttpConfigParams` へのコピー(既存 `m_master.no_dns_forward_to_parent` の並び、HttpConfig.cc:1461付近)**
```cpp
  params->no_dns_forward_to_parent                 = INT_TO_BOOL(m_master.no_dns_forward_to_parent);
  params->disable_just_forward_to_parent_when_empty = INT_TO_BOOL(m_master.disable_just_forward_to_parent_when_empty); // 追加
```

**mgmt/RecordsConfig.cc — レコード定義(既存 `no_dns_just_forward_to_parent` の並び、RecordsConfig.cc:350付近)**
```cpp
  {RECT_CONFIG, "proxy.config.http.disable_just_forward_to_parent_when_empty", RECD_INT, "0", RECU_DYNAMIC, RR_NULL, RECC_INT, "[0-1]", RECA_NULL}
```

(任意) doc/admin-guide/files/records.config.en.rst に既存 `no_dns_just_forward_to_parent` の並びで説明を追記。

以下の各判定は、新設定が有効時にのみ「親0台なら no_dns を無視する」ようにガードする。

### 1. 専用ヘルパーの追加

`ParentConfigParams` に「このテーブルに1台でも親が設定されているか」を返すヘルパーを追加する。

`proxy/ParentSelection.h` / `ParentSelection.cc`:
```cpp
// ParentSelection.h — ParentConfigParams の public メンバとして宣言
class ParentConfigParams : public ConfigInfo {
  ...
public:
  bool hasAnyParent() const;
  ...
};

// ParentSelection.cc — 実装
bool
ParentConfigParams::hasAnyParent() const
{
  // parent_table に1つでもルール(エントリ)が登録されているか、
  // もしくはデフォルト親が定義されていれば true。
  // parent.config が空なら getEntryCount() == 0 かつ DefaultParent == nullptr
  // となり false を返す。
  return DefaultParent != nullptr || parent_table->getEntryCount() > 0;
}
```

補足:
- `ControlMatcher::getEntryCount()`(`ControlMatcher.h:321-325`)は `m_numEntries`(= 設定ファイルのルール行数、`BuildTable` で設定)を返す。`parent.config` を空にした reload では `0` になる。
- `parent_table` と `DefaultParent` は `ParentConfigParams` の public メンバ(`ParentSelection.h:417-418`)なので、`ParentConfigParams` 自身のメソッドからそのまま参照できる。
- `parent_table` は reload(Node コンフィグ)で `ParentConfig::set_parent_table` / `reconfigure` により差し替わるため、`hasAnyParent()` も reload タイミングで最新の親設定に連動する(既存 `findParent`/`parentExists` と同じ)。

> 代替案: 既存の `parentExists()` で代用する手もあるが、これは「現在利用可能(available)な親」を見るため「全親ダウン」時にも false になり、元の `no_dns` の意図(全ダウン時はリクエストを失敗させる)を崩してしまう。専用ヘルパーのほうが安全。

### 2. `HttpTransact::find_server_and_update_current_info`(HttpTransact.cc:705-712) 【核心】

`PARENT_DIRECT` 時に `no_dns_forward_to_parent` で `PARENT_FAIL` に落とす処理を、新設定が有効かつ親0台の場合だけ回避する。

ロジック: **no_dns 有効のまま失敗させるのは、新設定が無効 OR 親が存在する場合のみ**。新設定有効かつ親0台なら `PARENT_DIRECT` のまま `ORIGIN_SERVER` へ(オリジンDNS)。
```cpp
  case PARENT_DIRECT:
-   if (s->http_config_param->no_dns_forward_to_parent) {
+   if (s->http_config_param->no_dns_forward_to_parent &&
+       (!s->http_config_param->disable_just_forward_to_parent_when_empty ||
+        s->parent_params->hasAnyParent())) {
      Warning("...");
      s->parent_result.result = PARENT_FAIL;
      return HttpTransact::HOST_NONE;
    }
```

### 3. `HttpTransact::PPDNSLookup`(HttpTransact.cc:1873)

`PARENT_DIRECT && no_dns != 1` で `CallOSDNSLookup` する分岐も、新設定有効かつ親0台ではオリジンDNSを許可。
```cpp
- } else if (s->parent_result.result == PARENT_DIRECT && s->http_config_param->no_dns_forward_to_parent != 1) {
+ } else if (s->parent_result.result == PARENT_DIRECT &&
+            (s->http_config_param->no_dns_forward_to_parent != 1 ||
+             (s->http_config_param->disable_just_forward_to_parent_when_empty &&
+              !s->parent_params->hasAnyParent()))) {
```

### 4. `HttpTransact::HandleCacheOpenReadMiss`(HttpTransact.cc:3436-3438)

ミス時の `PARENT_DIRECT && no_dns != 1` の `CallOSDNSLookup` も同様にガード。
```cpp
- if (s->parent_result.result == PARENT_DIRECT && s->http_config_param->no_dns_forward_to_parent != 1) {
+ if (s->parent_result.result == PARENT_DIRECT &&
+     (s->http_config_param->no_dns_forward_to_parent != 1 ||
+      (s->http_config_param->disable_just_forward_to_parent_when_empty &&
+       !s->parent_params->hasAnyParent()))) {
```

### 5. `HttpSM::state_hostdb_lookup`(HttpSM.cc:7852-7856)

`PARENT_UNDEFINED` 以外(≒`PARENT_DIRECT`)でDNSをスキップする分岐を、新設定有効かつ親0台では実施しない。
```cpp
- else if (t_state.dns_info.looking_up == HttpTransact::ORIGIN_SERVER && t_state.http_config_param->no_dns_forward_to_parent &&
-          t_state.parent_result.result != PARENT_UNDEFINED) {
+ else if (t_state.dns_info.looking_up == HttpTransact::ORIGIN_SERVER && t_state.http_config_param->no_dns_forward_to_parent &&
+          t_state.parent_result.result != PARENT_UNDEFINED &&
+          (!t_state.http_config_param->disable_just_forward_to_parent_when_empty ||
+           t_state.parent_params->hasAnyParent())) {
```

## 変更不要な参照箇所とその理由

`no_dns_forward_to_parent` の参照箇所のうち、上記 2〜5 以外は変更不要。箇所ごとに理由を記す。

### A. `HttpTransact.cc:635`(`find_server_and_update_current_info` — uncacheable_requests_bypass_parent 判定)

```cpp
} else if (s->txn_conf->uncacheable_requests_bypass_parent && s->http_config_param->no_dns_forward_to_parent == 0 && ...
```

この分岐は **`no_dns_forward_to_parent == 0`(no_dns 無効)のときにのみ実行**される。本変更が対象とするのは no_dns 有効時なので、この分岐はそもそも到達しない。変更不要。

### B. `HttpTransact.cc:664`(`find_server_and_update_current_info` — PARENT_SPECIFIED のリトライで PARENT_DIRECT に落ちた場合)

```cpp
case PARENT_SPECIFIED:
  nextParent(s);
  ...
  if (s->parent_result.result == PARENT_DIRECT && s->http_config_param->no_dns_forward_to_parent != 0) {
    ink_assert(!s->server_info.dst_addr.isValid());
    s->parent_result.result = PARENT_FAIL;
  }
```

これは「**一度は親(PARENT_SPECIFIED)が選ばれたが、リトライで親を使い尽くして PARENT_DIRECT になった**」ケース = 「**親が設定されているのに全ダウン/全親失敗**」のケース。

本設計は意図的にこのケースの挙動を変えない(`hasAnyParent()` が true のままなので従来どおり PARENT_FAIL)。「**親が1台も設定されていない(空)**」と「**親はあるが使えない**」を区別し、「空」のときだけ新挙動に切り替えるため、ここは変更しない。むしろ変更**すべきでない**箇所。

### C. `HttpTransact.cc:675`(`find_server_and_update_current_info` — PARENT_FAIL から直接オリジンへ bypass)

```cpp
case PARENT_FAIL:
  if (s->http_config_param->no_dns_forward_to_parent == 0 && bypass_ok(s) && parent_is_proxy(s) && ...
```

これも **`no_dns_forward_to_parent == 0`(no_dns 無効)のときのみ**実行される分岐。no_dns 有効時には到達しない。変更不要。

### D. `HttpTransact.cc:1671-1684`(`HandleRequest` — 親へ転送するため OSDNS をスキップ)

```cpp
if (s->http_config_param->no_dns_forward_to_parent && s->scheme != URL_WKSIDX_HTTPS && ...) {
  ...
  if (parentExists(s)) {  // 親があればそのまま親へ(OSDNS しない)
    ats_ip_invalidate(&s->server_info.dst_addr);
    StartAccessControl(s);
    return;
  } else if (s->http_config_param->no_origin_server_dns) { ... }
}
```

親が「設定されている」場合は従来どおり親へ転送(OSDNS スキップ)で正しい。親0台(空)では `parentExists()` が false になり **この if に入らず**、その下の通常フロー(キャッシュチェック→オリジンDNS)へ進む。つまり新設定がなくても、空のときは既にオリジンDNSへ進む構造のため変更不要。

(註: `parentExists()` は「利用可能な親があるか」を見るため全ダウン時も false になるが、その場合 `no_origin_server_dns` 設定の有無でエラーか通常フローかに分かれる。これも親0台の本変更の対象外で、既存挙動を維持する。)

### E. `HttpTransact.cc:2142`(リバースDNSスキップ判定)

```cpp
} else if (s->dns_info.lookup_name[0] <= '9' && s->dns_info.lookup_name[0] >= '0' && s->parent_params->parent_table->hostMatch &&
           !s->http_config_param->no_dns_forward_to_parent) {
```

これは「数値で始まるホスト名(=IPらしき文字列)に対する **リバースDNS** をアクセス制御用に実行するか」を決める分岐で、`parent_table->hostMatch`(親ルールが設定済みか)も条件に含む。フォワード先(親 or オリジン)の選択とは**直交**しており、オリジンの正引きDNSには無関係。親0台の新挙動に影響しないため変更不要。

### F. `HttpTransact.cc:3442`(`HandleCacheOpenReadMiss` — ink_release_assert 内)

```cpp
ink_release_assert(s->parent_result.result == PARENT_DIRECT || s->current.request_to == PARENT_PROXY ||
                   s->http_config_param->no_dns_forward_to_parent != 0);
```

これは「ここに来る状態の不変条件」を検証するアサーションであり、ルーティング判定ではない。隣の if(PARENT_DIRECT && ...)が変更対象(点4)で、アサーション自体は成り立つ条件がそのままなので変更不要。(本変更で親0台の場合は `no_dns_forward_to_parent != 0` でも成立する。)

### G. `HttpSM.cc:4335`(`do_hostdb_lookup`)

```cpp
if (t_state.http_config_param->no_dns_forward_to_parent && t_state.parent_result.result == PARENT_UNDEFINED) {
  t_state.dns_info.lookup_success = true;
  ...
}
```

このDNSスキップは **`PARENT_UNDEFINED`**(親選択がまだ行われていない未確定状態)のときだけ。親0台(空)の場合は `findParent` が `PARENT_DIRECT` を返すため `PARENT_UNDEFINED` にはならず、**この分岐に入らず実際のDNS解決が実行される**。つまり空のときは既に望む挙動(オリジンDNS実行)になるため変更不要。

### まとめ

- 「**no_dns 有効が前提でない**」箇所(A, C)や「**全ダウンを従来どおり失敗させたい**」箇所(B)は、本変更の対象・根拠から外れるため変更しない。
- 「**既に親0台ならオリジンDNSへ進む構造**」の箇所(D, G)は、変更する必要がない(現状で既定の動作が新しい要望を満たす)。
- 「**本変更と直交**」する箇所(E: リバースDNS, F: アサーション)は対象外。
- 変更が必要なのは、**親0台なのに no_dns が原因でオリジンDNSを塞ぎ、リクエストを失敗させてしまう箇所**(点2, 3, 4, 5)のみ。

## なぜこの変更か(理由)

- `no_dns_forward_to_parent` の本来の意図は「**親へフォワードするため**にオリジンDNSを省略する」こと。親が0台の状態は「フォワード先が無い=オリジンへ飛ばすしかない」のに、OSSの挙動はその場でリクエストを失敗させてしまう。
- 運用上「親を空にしてreload」する間は全リクエストが失敗するのは致命的。親0台の間だけオリジンDNSを許可すれば、メンテ中もサービスが継続できる。
- ただし、挙動変更を**常時**有効にすると、`no_dns_forward_to_parent` の既存利用者の意味合いが変わる。そこで新設定 `disable_just_forward_to_parent_when_empty` を追加し、**これを有効にした環境だけ**新挙動に切り替えられるようにする(デフォルト=0で従来挙動を維持)。
- 親が「設定されている」のに全ダウンのケース(従来は失敗)は挙動を変えないため、`hasAnyParent()`(設定ベース)と `parentExists()`(可用性ベース)を区別する。

## 影響範囲・リスク

- 変更は `no_dns_forward_to_parent` 有効かつ `disable_just_forward_to_parent_when_empty` 有効かつ「親が1台も無い」時のみ。デフォルト(新設定=0)では従来どおりの挙動で影響なし。
- テスト: 既存の parent selection unit test(`proxy/ParentSelection.cc` 内 SelfTests / `proxy/http/remap/unit-tests`)でリグレッション確認。加えて、新設定有効時と無効時の 2 パターンで「親0台」の gold test を追加すると良い。
- hasAnyParent() は reload(Node config) で再構築される `parent_table` を見るため、reload タイミングで反映される(新設定も RECU_DYNAMIC で即時反映)。
