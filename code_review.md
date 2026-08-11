# Code Review: 9.2.15.disable_just_forward_to_parent_when_empty

## レビュー対象

- ブランチ: `9.2.15.disable_just_forward_to_parent_when_empty` (base `9.2.15` tag 相当 `f671e52`)
- 対象コミット: `8ca2ac7`「Allow origin DNS when parents empty and disable_just_forward_to_parent_when_empty is set」
- 差分: `git diff 9.2.15..HEAD`

### 変更ファイル一覧

```
 doc/admin-guide/files/records.config.en.rst |  8 ++++++++
 mgmt/RecordsConfig.cc                       |  2 ++
 proxy/ParentSelection.cc                    |  9 +++++++++
 proxy/ParentSelection.h                     |  1 +
 proxy/http/HttpConfig.cc                    | 19 +++++++++++--------
 proxy/http/HttpConfig.h                     |  9 +++++----
 proxy/http/HttpSM.cc                        |  3 ++-
 proxy/http/HttpTransact.cc                  | 15 +++++++++++----
 8 files changed, 49 insertions(+), 17 deletions(-)
```

---

## 総評

設計は堅牢で、変更範囲の根拠も明確。`no_dns_just_forward_to_parent` (`no_dns_forward_to_parent`) が「親0台の reload 時にオリジンを DNS せずリクエストを失敗させる」問題を、**デフォルト無効の新設定でゲートした後方互換な修正**として実装している。

特に、可用性ベースの既存 `parentExists()` と設定ベースの新 `hasAnyParent()` を**意図的に区別**している点は仕様として賢明。デフォルトでは完全に従来挙動を維持するため、既存利用者への影響はない。

一方で、**自動テストが一切追加されていない**点と、境界ケース(go_direct のみ・default parent 設定)の暗黙的扱いが未文書化である点は QA 観点で指摘する。**内容的にはマージ可能な品質**だが、テスト追加とドキュメント補強を推奨する。

---

## 良い点(妥当と確認できた要素)

### 1. 変更4箇所の条件が全て整合的
新挙動「親0台なら no_dns を無視してオリジンDNS」へのフォールスルーが、どのコードパスでも一貫して実現されている。

| 箇所 | 説明 | 条件 |
|---|---|---|
| `HttpTransact.cc:710` | PARENT_DIRECT で `PARENT_FAIL` に落とす処理 | `no_dns && (!disable \|\| hasAnyParent())` |
| `HttpTransact.cc:1877` | PPDNSLookup で `CallOSDNSLookup` | `no_dns != 1 \|\| (disable && !hasAnyParent())` |
| `HttpTransact.cc:3444` | HandleCacheOpenReadMiss で `CallOSDNSLookup` | 同上 |
| `HttpSM.cc:7854` | DNS スキップ(just forward)分岐のガード | `!disable \|\| hasAnyParent()` |

いずれも「**disable が有効 かつ 親0台**」のときだけ新挙動へ切り替わり、それ以外は従来どおり失敗する。論理を4ケースで検証:
- `no_dns=1, disable=0`(デフォルト)→ 従来どおり失敗 ✅
- `no_dns=1, disable=1, 親あり`→ 失敗 ✅
- `no_dns=1, disable=1, 親0台`→ オリジンDNS ⭐新機能
- `no_dns=0`→ 常にオリジンDNS(本変更に無関係) 

### 2. `hasAnyParent()`(設定ベース)と `parentExists()`(可用性ベース)の区別
`parentExists()`(`ParentSelection.cc:226-258`)は一致レコードかつ**利用可能な親**があるかを返すため、「全親ダウン」でも false になる。本機能は「**親が1台も設定されていない**」ケースに限定したいため、エントリ数(`getEntryCount() > 0`)に基づく専用 `hasAnyParent()` を新設した、という設計方針は正しい。

これにより、**親は設定されているが全ダウン**(`HttpTransact.cc:664` の PARENT_SPECIFIED → PARENT_DIRECT)は従来どおり `PARENT_FAIL` させる。これは仕様として賢明な判断。

### 3. 変更不要と判断した参照箇所は実際にコードと一致
`no_dns_forward_to_parent` の参照箇所のうち変更していない A~G(仕様書対応)を確認:
- A(`:635`)、C(`:675`): `no_dns == 0` のときのみ実行 → 本変更と無関係 ✅
- B(`:664`): 全ダウン時で意図的に変更しない ✅
- D(`:1671`): 親0台では `parentExists()` が false になり既にオリジンDNSへ落ちる構造 → 変更不要 ✅
- E(`:2142`): リバースDNS判定で直交 → 変更不要 ✅
- F(`:3442`): アサーション(不変条件)のみ → 変更不要 ✅
- G(`HttpSM.cc:4335`): `PARENT_UNDEFINED` 限定で、親0台は `PARENT_DIRECT` なので不発 → 変更不要 ✅

### 4. 新設定の登録・デフォルト・リロードが整合
- `RecordsConfig.cc`: `[0-1]`、デフォルト `"0"`、`RECU_DYNAMIC` ✅
- `HttpConfig.h`: `MgmtByte ... = 0` ✅
- `HttpConfig.cc:1179` `startup()` 登録 + `:1464` `reconfigure()` で `params->... = INT_TO_BOOL(m_master...)`(既存 `no_dns` と同列) ✅
- doc に `:reloadable:` ✅

### 5. スレッド/設定一貫性
`hasAnyParent()` はリクエスト時に `configProcessor.acquire()` が返すスナップショット(`ParentConfigParams`)の `parent_table`/`DefaultParent` を読むため reload に連動し、原子性の問題もない(既存 `parentExists` と同様)。`parent_params` の非NULL前提も既存(HttpSM.cc:397)と整合。

---

## 指摘事項(重要度順)

### [高] 自動テストが未追加
新機能に対するテストが一切追加されていない。以下を強く推奨する。

1. **`hasAnyParent()` の unit test**(`ParentSelection.cc` 内 SelfTests、または `proxy/http/remap/unit-tests` 相当)
   - 空 `parent_table` → false
   - 1エントリ以上 → true
   - `DefaultParent` 設定時 → true
2. **gold/behavior test**: 新設定 有効/無効 の2パターンで「親0台 + no_dns 有効」時のリクエスト結果(オリジンDNS送信 vs PARENT_FAIL/502)を検証。

仕様書の「影響範囲・リスク」節も「gold test を追加すると良い」と述べており、実装側もテストの必要性を認識している。

### [中] `hasAnyParent()` に `parent_table` の null ガードがない
```cpp
bool ParentConfigParams::hasAnyParent() const {
  return DefaultParent != nullptr || parent_table->getEntryCount() > 0;
}
```
`parent_table` を無条件に dereference している。実装上は `ParentConfigParams` コンストラクタと `reconfigure()` で必ず `new P_table(...)` されるため非NULLではあるが、防御的なチェック(`parent_table && ...`)やコメントが望ましい。既存コードも無条件 dereference しているのでリスクは低い。

### [中] 境界ケース1: parent.config が「go_direct のみ / no_parent のみ」の場合
`getEntryCount()` は**ルール行数**を返すため、実親を1台も持たない `dest_domain=... go_direct=true` のようなエントリがあっても `hasAnyParent() == true` になる。この場合、新機能(オリジンDNS許可)が**発動しない**(従来どおり PARENT_FAIL)。

- 「ルールが1つでもあれば『親あり』とみなす」という仕様として許容できる判断ではある。
- ただし、go_direct ルールは本来オリジン直結を意図するため、`no_dns` との併用時は意味的に矛盾しうる。少なくともコメント/ドキュメントに「エントリ基準」である旨と、この境界ケースを明記すべき。

### [中] 境界ケース2: default parent 設定との相互作用
`proxy.config.socks.default_servers` / default parent が設定されている場合、`parent_table` が空でも `DefaultParent != nullptr` となり `hasAnyParent() == true`。つまり「default parent あり＋parent.config 空」では新機能が発動しない。

- 設定ベースの判定としては一貫している(フォワード先がある)。
- ただし要件である「reload で空にしたらオリジンDNS」が、default parent 設定環境では効かない点を、仕様として明確にしておく必要がある(想定通りの挙動ならドキュメントへ明記)。

### [低] ドキュメントの補強
doc の記述:
> When enabled, ignore `proxy.config.http.no_dns_just_forward_to_parent` when there are no parents configured (for example, after reloading an empty `parent.config`).

正しく記述されているが、以下を追記すると親切。
- 「全親ダウン(利用不可)の場合は対象外で従来どおり失敗する」
- 「`hasAnyParent()` は設定エントリ基準のため、default parent あり or go_direct のみの場合は発動しない」
- (任意) 長い設定名 `disable_just_forward_to_parent_when_empty` に略語の注記。

### [低] 命名の冗長さ
`disable_just_forward_to_parent_when_empty` は長いが、挙動を正確に表しており実害はない。既存 `no_dns_just_forward_to_parent` との対比も分かりやすいため、そのままとして問題ない。

---

## 結論

**内容的にはマージ可。** 後方互換性の確保、4箇所の条件整合、設定ベース/可用性ベースの区別、変更不要箇所の判断はすべて正しい。

ただし **QA 担保のため以下を推奨**:
1. (必須に近い)`hasAnyParent()` の unit test と、新設定 有効/無効 × 親0台 の behavior/gold test を追加。
2. `go_direct` のみ・default parent ありの境界ケースについて、実装コメントとドキュメントへ明記。
3. `hasAnyParent()` の `parent_table` null ガード(防御的)。

上記1のテスト追加が完了すれば、このブランチの品質は十分確保されると判断する。
