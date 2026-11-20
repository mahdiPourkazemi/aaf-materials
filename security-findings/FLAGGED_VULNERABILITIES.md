# Flagged vulnerabilities — aaf-materials chat apps

Scan date: 2026-11-20  
Commit: `91d3b68923231b2670e152c4df65e6d927808562`  
Scope: `05-jetpack-compose`, `06-advanced-jetpack-compose`, `07-advanced-architecture` (starter + final)

Only findings with a realistic attacker and verified call chain are listed. Chapters 05/06 and 07-starter use local/FakeData only (no Ditto sync), so remote peer issues apply to **07-final**.

---

## 1. OnlinePlayground shared-token identity allows any credential holder full mesh R/W

| Field | Value |
| --- | --- |
| Severity | **Critical** |
| Primary file | `07-advanced-architecture/projects/final/app/src/main/java/com/kodeco/chat/MainActivity.kt` |
| Evidence | `MainActivity.kt:96-102`, `RepositoryImpl.kt:186`, `271-278`, `318-322`, `Constants.kt:40-41` |
| Call chain verified | **Yes** (static) |
| Attacker | Anyone who obtains `DITTO_APP_ID` + `DITTO_TOKEN` (APK reverse engineering, shared book credentials, another installed copy of the app) |

### Attack path

1. Obtain playground `appId` + `token` (see finding 2).
2. Initialize `DittoIdentity.OnlinePlayground` with those values and `startSync()` (same as `setupDitto()`).
3. Subscribe to hardcoded public messages collection `1440174b9330e430b46da939f0b04a34a40e10ac8073671156da174fef1ffaef`, plus `rooms` and `users`.
4. Read all synced messages/users; `upsert` arbitrary documents (messages, users, rooms).

Ditto documents OnlinePlayground as development-only: shared static token, no per-user identities, all connected clients can read/write all collections.

### Mitigations found

- None in app code. No `OnlineWithAuthentication`, no permission rules, no collection ACLs.
- `keys.properties` is gitignored (reduces source-leak risk only).

---

## 2. Playground credentials compiled into `BuildConfig` with minify disabled

| Field | Value |
| --- | --- |
| Severity | **High** |
| Primary file | `07-advanced-architecture/projects/final/app/build.gradle.kts` |
| Evidence | `build.gradle.kts:66`, `71-76`; consumed at `MainActivity.kt:98-99` |
| Call chain verified | **Yes** |
| Attacker | Anyone with a built APK/AAB (distributed debug/release binary) |

### Attack path

1. Builder places `DITTO_APP_ID` / `DITTO_TOKEN` in `keys.properties` (required by Gradle).
2. Both `debug` and `release` inject them via `buildConfigField`.
3. `isMinifyEnabled = false` leaves string literals recoverable from the APK (`BuildConfig` / smali / strings).
4. Credentials feed finding 1.

### Mitigations found

- `keys.properties` listed in `.gitignore` — **no live token values are in this repo** at scan time.
- Chapter 04 `keys.properties` only has keystore placeholders, not Ditto tokens.

---

## 3. No app-layer authorization: impersonation, message overwrite, user profile hijack

| Field | Value |
| --- | --- |
| Severity | **High** |
| Primary file | `07-advanced-architecture/projects/final/app/src/main/java/com/kodeco/chat/data/repository/RepositoryImpl.kt` |
| Evidence | `RepositoryImpl.kt:178-186` (`userId` client-chosen), `189-197` (user upsert by `_id`), `268-278` / `316-322` (`findAll` with no filters) |
| Call chain verified | **Yes** |
| Attacker | Malicious peer already on the playground mesh (finding 1) |

### Attack path

1. `users.findAll()` / message `findAll()` → learn victim `userId` / document `_id` values.
2. `upsert` a message with `userIdKey = <victimId>` → UI attributes text to that user (`MessageUiModel` joins on `userId`).
3. `upsert` `users` with same `_id` → overwrite display name.
4. `upsert` existing message `_id` → alter or replace others’ messages. App never checks author before write; playground grants write to all peers.

### Mitigations found

- None. No signed identity, no “only author may edit”, no delete/write guards in repository.

---

## 4. “Private” rooms are UUID secrecy only (QR join grants full access)

| Field | Value |
| --- | --- |
| Severity | **Medium** |
| Primary file | `07-advanced-architecture/projects/final/app/src/main/java/com/kodeco/chat/data/repository/RepositoryImpl.kt` |
| Evidence | `RepositoryImpl.kt:207-209`, `242-259` (comment: “qrCode join private room”) |
| Call chain verified | **Yes** (code path present; QR UI not wired in this chapter, but subscription helper exists) |
| Attacker | Peer who learns `collectionId` + `messagesId` (QR/shared link, logs, shoulder-surf) |

### Attack path

1. `isPrivate` only switches room metadata to a random collection UUID — no crypto, membership list, or Ditto permissions.
2. `addPrivateRoomSubscriptions(collectionId, messagesId)` subscribes `findAll()` on those collections for any caller who knows the IDs.
3. Same OnlinePlayground write capability applies → full read/write of that “private” room.

### Mitigations found

- Random UUIDs raise discovery cost only. No real authz.

---

## 5. Untrusted chat links opened via `uriHandler.openUri` without confirmation

| Field | Value |
| --- | --- |
| Severity | **Medium** |
| Primary file | `07-advanced-architecture/projects/final/app/src/main/java/com/kodeco/chat/conversation/Conversation.kt` |
| Evidence | `MessageFormatter.kt:53` (http/https regex), `187-199`; `Conversation.kt:381`; messages from Ditto `Message(document)` text at `ConversationUiState.kt:85-91` |
| Call chain verified | **Yes** |
| Attacker | Malicious peer (finding 1/3) injects `https://evil.example/...`; victim taps the styled link |

### Attack path

1. Peer upserts message text containing `https://…` phishing URL.
2. `messageFormatter` annotates it as `LINK`.
3. `ClickableText` → `uriHandler.openUri(annotation.item)` with no allowlist, interstitial, or user confirmation beyond the tap.

### Mitigations found

- Regex restricts schemes to `http`/`https` only (blocks `intent:`, `file:`, `javascript:`).
- Same formatter exists in 05/06 finals, but those modules lack a remote untrusted message source → not separately flagged.

---

## Out of scope / no finding

| Area | Result |
| --- | --- |
| Exported components / deep links | Only launcher `MAIN`/`LAUNCHER` on `MainActivity`. No custom schemes. |
| FileProvider / ContentProvider | None declared; no path XML. |
| Attachment path traversal | `PickVisualMedia` content URIs only; photo send path stubbed (`photoUri != null` skips Ditto write). |
| Classic XSS | Compose `ClickableText` / `Text`, not WebView/HTML. |
| `allowBackup=true` | Explicitly excluded per scan rules. |
| Live `DITTO_TOKEN` in git | Not present. |
| 05 / 06 / 07-starter remote peer issues | No Ditto sync; FakeData/local only. |
