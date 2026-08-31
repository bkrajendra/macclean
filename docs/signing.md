# MacClean — Code Signing & Notarisation

The release workflow is already wired for Developer ID signing + notarisation.
It's **opt-in**: it stays ad-hoc-signed until you add the secrets below and set
one repository variable. Nothing in the code changes.

> Why bother: an ad-hoc-signed build gets a new code identity every time it's
> rebuilt, so macOS won't carry a **Full Disk Access** grant across updates —
> you'd re-add MacClean in System Settings after every release. A notarised
> Developer ID build has a stable identity and the grant persists.

---

## One-time: create the certificate

You need an **Apple Developer Program** membership.

### 1. Team ID
<https://developer.apple.com/account> ▸ **Membership** ▸ *Team ID* (10 chars, e.g. `AB12CD34EF`).

### 2. "Developer ID Application" certificate

1. Keychain Access ▸ menu **Certificate Assistant ▸ Request a Certificate From a
   Certificate Authority** ▸ enter your email, choose *Saved to disk* ▸ save
   `CertificateSigningRequest.certSigningRequest`.
2. <https://developer.apple.com/account/resources/certificates> ▸ **+** ▸
   **Developer ID Application** ▸ upload the CSR ▸ download the `.cer`.
3. Double-click the `.cer` to add it to your login keychain.
4. In Keychain Access ▸ *My Certificates*, find
   **`Developer ID Application: Your Name (TEAMID)`**, right-click ▸ **Export…**
   ▸ save as `macclean-signing.p12` with a password (remember it).

### 3. App-specific password (for notarisation)
<https://account.apple.com> ▸ **Sign-In and Security ▸ App-Specific Passwords** ▸
**+** ▸ label it `macclean-notary` ▸ copy the `xxxx-xxxx-xxxx-xxxx` value.

### 4. Base64 the certificate
```bash
base64 -i macclean-signing.p12 | pbcopy
```

---

## Add to GitHub

**Settings ▸ Secrets and variables ▸ Actions ▸ Secrets** → *New repository secret*:

| Secret | Value |
|--------|-------|
| `APPLE_CERTIFICATE` | the base64 string from step 4 |
| `APPLE_CERTIFICATE_PASSWORD` | the `.p12` export password |
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: Your Name (TEAMID)` — the exact name from Keychain |
| `APPLE_ID` | your Apple ID email |
| `APPLE_PASSWORD` | the app-specific password from step 3 |
| `APPLE_TEAM_ID` | your 10-char Team ID |

**Settings ▸ Secrets and variables ▸ Actions ▸ Variables** → *New repository variable*:

| Variable | Value |
|----------|-------|
| `ENABLE_APPLE_SIGNING` | `true` |

That's it. The next `feat:` / `fix:` push to `main` runs the **“Build (Developer
ID signed + notarised)”** step: `tauri build` signs the `.app`, submits the
`.dmg` to Apple's notary service, waits, and staples the ticket. The GitHub
Release then carries a notarised `.dmg` + `.app.zip`.

---

## Alternative: App Store Connect API key (instead of Apple ID + password)

If you prefer an API key for notarisation:

1. App Store Connect ▸ **Users and Access ▸ Integrations ▸ App Store Connect API**
   ▸ generate a key with the **Developer** role ▸ download the `.p8` (once only).
   Note the **Key ID** and **Issuer ID**.
2. Add secrets instead of `APPLE_ID` / `APPLE_PASSWORD`:

   | Secret | Value |
   |--------|-------|
   | `APPLE_API_KEY` | the Key ID |
   | `APPLE_API_ISSUER` | the Issuer ID |
   | `APPLE_API_KEY_PATH` | `~/private_keys/AuthKey_<KEYID>.p8` — the workflow writes it from `APPLE_API_KEY_CONTENT` |
   | `APPLE_API_KEY_CONTENT` | contents of the `.p8` file |

The signed build step passes all of these through; Tauri uses the API key when
present and falls back to `APPLE_ID` / `APPLE_PASSWORD` otherwise.

---

## Verify a build

```bash
codesign -dv --verbose=4 /Applications/MacClean.app     # Authority=Developer ID Application: …
spctl -a -vvv -t install /Applications/MacClean.app     # accepted  source=Notarized Developer ID
xcrun stapler validate /Applications/MacClean.app       # The validate action worked!
```

## Local signed build (optional)

```bash
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="you@example.com"
export APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export APPLE_TEAM_ID="AB12CD34EF"
npm run tauri build -- --target universal-apple-darwin
```

## Never commit

The `.p12`, `.p8`, CSR, passwords or Team-scoped credentials. They live only in
GitHub Secrets.
