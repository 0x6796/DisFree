# DisFree BRHU3

**DisFree** is a Go project focused on one thing: **freedom to access Discord**.


DisFree exists so a network restriction, filter, routing problem or blocked startup path does not have to decide whether you can reach your friends, communities and conversations on Discord. The project uses a temporary VPN bootstrap only for the part that needs it, then gets out of the way and returns Discord to the normal connection.

## Freedom first

The idea behind DisFree is simple:

> Your connection should not decide whether you are allowed to reach your community.

DisFree is not designed to keep all of your traffic behind a VPN forever. Its goal is narrower: give Discord the temporary path it needs to start and establish its Gateway session, then restore the normal internet connection as soon as possible.

That means the project is built around three principles:

- **Access:** help Discord get online when the normal startup path is restricted or unreliable.
- **Freedom:** keep the user in control of the connection instead of forcing a permanent VPN route.
- **Minimal interference:** tunnel only the bootstrap phase that needs help, then return traffic to the normal network.

The VPN protocol/data-channel implementation is part of this repository. DisFree does not invoke an OpenVPN executable.

## VPN provider: RiseupVPN

DisFree uses the public **RiseupVPN** infrastructure as its VPN provider.

- RiseupVPN: https://riseup.net/en/vpn

RiseupVPN provides the VPN infrastructure. DisFree implements its own client-side protocol, routing and Discord handoff logic. DisFree is an independent project and is not an official Riseup Networks or Discord project.

## How it works

The handoff point is the Discord Gateway state:

`SESSION_ESTABLISHED`

Until that point, DisFree can provide the temporary RiseupVPN path needed for Discord startup. Once the Gateway session is established, DisFree removes the VPN path and lets Discord continue on the normal connection.

### Windows

- Discord updater stays on the normal connection.
- When the main Discord window starts, Discord TCP bootstrap traffic is routed through the Riseup session.
- The first TCP SYN is captured before the per-flow route is installed.
- At `SESSION_ESTABLISHED`, the Riseup session and WinDivert interception are closed.
- Discord continues over the normal internet connection.
- Closing the DisFree console closes Discord.

Windows packet interception uses the embedded WinDivert runtime under `windows/third_party/windivert/`.

### Linux

- Discord stays in the normal user environment.
- A local proxy keeps updater traffic direct.
- At main-window launch, new TCP connections use the temporary Riseup tunnel.
- At `SESSION_ESTABLISHED`, the TUN/Riseup path is closed and the proxy returns to direct mode.
- UDP/voice remains on the normal host network.

## Source layout

```text
.
├── *.go                         DisFree source
├── *_test.go                    unit tests
├── go.mod
├── icon.ico                     Windows application icon source
└── windows/
    └── third_party/
        └── windivert/
            ├── WinDivert.dll
            ├── WinDivert64.sys
            └── LICENSE.txt
```

The WinDivert DLL/driver are intentionally kept in the source tree because `windivert_windows.go` embeds them into the Windows build. Generated executables, old builds, backups, logs, identities and ping-test utilities are not part of this source folder.

## Build

Windows:

```powershell
go test ./...
go build -o DisFree.exe .
```

Linux amd64:

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o DisFree .
```

## Runtime data

Client identities/private keys are runtime data and must not be committed. Keep `identity.pem`, logs and generated binaries outside the repository.

## Project scope

DisFree is not intended to be a general-purpose full-device VPN client. Its focus is Discord freedom: helping Discord establish access when the normal path cannot, and handing control back to the normal connection immediately afterward.

## License

DisFree is free software licensed under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**.

You are free to use, study, modify and redistribute DisFree under the terms of the GNU GPL. If you distribute modified versions, the corresponding source must remain available under the GPL terms.

See [`LICENSE`](LICENSE) for the full license text.

The bundled WinDivert files retain their own upstream license in `windows/third_party/windivert/LICENSE.txt`.
