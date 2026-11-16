# Blades of Fire Save Converter

Move your **Blades of Fire** progress between the **Epic Games Store** and **Steam** versions of the game on PC.

The two versions use the same save format, but encrypt it with different keys, so a save copied from one
store's folder to the other won't load. This tool decrypts a save with the source store's key and
re-encrypts it with the destination store's key. The save data itself is left exactly as it was.

It comes in two equivalent flavours; use whichever suits you:

| Script | Runs on | Needs |
|---|---|---|
| `bof_save_convert.py` | Windows, Linux (incl. Proton / Steam Deck), macOS | Python 3.6+ (no extra packages) |
| `Convert-BoFSave.ps1` | Windows | Windows PowerShell 5.1 or PowerShell 7 (built in to Windows 10/11) |

Both convert in either direction (Epic → Steam or Steam → Epic).

## Before you start

1. **Close the game** on both stores.
2. **Launch the game on the destination store at least once** and get to the main menu, so it creates its save folder.
   Then quit.
3. **Make your own backup** of both save folders (just copy them somewhere). The tool also backs up the destination save
   automatically, but an extra copy never hurts.

## Finding your save folders

On Windows, saves live in:

```
%LOCALAPPDATA%\MercurySteam\Blades of Fire\
```

(paste that into the Explorer address bar). Inside there is one folder per account:

| Store | Folder name looks like | Example |
|---|---|---|
| Steam | your 17-digit SteamID64 | `76561198000000000` |
| Epic Games | your 32-character Epic account ID | `0123456789abcdef0123456789abcdef` |

Each folder contains a `Profile.BoF` (your progress) and `game.cfg` (settings). The tool only converts `Profile.BoF`.

**Linux / Steam Deck (Proton):** the folder is inside the game's Proton prefix:

```
~/.steam/steam/steamapps/compatdata/<appid>/pfx/drive_c/users/steamuser/AppData/Local/MercurySteam/Blades of Fire/
```

If you're not sure where it is, run:

```sh
find ~ -type d -path '*MercurySteam/Blades of Fire' 2>/dev/null
```

For the Epic version under Heroic, Lutris etc., look for the same `AppData/Local/MercurySteam/Blades of Fire` path inside
that game's Wine prefix.

## Usage: Python (any OS)

Download `bof_save_convert.py`, then:

```sh
python3 bof_save_convert.py  <SOURCE folder>  <DESTINATION folder>
```

Windows example (Epic → Steam), from Command Prompt:

```bat
python bof_save_convert.py "%LOCALAPPDATA%\MercurySteam\Blades of Fire\0123456789abcdef0123456789abcdef" "%LOCALAPPDATA%\MercurySteam\Blades of Fire\76561198000000000"
```

Linux / Steam Deck example (Steam → Epic):

```sh
SAVES=~/.steam/steam/steamapps/compatdata/<appid>/pfx/drive_c/users/steamuser/AppData/Local/MercurySteam/"Blades of Fire"
python3 bof_save_convert.py "$SAVES/76561198000000000" "/path/to/epic/prefix/.../Blades of Fire/0123456789abcdef0123456789abcdef"
```

On Windows use `python` (or `py`) instead of `python3`. Run `python3 bof_save_convert.py --help` for all options.

No extra packages are required. If you happen to have `cryptography` or `pycryptodome` installed, the script uses it
and finishes almost instantly; otherwise it uses a built-in AES implementation that takes a couple of seconds.

## Usage: PowerShell (Windows)

Download `Convert-BoFSave.ps1`, open PowerShell in the folder you saved it to, and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Convert-BoFSave.ps1 `
  -Source      "$env:LOCALAPPDATA\MercurySteam\Blades of Fire\0123456789abcdef0123456789abcdef" `
  -Destination "$env:LOCALAPPDATA\MercurySteam\Blades of Fire\76561198000000000"
```

`-ExecutionPolicy Bypass` applies to this one run only. It's needed because Windows blocks downloaded scripts by
default. (Alternatively run `Unblock-File .\Convert-BoFSave.ps1` once.)

Run `Get-Help .\Convert-BoFSave.ps1 -Full` for details.

## Options

Both scripts take the same options:

| Python | PowerShell | Meaning |
|---|---|---|
| `SOURCE` | `-Source` | Source save folder, or the `Profile.BoF` inside it |
| `DESTINATION` | `-Destination` | Destination save folder, or the `Profile.BoF` inside it |
| `--source-id ID` | `-SourceId ID` | Account ID to decrypt the source with, if its folder has been renamed |
| `--target-id ID` | `-TargetId ID` | Account ID to encrypt for, if the destination folder isn't named after the account |
| `--no-backup` | `-NoBackup` | Don't back up an existing destination `Profile.BoF` |

By default the platform is worked out from the folder names: 17 digits means Steam, 32 hex characters means Epic.

## After converting

* **Steam Cloud:** the first time you launch the Steam version afterwards, Steam may say your local and cloud saves
  don't match. **Choose the local files**, otherwise Steam will put your old cloud save back.
* **Backups:** if the destination already had a save, it was copied to `Profile.BoF.bak-<date>-<time>` next to it.
  To undo the conversion, delete `Profile.BoF` and rename that backup back to `Profile.BoF`.

## Safety

* The source save is only ever read, never modified.
* Before writing anything, the tool checks the source decrypts to a valid save (magic header and SHA-256 checksum) and
  that the re-encrypted copy decrypts back correctly. If either check fails, nothing is written.
* Both stores need to be on the same game version. If an update ever changes the encryption, the tool refuses to
  convert rather than producing a broken save.

## How it works

`Profile.BoF` is always 1,056,840 bytes:

| Offset | Size | Contents |
|---|---|---|
| `0x0000` | `0x2028` | Unencrypted header: `RGMH`, version, GUID, `"Mercury Engine"` |
| `0x2028` | `0x100020` | AES-256-CBC encrypted payload (all-zero IV, no padding) |

Decrypted payload:

| Offset | Contents |
|---|---|
| `0x000000` | `"0002"`, uint32 compressed size, LZ4 block containing the save data |
| `0x100000` | SHA-256 of the first `0x100000` bytes, every byte XORed with `0x01` |

The AES key is a 64-hex-digit constant built into the game. Before the game hex-decodes it into the 32-byte key, it
writes the platform user-ID string over the start of it:

* **Steam:** no user ID is mixed in, so the constant is used as-is.
* **Epic:** the 32-character Epic account ID replaces the first 32 hex digits.

The save data itself contains no account IDs, so changing stores only means changing the key.

## Disclaimer

This is an unofficial fan-made tool. It isn't affiliated with or endorsed by MercurySteam, 505 Games, Epic Games or
Valve. It has been tested with the November 2026 builds of the game, but back up your saves anyway. Use at your own
risk.

## License

[MIT](LICENSE)
