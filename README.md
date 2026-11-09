# Privacy Cleaner

A privacy-focused plugin for Exteragram.

## Features

- Removes metadata from supported photos and videos before sending.
- Cleans common tracking parameters from links.
- Performs offline checks for potentially phishing-related links.
- Displays information about chats and conversations.
- Detects the recording client of Telegram round videos when the required information is available.
- Keeps processing on the device; the plugin description states that it does not require network access.

## Installation

1. Download `privacy_cleaner.plugin` from the repository.
2. Send the file to **Saved Messages** in Telegram.
3. Open the file in Exteragram.
4. Confirm installation in the plugin installation dialog.

## Source code

`privacy_cleaner.py` contains the readable Python source. `privacy_cleaner.plugin` is the installable plugin file. They contain the same code.

## Credits

- **Sato.py (@m0lex)** — Privacy Cleaner and original project code.
- **Link Guard (@Robobloxi)** — integrated link-cleaning and phishing-detection code, used with the author's permission.
- **Round Client Detector (@netconfiger)** — integrated round-video client-detection code, used with the author's permission.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and permission notes.

## Version

0.3.0
