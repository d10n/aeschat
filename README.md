# aeschat
AES encryption for IRC with HexChat

## Installation

### HexChat
 - Windows: download and run the latest HexChat and Python 2.7 installers.
     - Make sure to enable Python plugin support when installing HexChat.
 - Linux: install from a repository
 - Mac: brew install hexchat

### PyCrypto
 - Windows: download and run the [PyCrypto 2.6 for Python 2.7 installer](http://www.voidspace.org.uk/python/modules.shtml#pycrypto).
 - Linux: install from a distro repository or pip
 - Mac: pip install pycrypto

### aeschat
 - Copy aeschat.py and simplecrypt/ to the HexChat addons directory.
     - Windows: %APPDATA%\hexchat\addons\
     - Linux and Mac: ~/.config/hexchat/addons/

## Usage
 - aeschat is automatically loaded when HexChat starts up. [test]
 - Set a key for a channel by typing /AESKEY &lt;key&gt; in the channel.
 - Unset a key for a channel by typing /AESKEY in the channel.
 - Encrypted messages are denoted with a mark before the username.

## Notes
 - Python 2 and 3 are supported. Python 2 needs the d10n/simple-crypt fork.
     - The simplecrypt folder is from d10n/simple-crypt/src/simplecrypt and is currently included for ease of distribution
 - Channel messages and channel CTCP ACTION (/me) messages are handled.
 - One message typed multiple times will have different encrypted outputs.
 - Messages are compressed before encryption to allow longer messages.

## Future
 - Private message handling
 - DH2048 key exchange
 - Topic handling
 - General code cleaning and refactoring
