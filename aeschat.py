#
# -*- coding: utf8 -*-
# aeschat.py
# ugly and only with basic functionality
# but it works for now and will be improved

import hexchat
import base64
import zlib  # better than bz2 for very short text
import os
import sys
SCRIPT_DIR = os.path.join(hexchat.get_info('configdir'), 'addons')
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)  # needed for reloading this file
import simplecrypt

# simplecrypt default: 10000. Expansion takes a second.
# truecrypt default: 1000. Expansion time is negligible.
simplecrypt.EXPANSION_COUNT = 2000
# simplecrypt default: 128
# truecrypt default: 512. Can't be a bad idea after lowering EXPANSION_COUNT
simplecrypt.SALT_LEN = 512
# simplecrypt default: b'sc\x00\x00'
# Change to avoid confusion with different default EXPANSION_COUNT and SALT_LEN
simplecrypt.HEADER = b'xc\x00\x00'  # must be 4 bytes


__author__ = 'd10n'
__module_name__ = 'aeschat'
__module_version__ = '0.0.1'
__module_description__ = 'AES end-to-end encryption'

IS_PY2 = sys.version_info[0] == 2
FLAG = '++OK'
IRC_MAX_MESSAGE_LENGTH = 512
if IS_PY2:
    safety_mark = u'\u2713\u00a0'.encode('utf-8')
else:
    safety_mark = u'\u2713\u00a0'


channel_keys = {}
# keys[server+channel] = 'key'

ctcp_escape = lambda x: '\x01' + x + '\x01'


def decrypt_privmsg(word, word_eol, userdata):
    if not word[1].startswith(FLAG):
        return hexchat.EAT_NONE
    context = hexchat.get_context()
    server = context.get_info('server')
    channel = context.get_info('channel')
    if not server + channel in channel_keys:
        return hexchat.EAT_NONE
    nick = word[0]
    message_b64 = word[1][len(FLAG):]
    message_aes = base64.standard_b64decode(message_b64.strip())
    try:
        message_gzip = simplecrypt.decrypt(
            channel_keys[server + channel], message_aes)
    except simplecrypt.DecryptionException as ex:
        return hexchat.EAT_NONE
    if not IS_PY2:
        message_gzip = message_gzip.decode('utf8')
    message_raw = zlib.decompress(message_gzip)

    context.command('RECV :{} PRIVMSG {} :{}'.format(
        safety_mark + nick, channel, message_raw
    ))
    return hexchat.EAT_ALL


def encrypt_privmsg(word, word_eol, userdata):
    context = hexchat.get_context()
    server = context.get_info('server')
    channel = context.get_info('channel')
    if not server + channel in channel_keys:
        return hexchat.EAT_NONE
    message_raw = word_eol[0]
    if userdata == 'CTCP':
        ctcp_type, _, message_raw = message_raw.partition(' ')
        if ctcp_type.lower() in ['me', 'action']:
            ctcp_type = 'ACTION'
        message_raw = ctcp_escape('{} {}'.format(ctcp_type, message_raw))
    message_gzip = zlib.compress(message_raw, 9)
    message_aes = simplecrypt.encrypt(
        channel_keys[server + channel], message_gzip)
    message_b64 = base64.standard_b64encode(message_aes)
    nick = context.get_info('nick')
    message_prototype = 'PRIVMSG {} :{}{}'
    user_list = context.get_list('users')
    my_host = 'temp.host'
    for user in user_list:
        if user.nick == nick:
            my_host = user.host
            break
    if not IS_PY2:
        message_b64 = message_b64.decode('utf-8')
    message_length = len(':{}!{} '.format(nick, my_host) +
                         message_prototype.format(channel, FLAG, message_b64))
    if message_length > IRC_MAX_MESSAGE_LENGTH:
        context.prnt(
            '{}: compressed message too long to send by {} bytes. '.format(
                __module_name__, message_length - IRC_MAX_MESSAGE_LENGTH))
        return hexchat.EAT_ALL
    context.command(message_prototype.format(channel, FLAG, message_b64))
    # lets you highlight yourself but less ugly than handling events manually
    context.command('RECV :{} PRIVMSG {} :{}'.format(
        safety_mark + nick, channel, message_raw
    ))
    return hexchat.EAT_ALL


def set_aes_key(word, word_eol, userdata):
    context = hexchat.get_context()
    server = context.get_info('server')
    channel = context.get_info('channel')
    if len(word) < 2:
        if server + channel in channel_keys:
            del channel_keys[server + channel]
        hexchat.prnt('AESKEY: key for {} @ {} cleared'.format(channel, server))
        return hexchat.EAT_ALL
    if len(server) == 0 or '#' not in channel:
        hexchat.prnt('AESKEY: no key set; use while in a channel')
        return hexchat.EAT_ALL
    channel_keys[server + channel] = word[1]
    # base64 encode so passwords don't show up with grep or something similar
    hexchat.set_pluginpref(
        __module_name__, base64.standard_b64encode(repr(channel_keys))
    )
    hexchat.prnt('AESKEY: key for {} @ {} set'.format(channel, server))
    return hexchat.EAT_ALL


if __module_name__ in hexchat.list_pluginpref():
    import ast
    keys_b64 = hexchat.get_pluginpref(__module_name__)
    try:
        keys_string = base64.standard_b64decode(keys_b64)
        channel_keys = ast.literal_eval(keys_string)
    except TypeError as ex:
        pass


hexchat.hook_print('Channel Message', decrypt_privmsg)
hexchat.hook_command('', encrypt_privmsg)  # sending regular message
hexchat.hook_command('ACTION', encrypt_privmsg, 'CTCP')
hexchat.hook_command('ME', encrypt_privmsg, 'CTCP')
hexchat.hook_command('AESKEY', set_aes_key,
                     help='/AESKEY "<key>"  Set an encryption key for '
                          'the current channel. Blank key to unset.')
hexchat.hook_unload(lambda x: hexchat.prnt(__module_name__ + ' unloaded'))
hexchat.prnt(__module_name__ + ' loaded')
