"""
Implements the LUKS (Linux Unified Key Setup) Version 1.0
on disk specification inside a file.

http://luks.endorphin.org/

LUKS offers:
    * compatiblity via standardization,
    * secure against low entropy attacks,
    * support for multiple keys,
    * effective passphrase revocation,

This module is compatible with dm-crypt and cryptsetup tools for the Linux
kernel, as long as hashSpec="sha1" is used. Loopback files or partitions created
with the linux kernel can be decrypted using this module.  FreeOTFE
(http://www.freeotfe.org/) should provide support for reading and writing on
Windows.

This module has one class LuksFile.

Loading a LUKS disk image (use both, one after another):
- load_from_file(file)
- open_any_key(password)

Creating a new LUKS disk image (use both):
- create(file, cipherName, cipherMode, hashSpec, masterSize, stripes)
- set_key(0, password, iterations)

Once a file is unlocked (either because it was just created or
open_any_key() returned True), you can perform the key operations:
- enabled_key_count()
- key_information(keyIndex)
- set_key(keyIndex, password, iterations)
- delete_key(keyIndex)

Once a file is unlocked, you can perform data encryption/decryption with
- data_length()
- encrypt_data(offset, data)
- decrypt_data(offset, length)
- truncate(length)

Finally, to close the file:
- close()

Copyright 2006 John Lenz <lenz@cs.wisc.edu>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

http://www.gnu.org/copyleft/gpl.html
"""

import math
import struct
import hashlib
from Crypto.Cipher import AES, CAST, Blowfish
import PBKDFv2
import AfSplitter


class LuksError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class LuksFile:
    """Implements the LUKS (Linux Unified Key Setup) Version 1.0 http://luks.endorphin.org/"""

    LUKS_FORMAT = ">6sH32s32s32sII20s32sI40s"
    LUKS_MAGIC = "LUKS\xba\xbe"

    LUKS_KEY_DISABLED = 0x0000DEAD
    LUKS_KEY_ENABLED = 0x00AC71F3

    SECTOR_SIZE = 512.0

    KEY_STRIPES = 4000
    SALT_SIZE = 32
    DIGEST_SIZE = 20

    def __init__(self):
        self.file = None
        self.masterKey = None
        self.ivGen = None

    # Read the header from the file descriptor
    def load_from_file(self, file):
        """Initialize this LuksFile class from the file.

          The file parameter should be an object implementing the File Object API
              This function will error if the file is not a LUKS partition (the LUKS_MAGIC does not match)
          """

        if self.file != None:
            raise LuksError("This LuksFile has already been initialized")

        # Read the main parameters
        self.file = file

        magic = self.file.read(6)
        # check magic
        if magic != self.LUKS_MAGIC:
            self.file = None
            raise LuksError("%s is not a LUKS data file" % file.name)

        self.file.seek(0)

        self.magic,\
        self.version,\
        cipherName,\
        cipherMode,\
        hashSpec,\
        self.payloadOffset,\
        self.keyBytes,\
        self.mkDigest,\
        self.mkDigestSalt,\
        self.mkDigestIterations,\
        self.uuid =\
        struct.unpack(self.LUKS_FORMAT, self.file.read(208))

        # check magic
        if self.magic != self.LUKS_MAGIC:
            self.file = None
            raise LuksError("%s is not a LUKS data file" % file.name)

        # Check the hash and cipher
        self.hashSpec = hashSpec.strip(" \x00")
        self._check_cipher(cipherName.strip(" \x00"), cipherMode.strip(" \x00"))

        # Load the key information
        self.keys = [None] * 8
        for i in range(0, 8):
            self.keys[i] = self._key_block()
            self.keys[i].load_from_str(self.file.read(48))

        # set the digest to be the correct size
        self.mkDigest = self.mkDigest[:hashlib.new(self.hashSpec).digest_size]

        self.masterKey = None

    def open_key(self, keyIndex, password):
        """Open a specific keyIndex using password.  Returns True on success"""

        if self.file == None:
            raise LuksError("LuksFile has not been initialized")

        if keyIndex < 0 or keyIndex > 7:
            raise LuksError("keyIndex is out of range")

        key = self.keys[keyIndex]

        if key.active != self.LUKS_KEY_ENABLED:
            return False

        # Hash the password using PBKDFv2
        pbkdf = PBKDFv2.PBKDFv2()
        derived_key = pbkdf.makeKey(password, key.passwordSalt, key.passwordIterations, self.keyBytes, self.hashSpec)

        # Setup the IV generation to use this key
        self.ivGen.set_key(derived_key)

        # Decrypt the master key data using the hashed password
        AfKeySize = key.stripes * self.keyBytes
        AfSectors = int(math.ceil(float(AfKeySize) / self.SECTOR_SIZE))
        AfKey = ""
        for sector in range(0, AfSectors):
            AfKey += self._decrypt_sector(derived_key, key.keyMaterialOffset + sector, sector)
        AfKey = AfKey[0:AfKeySize]

        # Merge the decrypted master key
        masterKey = AfSplitter.AFMerge(AfKey, key.stripes, self.hashSpec)

        # Check if the password was the correct one, by checking the master key digest
        checkDigest = pbkdf.makeKey(masterKey, self.mkDigestSalt, self.mkDigestIterations, hashlib.new(self.hashSpec).digest_size, self.hashSpec)

        # Since the header only stores DIGEST_SIZE (which is smaller than sha256 digest size)
        #   trim the digest to DIGEST_SIZE
        checkDigest = checkDigest[:self.DIGEST_SIZE]

        if checkDigest != self.mkDigest:
            return False

        return True

    def open_any_key(self, password):
        """Try to open any enabled key using the provided password.  Returns index number on success, or None"""

        if self.file == None:
            raise LuksError("LuksFile has not been initialized")

        for i in range(0, 8):
            if self.open_key(i, password):
                return i
        return None

    def enabled_key_count(self):
        """Returns the number of enabled key slots"""

        if self.file == None:
            raise LuksError("LuksFile has not been initialized")

        cnt = 0
        for i in range(0, 8):
            if self.keys[i].active == self.LUKS_KEY_ENABLED:
                cnt += 1
        return cnt

    def key_information(self, keyIndex):
        """Returns a tuple of information about the key at keyIndex (enabled, iterations, stripes)"""

        if self.file == None:
            raise LuksError("LuksFile has not been initialized")

        if keyIndex < 0 or keyIndex > 7:
            raise LuksError("keyIndex out of range")

        key = self.keys[keyIndex]
        active = (key.active == self.LUKS_KEY_ENABLED)
        return (active, key.passwordIterations, key.stripes)

    def data_length(self):
        """Returns the total data length"""

        if self.file == None:
            raise LuksError("LuksFile has not been initialized")

        # Seek to the end of the file, and use tell()
        self.file.seek(0, 2)
        fLen = self.file.tell()
        return fLen - int(self.payloadOffset * self.SECTOR_SIZE)

    ##### Private functions

    class _key_block:
        """Internal class, used to store the key information about each key."""

        LUKS_KEY_FORMAT = ">II32sII"

        def load_from_str(self, str):
            """Unpack the key information from a string"""
            self.active,\
            self.passwordIterations,\
            self.passwordSalt,\
            self.keyMaterialOffset,\
            self.stripes =\
            struct.unpack(self.LUKS_KEY_FORMAT, str)

        def create(self, offset, stripes, disabled):
            """Create a new set of key information.  Called from LuksFile.create()"""
            self.active = disabled
            self.passwordIterations = 0
            self.passwordSalt = ''
            self.keyMaterialOffset = offset
            self.stripes = stripes

        def save(self):
            """Pack the key information into a string"""
            return struct.pack(self.LUKS_KEY_FORMAT, self.active, self.passwordIterations,\
                               self.passwordSalt, self.keyMaterialOffset, self.stripes)

    class _plain_iv_gen:
        """Internal class to represent cbc-plain cipherMode"""

        def set_key(self, key):
            # plain IV generation does not use the key in any way
            pass

        def generate(self, sectorOffset, size):
            istr = struct.pack("<I", sectorOffset)
            return istr + "\x00" * (size - 4)

    class _essiv_gen:
        """Internal class to represent cbc-essiv:<hash> cipherMode"""

        # essiv mode is defined by
        # SALT=Hash(KEY)
        # IV=E(SALT,sectornumber)
        def __init__(self, str, cipher, luksParent):
            self.hashSpec = str[1:]
            self.cipher = cipher

        def set_key(self, key):
            h = hashlib.new(self.hashSpec, key)
            self.salt = h.digest()
            self.encr = self.cipher.new(self.salt, self.cipher.MODE_ECB)

        def generate(self, sectorOffset, size):
            istr = struct.pack("<I", sectorOffset) + "\x00" * (size - 4)
            return self.encr.encrypt(istr)

    def _check_cipher(self, cipherName, cipherMode):
        """Internal function to check for a valid cipherName and cipherMode"""
        if cipherName == "aes":
            self.cipher = AES
        elif cipherName == "cast5":
            self.cipher = CAST
        elif cipherName == "blowfish":
            self.cipher = Blowfish
        else:
            raise LuksError("invalid cipher %s" % cipherName)

        # All supported ciphers are block ciphers, so modes are the same (CBC)
        self.mode = self.cipher.MODE_CBC

        if cipherMode == "cbc-plain":
            self.ivGen = self._plain_iv_gen()
        elif cipherMode[:10] == "cbc-essiv:":
            self.ivGen = self._essiv_gen(cipherMode[9:], self.cipher, self)
        else:
            raise LuksError("invalid cipher mode %s" % cipherMode)

        self.cipherName = cipherName
        self.cipherMode = cipherMode

    def _decrypt_sector(self, key, sector, sectorOffset):
        """Internal function to decrypt a single sector"""

        # Read the ciphertext from disk
        self.file.seek(int(sector * self.SECTOR_SIZE))
        encrData = self.file.read(int(self.SECTOR_SIZE))

        # Decrypt the data using cipher, iv generation, and mode
        IV = self.ivGen.generate(sectorOffset, self.cipher.block_size)
        cipher = self.cipher.new(key, self.mode, IV)
        return cipher.decrypt(encrData)

# The following was copied from the reference implementation of LUKS in cryptsetup-luks-1.0.1 from
# http://luks.endorphin.org/dm-crypt

#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20 // since SHA1
#define LUKS_HMACSIZE 32
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
#define LUKS_MAGIC_L 6

#/* Actually we need only 37, but we don't want struct autoaligning to kick in */
#define UUID_STRING_L 40

#struct luks_phdr {
#	char		magic[LUKS_MAGIC_L];
#	uint16_t	version;
#	char		cipherName[LUKS_CIPHERNAME_L];
#	char		cipherMode[LUKS_CIPHERMODE_L];
#	char            hashSpec[LUKS_HASHSPEC_L];
#	uint32_t	payloadOffset;
#	uint32_t	keyBytes;
#	char		mkDigest[LUKS_DIGESTSIZE];
#	char		mkDigestSalt[LUKS_SALTSIZE];
#	uint32_t	mkDigestIterations;
#	char            uuid[UUID_STRING_L];
#
#	struct {
#		uint32_t active;
#
#		/* parameters used for password processing */
#		uint32_t passwordIterations;
#		char     passwordSalt[LUKS_SALTSIZE];
#
#		/* parameters used for AF store/load */
#		uint32_t keyMaterialOffset;
#		uint32_t stripes;
#	} keyblock[LUKS_NUMKEYS];
#};

# size is 208 bytes + 48 * LUKS_NUMKEYS  = 592 bytes

import sys
if len(sys.argv) < 2:
    print >> sys.stderr, "Usage: %s <LUKS file>" % sys.argv[0]
    sys.exit(-1)

obj = LuksFile()
f = open(sys.argv[1])
obj.load_from_file(f)
#print obj.key_information(0)

line = sys.stdin.readline()
while line:
    line = line.rstrip()
    ret = obj.open_any_key(line)
    if ret is not None:
        print "Password Found : %s" % line
        sys.exit(0)
    line = sys.stdin.readline()
