from enum import Enum, unique


@unique
class AttackMode(Enum):
    """Enum to easily access attack modes"""

    straight = 0
    combination = 1
    brute_force = 3
    hybrid_wordlist_mast = 6
    hybrid_mask_wordlist = 7
    association = 9

    def resolve_mode(mode):
        """
        Take either an int of AttackMode and return the appropriate attack
        mode. If the give mode argument can't be resolved to an AttackMode,
        throw a TypeError
        """

        if type(mode) == int:
            mode = AttackMode(mode)
        if type(mode) != AttackMode:
            error = "Attack mode must be set to AttackMode or int,"
            error += f" got {type(mode)}"
            raise TypeError(error)
        return mode


@unique
class HashMode(Enum):
    """Enum to easily access hash modes"""

    md5 = 0
    sha1 = 100
    sha2_224 = 1300
    sha2_256 = 1400
    sha2_384 = 10800
    sha2_512 = 1700
    sha3_224 = 17300
    sha3_256 = 17400
    sha3_384 = 17500
    sha3_512 = 17600

    def resolve_mode(mode):
        """
        Take either an int or HashMode and return the appropriate hash mode. If
        the give mode argument can't be resolved to a HashMode, throw a
        TypeError
        """

        if type(mode) == int:
            mode = HashMode(mode)
        if type(mode) != HashMode:
            error = "Hash mode must be set to HashMode or int,"
            error += f" got {type(mode)}"
            raise TypeError(error)
        return mode
