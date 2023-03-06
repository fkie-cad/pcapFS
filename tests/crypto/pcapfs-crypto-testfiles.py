#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  pcapfs-crypto-testfiles.py
#
#


def generate_testfile_single(word_size=15, count=1):
    with open("files/file_a_single", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def generate_testfile_tiny(word_size=15, count=32):
    with open("files/file_b_tiny", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def generate_testfile_small(word_size=15, count=1024):
    with open("files/file_c_small", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def generate_testfile_medium(word_size=15, count=16 * 1024):
    with open("files/file_d_medium", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def generate_testfile_large(word_size=15, count=16 * 16 * 1024):
    with open("files/file_e_large", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def generate_testfile_xl(word_size=15, count=16 * 16 * 16 * 1024):
    with open("files/file_f_xl", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def generate_testfile_xxl(word_size=15, count=16 * 16 * 16 * 16 * 1024):
    with open("files/file_g_xxl", "w") as small:
        for i in range(0, count):
            word = "%0" + str(word_size) + "i\n"
            small.write(word % i)


def main(args):
    print(
        """
                                                    $$$$$$\
                                                   $$  __$$\
             $$$$$$\   $$$$$$$\ $$$$$$\   $$$$$$\  $$ /  \__|$$$$$$$\
            $$  __$$\ $$  _____|\____$$\ $$  __$$\ $$$$\    $$  _____|
            $$ /  $$ |$$ /      $$$$$$$ |$$ /  $$ |$$  _|   \$$$$$$\
            $$ |  $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |      \____$$\
            $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$$$$$$  |$$ |     $$$$$$$  |
            $$  ____/  \_______|\_______|$$  ____/ \__|     \_______/
            $$ |                         $$ |
            $$ |                         $$ |
            \__|                         \__|
    """
    )

    print("\nGenerating test files...")

    generate_testfile_single()
    generate_testfile_tiny()
    generate_testfile_small()
    generate_testfile_medium()
    generate_testfile_large()
    generate_testfile_xl()
    generate_testfile_xxl()

    print("done!")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv))
