#!/usr/bin/env python
import ctypes
import pathlib
import time
import random

libname = pathlib.Path().absolute()
c_lib = ctypes.CDLL(libname / "abct_cpp/abct_prob.o")
c_lib.abct_prob.restype = ctypes.c_longdouble


class Combo:
    def __init__(self, a, b, c, d):
        self.a = a
        self.b = b
        self.c = c
        self.d = d

    def __lt__(self, other):
        return (self.a, self.b, self.c, self.d) < (other.a, other.b, other.c, other.d)


def generateCombination(alphaBit, alphaPrimeBit, betaBit, betaPrime_bit, comboCount):
    """
    generate random valid switches with 0,1,(odd,odd) / (even,even)
    """
    if (
        alphaBit % 4 != 0
        or alphaPrimeBit % 4 != 0
        or betaBit % 4 != 0
        or betaPrime_bit % 4 != 0
    ):
        print("please provide number of bits of LSB: 4,8,12,16")
        return 0

    comboList = set()

    while len(comboList) < comboCount:
        a = (random.randint(0, alphaBit) // 16) * 16
        b = (random.randint(0, alphaPrimeBit) // 16) * 16 + 1

        c = random.randint(0, betaBit)
        d = random.randint(0, betaPrime_bit)

        if (c % 2 == 0 and d % 2 == 0) or (c % 2 == 1 and d % 2 == 1):
            c = c
            d = d

        elif c % 2 == 1 and d % 2 == 0:
            c = c + 1
            d = d

        elif c % 2 == 0 and d % 2 == 1:
            c = c
            d = d + 1

        randomCombo = Combo(a, b, c, d)

        if randomCombo not in comboList:  # check for duplication
            comboList.add(randomCombo)

    return comboList


def sort_abct_result(inputList, limit=20):
    sortedList = sorted(inputList, key=lambda x: x[2], reverse=True)

    # Filter out tuples where the 3rd item is 0
    finalList = [tup for tup in sortedList if tup[2] != 0]

    if limit > len(finalList):
        return finalList[: len(finalList)]
    else:
        return finalList[:limit]


def check_abct_prob(alpha, alpha_prime, beta, beta_prime):
    prob = c_lib.abct_prob(
        ctypes.c_uint32(alpha),
        ctypes.c_uint32(alpha_prime),
        ctypes.c_uint32(beta),
        ctypes.c_uint32(beta_prime),
    )

    # turn off printing?
    print(f"{hex(alpha)}, {hex(alpha_prime)}, {hex(beta)}, {hex(beta_prime)}, {prob}")

    return prob


def parse_abct_prob(inputFilePath):
    # List to store tuples
    results = []

    filePath = inputFilePath
    # Open the file and read line by line
    with open(filePath, "r") as file:
        file.readline()  # skip first line
        for line in file:
            # Split the line into values
            values = line.strip().split(",")

            # Extract the 3rd, 4th, and 5th values
            entry = (int(values[2], 16), int(values[3], 16), float(values[4]))

            # Append the tuple to the list
            results.append(entry)

    finalResult = sort_abct_result(results)

    return finalResult


def compute_abct_switch(x0, x1, timestamp):
    """
    return top 20 valid switches between 0 to 0xff
    result= [(beta, beta', prob),(beta, beta', prob), ... ()]
    """
    consecutiveZeroCount = 0
    candidateList = []
    for beta in range(0x2):  # for demo purpose, change to 0xff if needed
        for beta_prime in range(0x2):
            prob = c_lib.abct_prob(
                ctypes.c_uint32(x0),
                ctypes.c_uint32(x1),
                ctypes.c_uint32(beta),
                ctypes.c_uint32(beta_prime),
            )

            if prob == 0:
                consecutiveZeroCount += 1
            else:
                # turn off later?
                print(
                    f"Time: {round(time.time() - timestamp, 2)}s {hex(x0)}, {hex(x1)}, {hex(beta)}, {hex(beta_prime)}, {prob}"
                )
                candidateList.append((beta, beta_prime, prob))

            if consecutiveZeroCount >= (0xFF / 4):
                consecutiveZeroCount = 0
                break

    finalResult = sort_abct_result(candidateList)
    return finalResult
