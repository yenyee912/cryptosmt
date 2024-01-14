#!/usr/bin/env python
import ctypes
import pathlib
import time

libname = pathlib.Path().absolute()
c_lib = ctypes.CDLL(libname / "abct_cpp/abct_prob.o")
c_lib.abct_prob.restype = ctypes.c_longdouble


def sort_abct_result(inputList, limit=20):
    sortedList = sorted(inputList, key=lambda x: x[2], reverse=True)

    # Filter out tuples where the 3rd item is 0
    finalList = [tup for tup in sortedList if tup[2] != 0]

    if limit > len(finalList):
        return finalList[: len(finalList)]
    else:
        return finalList[limit]


def parse_abct_prob(inputFilePath):
    # List to store tuples
    results = []

    filePath = libname / "abct_cpp/1.txt"

    # Open the file and read line by line
    with open(filePath, "r") as file:
        file.readline()
        for line in file:
            # Split the line into values
            values = line.strip().split(",")

            # Extract the 3rd, 4th, and 5th values
            entry = (int(values[2], 16), int(values[3], 16), float(values[4]))

            # Append the tuple to the list
            results.append(entry)

    finalResult = sort_abct_result(results)

    return finalResult


def check_abct_prob(alpha, alpha_prime, beta, beta_prime):
    # Sample data for our call:
    # alpha, alpha_prime, beta, beta_prime = 0x355E, 0xBF30, 0x1, 0x2

    # run abct_prob() in cpp to get the prob of the 4 params
    prob = c_lib.abct_prob(
        ctypes.c_uint32(alpha),
        ctypes.c_uint32(alpha_prime),
        ctypes.c_uint32(beta),
        ctypes.c_uint32(beta_prime),
    )

    # turn off printing?
    print(f"{hex(alpha)}, {hex(alpha_prime)}, {hex(beta)}, {hex(beta_prime)}, {prob}")

    return prob


def compute_abct_switch(x0, x1, timestamp):
    """
    return list of tuples
    result= [(beta, beta', prob),(beta, beta', prob), ... ()]
    """
    consecutiveZeroCount = 0
    candidateList = []
    for beta in range(0x4):
        for beta_prime in range(0x3):
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

    # do some sorting algo to compare prob
    finalResult = sort_abct_result(candidateList)
    return finalResult
