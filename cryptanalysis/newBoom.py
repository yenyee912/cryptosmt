from parser import parsesolveroutput, stpcommands
from cryptanalysis import search, diffchars
from config import (
    PATH_STP,
    PATH_BOOLECTOR,
    PATH_CRYPTOMINISAT,
    MAX_WEIGHT,
    MAX_CHARACTERISTICS,
)
from abct_cpp import checkAbct

import math
import os
import time
import sys
import pathlib
import time

from fractions import gcd


def findARXBoomerangDifferentialByMatchSwitch(cipher, parameters):
    # while parameters["maxweight"] < (parameters["wordsize"] / 2):
    startTime = time.time()
    switchRound = parameters["switchround"]

    # print("beforeeee-----", parameters["skipround"])
    parameters["rounds"] = parameters["uppertrail"] + parameters["lowertrail"] + 1
    characteristic = searchDifferentialTrail(
        cipher,
        parameters,
        startTime,
    )

    # get a,b,d,g from char, feed to abct, see if match
    # use try, might not have trail generated
    try:
        upperEndRound = parameters["uppertrail"]
        left_alpha = int(characteristic.getData()[0][0], 16)
        left_alpha_prime = int(characteristic.getData()[0][1], 16)
        right_alpha = int(characteristic.getData()[0][2], 16)
        right_alpha_prime = int(characteristic.getData()[0][3], 16)

        left_beta = int(characteristic.getData()[upperEndRound][0], 16)
        left_beta_prime = int(characteristic.getData()[upperEndRound][1], 16)
        right_beta = int(characteristic.getData()[upperEndRound][2], 16)
        right_beta_prime = int(characteristic.getData()[upperEndRound][3], 16)

        lowerStartRound = switchRound + 1
        if lowerStartRound % 3 == 0:  # take the output from A2
            left_delta = int(characteristic.getData()[switchRound][4], 16)
            left_delta_prime = int(characteristic.getData()[switchRound][5], 16)
            right_delta = int(characteristic.getData()[switchRound][6], 16)
            right_delta_prime = int(characteristic.getData()[switchRound][7], 16)
        else:
            left_delta = int(characteristic.getData()[lowerStartRound][0], 16)
            left_delta_prime = int(characteristic.getData()[lowerStartRound][1], 16)
            right_delta = int(characteristic.getData()[lowerStartRound][2], 16)
            right_delta_prime = int(characteristic.getData()[lowerStartRound][3], 16)
        # print(lowerStartRound + parameters["lowertrail"])
        lowerEndRound = lowerStartRound + parameters["lowertrail"] - 1
        left_gamma = int(characteristic.getData()[lowerEndRound][0], 16)
        left_gamma_prime = int(characteristic.getData()[lowerEndRound][1], 16)
        right_gamma = int(characteristic.getData()[lowerEndRound][2], 16)
        right_gamma_prime = int(characteristic.getData()[lowerEndRound][3], 16)

        parameters["upperVariables"] = {
            "X00": "0x" + format(left_alpha, "04x"),
            "X10": "0x" + format(left_alpha_prime, "04x"),
            "Y00": "0x" + format(right_alpha, "04x"),
            "Y10": "0x" + format(right_alpha_prime, "04x"),
            f"X0{upperEndRound}": "0x" + format(left_beta, "04x"),
            f"X1{upperEndRound}": "0x" + format(left_beta_prime, "04x"),
            f"Y0{upperEndRound}": "0x" + format(right_beta, "04x"),
            f"Y1{upperEndRound}": "0x" + format(right_beta_prime, "04x"),
        }

        # # could be x0A, edit later
        parameters["lowerVariables"] = {
            f"X0{lowerStartRound}": "0x" + format(left_delta, "04x"),
            f"X1{lowerStartRound}": "0x" + format(left_delta_prime, "04x"),
            f"Y0{lowerStartRound}": "0x" + format(right_delta, "04x"),
            f"Y1{lowerStartRound}": "0x" + format(right_delta_prime, "04x"),
            f"X0{lowerEndRound}": "0x" + format(left_gamma, "04x"),
            f"X1{lowerEndRound}": "0x" + format(left_gamma_prime, "04x"),
            f"Y0{lowerEndRound}": "0x" + format(right_gamma, "04x"),
            f"Y1{lowerEndRound}": "0x" + format(right_gamma_prime, "04x"),
        }

        print("Obtaining characteristics for trail E0 and E1")
        print("L     |     R ")
        print(
            f"Upper trail(E0): X0{upperEndRound}:{hex(left_beta)}, {hex(left_beta_prime)} | Y0{upperEndRound}:{hex(right_beta)}, {hex(right_beta_prime)}"
        )
        print(
            f"Lower trail(E1): X0{lowerStartRound}:{hex(left_delta)}, {hex(left_delta_prime)} | Y0{lowerStartRound}:{hex(right_delta)}, {hex(right_delta_prime)}"
        )
        print("Rotating inputs...")
        # need to rotate the input(for display as the smt ady added the constraints)
        (
            left_beta,
            left_beta_prime,
            right_beta,
            right_beta_prime,
            left_delta,
            left_delta_prime,
            right_delta,
            right_delta_prime,
        ) = characRotation(
            left_beta,
            left_beta_prime,
            right_beta,
            right_beta_prime,
            left_delta,
            left_delta_prime,
            right_delta,
            right_delta_prime,
            0,
        )
        print(f"Matching the switch in Em(Round {switchRound})...")
        leftSwitchProb = checkAbct.check_abct_prob(
            left_beta, left_beta_prime, left_delta, left_delta_prime
        )
        rightSwitchProb = checkAbct.check_abct_prob(
            right_beta, right_beta_prime, right_delta, right_delta_prime
        )
        totalSwitchProb = 0
        if leftSwitchProb != 0 and rightSwitchProb != 0:
            totalSwitchProb = leftSwitchProb * rightSwitchProb
            # totalSwitchWeight = -math.log((totalSwitchProb), 2)
            totalProb = (2 ** (-parameters["sweight"] * 2)) * totalSwitchProb
            # print(totalSwitchProb, totalProb)
            print(
                f"{upperEndRound} rounds uppertrail: \n{parameters['upperVariables']}"
            )
            print(f"one round boomerang switch at r{switchRound}")
            print(
                f"{parameters['lowertrail']} rounds lowertrail: \n{parameters['lowerVariables']}"
            )
        else:
            print("Either side of the switch is INVALID. Try again")

    except:
        print(
            "No characteristic found for the given limits. Please check the variables and weights setting.\n"
        )


def searchDifferentialTrail(cipher, parameters, timestamp, searchLimit=32):
    """
    Search top or bottom trail (characteristic) of a boomerang
    modify from search.findMinWeightCharacteristic and boomerang.boomerangTrail
    """
    # Set parameters for targeted boomerang face

    print(
        (
            "Starting search for boomerang characteristic with minimal weight for\n"
            "{} - Rounds: {} Wordsize: {}".format(
                cipher.name, parameters["rounds"], parameters["wordsize"]
            )
        )
    )

    print("MAX weight= {} of the boomerang trail".format(searchLimit))
    print("---")
    start_time = timestamp
    # Set target weight for trail
    # parameters["sweight"] = parameters["weight"]

    characteristic = ""

    print('parameters["fixedVariables"] : ', parameters["fixedVariables"])
    print('parameters["boomerangVariables"] : ', parameters["boomerangVariables"])

    while (
        not search.reachedTimelimit(start_time, parameters["timelimit"])
        and parameters["sweight"] <= searchLimit
    ):
        print(
            "Weight: {} Time: {}s".format(
                parameters["sweight"], round(time.time() - start_time, 2)
            )
        )

        # Construct problem instance for given parameters
        stp_file = "tmp/{}-{}-{}-whole.stp".format(
            cipher.name,
            # parameters["wordsize"],
            parameters["rounds"],
            timestamp,
        )

        # Fix number of rounds
        # parameters["rounds"] = parameters[trail]

        cipher.createSTP(stp_file, parameters)
        result = ""
        if parameters["boolector"]:
            result = search.solveBoolector(stp_file)
        else:
            result = search.solveSTP(stp_file)
        characteristic = ""

        # Check if a characteristic was found
        if search.foundSolution(result):
            current_time = round(time.time() - start_time, 2)
            print("---")
            print(
                (
                    "Boomerang(complete) trail for {} - Rounds {} - Wordsize {} - "
                    "Weight {} - Time {}s".format(
                        cipher.name,
                        parameters["rounds"],
                        parameters["wordsize"],
                        parameters["sweight"],
                        current_time,
                    )
                )
            )
            print("X0L= (X0A^X1A)<<8 ^X0A")
            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher, parameters["rounds"]
                )
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher, parameters["rounds"]
                )
            characteristic.printText()
            print("----")
            break
        parameters["sweight"] += 1
        # print("----")
    # parameters["skipround"] = 55
    return characteristic


# define ROTL(x, n) ( ((x) << n) | ((x) >> (16 - (n))))
def rotl(num, pose):
    return (num << pose) | (num >> (16 - pose))


def characRotation(x0, x1, y0, y1, x2, x3, y2, y3, linear=0):
    """
    Rotate the output of E0 and input of E1 for ciphers
    E0: x0,x1| y0,y1
    E1: x2,x3| y2,y3
    """

    x0 = rotl(x0, 9)
    y0 = rotl(y0, 9)

    if linear == 0:
        x3 ^= x2
        x3 = rotl(x2, 2)
        y3 ^= y2
        y3 = rotl(y3, 2)
    else:
        x3 ^= x2
        x3 = rotl(x3, 2)
        y3 ^= y2
        y3 = rotl(y3, 2)

    x0 &= 0xFFFF
    x1 &= 0xFFFF
    y0 &= 0xFFFF
    y1 &= 0xFFFF
    x2 &= 0xFFFF
    x3 &= 0xFFFF
    y2 &= 0xFFFF
    y3 &= 0xFFFF

    return (x0, x1, y0, y1, x2, x3, y2, y3)
