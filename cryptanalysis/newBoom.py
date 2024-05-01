"""
boomerang search script made for CHAM
"""

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
    startTime = time.time()
    switchRound = parameters["switchround"]

    parameters["rounds"] = parameters["switchround"] + parameters["lowertrail"]
    characteristic = searchDifferentialTrail(
        cipher,
        parameters,
        startTime,
    )

    # use try, might not have trail generated
    try:
        if characteristic.getStatus():
            upperEndRound = switchRound - 1
            left_alpha = int(characteristic.getData()[0][0], 16)
            left_alpha_prime = int(characteristic.getData()[0][1], 16)
            right_alpha = int(characteristic.getData()[0][2], 16)
            right_alpha_prime = int(characteristic.getData()[0][3], 16)

            left_beta = int(characteristic.getData()[upperEndRound][0], 16)
            left_beta_prime = int(characteristic.getData()[upperEndRound][1], 16)
            right_beta = int(characteristic.getData()[upperEndRound][2], 16)
            right_beta_prime = int(characteristic.getData()[upperEndRound][3], 16)

            lowerStartRound = switchRound + 1
            left_delta = int(characteristic.getData()[lowerStartRound][0], 16)
            left_delta_prime = int(characteristic.getData()[lowerStartRound][1], 16)
            right_delta = int(characteristic.getData()[lowerStartRound][2], 16)
            right_delta_prime = int(characteristic.getData()[lowerStartRound][3], 16)

            lowerEndRound = switchRound + parameters["lowertrail"]
            left_gamma = int(characteristic.getData()[lowerEndRound][0], 16)
            left_gamma_prime = int(characteristic.getData()[lowerEndRound][1], 16)
            right_gamma = int(characteristic.getData()[lowerEndRound][2], 16)
            right_gamma_prime = int(characteristic.getData()[lowerEndRound][3], 16)

            parameters["upperVariables"] = {
                "X00": "0x" + format(left_alpha, "04x"),
                "X10": "0x" + format(left_alpha_prime, "04x"),
                "X20": "0x" + format(right_alpha, "04x"),
                "X30": "0x" + format(right_alpha_prime, "04x"),
                f"X0{upperEndRound}": "0x" + format(left_beta, "04x"),
                f"X1{upperEndRound}": "0x" + format(left_beta_prime, "04x"),
                f"X2{upperEndRound}": "0x" + format(right_beta, "04x"),
                f"X3{upperEndRound}": "0x" + format(right_beta_prime, "04x"),
            }

            # could be x0A, edit later
            parameters["lowerVariables"] = {
                f"X0{lowerStartRound}": "0x" + format(left_delta, "04x"),
                f"X1{lowerStartRound}": "0x" + format(left_delta_prime, "04x"),
                f"X2{lowerStartRound}": "0x" + format(right_delta, "04x"),
                f"X3{lowerStartRound}": "0x" + format(right_delta_prime, "04x"),
                f"X0{lowerEndRound}": "0x" + format(left_gamma, "04x"),
                f"X1{lowerEndRound}": "0x" + format(left_gamma_prime, "04x"),
                f"X2{lowerEndRound}": "0x" + format(right_gamma, "04x"),
                f"X3{lowerEndRound}": "0x" + format(right_gamma_prime, "04x"),
            }

            print("Obtaining characteristics for trail E0 and E1")
            keyList = list(parameters["upperVariables"].keys())
            print(
                f"Upper trail(E0): {keyList[4]}:{parameters['upperVariables'][keyList[4]]},"
                f"{keyList[5]}:{parameters['upperVariables'][keyList[5]]} | "
                f"{keyList[6]}:{parameters['upperVariables'][keyList[6]]}, "
                f"{keyList[7]}: {parameters['upperVariables'][keyList[7]]}"
            )
            keyList2 = list(parameters["lowerVariables"].keys())
            print(
                f"Lower trail(E1): {keyList2[0]}:{parameters['lowerVariables'][keyList2[0]]},"
                f"{keyList2[1]}: {parameters['lowerVariables'][keyList2[1]]} | "
                f"{keyList2[2]}:{parameters['lowerVariables'][keyList2[2]]},"
                f"{keyList2[3]}: {parameters['lowerVariables'][keyList2[3]]}"
            )
            print("Rotating inputs...")
            # need to rotate the input(for display as the smt ady added the constraints)
            if switchRound % 2 == 0:
                left_beta_prime = rotl(left_beta_prime, 1)
                right_beta_prime = rotl(right_beta_prime, 1)
                left_delta = rotl(left_delta, 8)
                right_delta = rotl(right_delta, 8)

            else:
                left_beta_prime = rotl(left_beta_prime, 8)
                right_beta_prime = rotl(right_beta_prime, 8)
                left_delta = rotl(left_delta, 15)
                right_delta = rotl(right_delta, 15)

            print(f"Matching the switch in Em(Round {switchRound})...")
            # leftSwitchProb = 1.0
            leftSwitchProb = checkAbct.check_abct_prob(
                left_beta, left_beta_prime, left_delta, left_delta_prime
            )
            # rightSwitchProb = 0.5
            rightSwitchProb = checkAbct.check_abct_prob(
                right_beta, right_beta_prime, right_delta, right_delta_prime
            )
            if leftSwitchProb != 0 and rightSwitchProb != 0:
                totalSwitchWeight = abs(math.log(leftSwitchProb * rightSwitchProb, 2))
                totalWeight = (parameters["sweight"] * 2) + totalSwitchWeight
                print("TotalWeight: ", totalWeight)
                print(
                    f"{upperEndRound} rounds uppertrail: \n{parameters['upperVariables']}"
                )
                print(f"One round boomerang switch at R{switchRound}")
                print(
                    f"{parameters['lowertrail']} rounds lowertrail: \n{parameters['lowerVariables']}"
                )
            else:
                print("Either side of the switch is INVALID. Try again")
        else:
            print(
                f"No characteristic found for the swicth at r{switchRound}. Please check the variables and weights setting.\n"
            )
    except Exception as e:
        print("Error occured here...", e)


def searchDifferentialTrail(cipher, parameters, timestamp, searchLimit=32, mode=0):
    """
    Search top or bottom trail (characteristic) of a boomerang
    modify from search.findMinWeightCharacteristic and boomerang.boomerangTrail
    """
    print(cipher.name)
    print(f"Starting search for boomerang characteristic with minimal weight for")
    print(
        f"{cipher.name} - Rounds: {parameters['rounds']} Switch: {parameters['switchround']} Wordsize: {parameters['wordsize']}"
    )

    print("MAX weight= {} of the boomerang trail".format(searchLimit))
    print("---")
    start_time = timestamp
    # Set target weight for trail
    # parameters["sweight"] = parameters["weight"]

    characteristic = ""

    print('parameters["fixedVariables"] : ', parameters["fixedVariables"])
    # print('parameters["boomerangVariables"] : ', parameters["boomerangVariables"])

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
                    "Boomerang(complete) trail for {} - Rounds {} -Switch {} - Wordsize {} - "
                    "Weight {} - Time {}s".format(
                        cipher.name,
                        parameters["rounds"],
                        parameters["switchround"],
                        parameters["wordsize"],
                        parameters["sweight"],
                        current_time,
                    )
                )
            )
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

    if mode == 4:
        return parameters["sweight"]
    else:
        return characteristic


# define ROTL(x, n) ( ((x) << n) | ((x) >> (16 - (n))))
def rotl(num, pose):
    x = (num << pose) | (num >> (16 - pose))
    x &= 0xFFFF
    return x
