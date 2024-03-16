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

    characteristic = searchDifferentialTrail(
        cipher,
        parameters,
        startTime,
    )

    # get a,b,d,g from char, feed to abct, see if match
    # use try, might not have trail generated
    try:
        upperRound = parameters["uppertrail"]
        left_alpha = int(characteristic.getData()[0][0], 16)
        left_alpha_prime = int(characteristic.getData()[0][1], 16)
        right_alpha = int(characteristic.getData()[0][2], 16)
        right_alpha_prime = int(characteristic.getData()[0][3], 16)

        left_beta = int(characteristic.getData()[upperRound][0], 16)
        left_beta_prime = int(characteristic.getData()[upperRound][1], 16)
        right_beta = int(characteristic.getData()[upperRound][2], 16)
        right_beta_prime = int(characteristic.getData()[upperRound][3], 16)

        lowerRound = switchRound + 1
        left_delta = int(characteristic.getData()[lowerRound][0], 16)
        left_delta_prime = int(characteristic.getData()[lowerRound][1], 16)
        right_delta = int(characteristic.getData()[lowerRound][2], 16)
        right_delta_prime = int(characteristic.getData()[lowerRound][3], 16)

        # for index purpose, trail start from 0
        lowerRound += parameters["lowertrail"] - 1
        left_gamma = int(characteristic.getData()[lowerRound][0], 16)
        left_gamma_prime = int(characteristic.getData()[lowerRound][1], 16)
        right_gamma = int(characteristic.getData()[lowerRound][2], 16)
        right_gamma_prime = int(characteristic.getData()[lowerRound][3], 16)

        parameters["upperVariables"] = {
            "X00": "0x" + format(left_alpha, "04x"),
            "X10": "0x" + format(left_alpha_prime, "04x"),
            "Y00": "0x" + format(right_alpha, "04x"),
            "Y10": "0x" + format(right_alpha_prime, "04x"),
            f"X0{upperRound}": "0x" + format(left_beta, "04x"),
            f"X1{upperRound}": "0x" + format(left_beta_prime, "04x"),
            f"Y0{upperRound}": "0x" + format(right_beta, "04x"),
            f"Y1{upperRound}": "0x" + format(right_beta_prime, "04x"),
        }
        parameters["lowerVariables"] = {
            f"X0{switchRound+1}": "0x" + format(left_delta, "04x"),
            f"X1{switchRound+1}": "0x" + format(left_delta_prime, "04x"),
            f"Y0{switchRound+1}": "0x" + format(right_delta, "04x"),
            f"Y1{switchRound+1}": "0x" + format(right_delta_prime, "04x"),
            f"X0{lowerRound}": "0x" + format(left_gamma, "04x"),
            f"X1{lowerRound}": "0x" + format(left_gamma_prime, "04x"),
            f"Y0{lowerRound}": "0x" + format(right_gamma, "04x"),
            f"Y1{lowerRound}": "0x" + format(right_gamma_prime, "04x"),
        }

        print("matching the switch...")
        # need to rotate the input
        left_beta, left_beta_prime, right_beta, right_beta_prime = inputRotation(
            "sparxroundBoom", left_beta, left_beta_prime, right_beta, right_beta_prime
        )

        print(
            "\n checking ==== \n",
            left_beta,
            left_beta_prime,
            right_beta,
            right_beta_prime,
        )
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
            print(totalSwitchProb, totalProb)
            print(f"{upperRound} rounds uppertrail: \n{parameters['upperVariables']}")
            print(f"one round boomerang switch at r{switchRound}")
            print(
                f"{lowerRound-upperRound-1} rounds lowertrail: \n{parameters['lowerVariables']}"
            )
            print("after-----", parameters["skipround"])
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
        stp_file = "tmp/complete-{}{}-{}-{}.stp".format(
            cipher.name,
            parameters["wordsize"],
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
    parameters["skipround"] = 55
    return characteristic


# define ROTL(x, n) ( ((x) << n) | ((x) >> (16 - (n))))
def rotl(num, pose):
    return (num << pose) | (num >> (16 - pose))


def inputRotation(cipher, x0, x1, y0, y1, round=0):
    """
    Rotate the output of E0 and input of E1 for ciphers
    """

    if cipher == "sparxroundBoom":
        x1 = rotl(x1, 2)
        x1 ^= x0
        y1 = rotl(y1, 2)
        y1 ^= y0

    elif cipher == "chamBoom":
        if round % 2 == 0:
            x1 = (x1 << 2) ^ x0
            y1 = (y1 << 2) ^ y0
        else:
            x1 = (x1 << 2) ^ x0
            y1 = (y1 << 2) ^ y0
    else:
        print(
            "Ciphers rotation not exist. Please check again or add new rotation properties."
        )

    print(x0, x1, y0, y1)
    return (x0, x1, y0, y1)
