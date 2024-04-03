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

        # could be x0A, edit later
        lowerStartRoundVar0 = "0" + str(lowerStartRound)
        lowerStartRoundVar1 = "1" + str(lowerStartRound)
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
        keys_list = list(parameters["upperVariables"].keys())
        print(
            f"Upper trail(E0): {keys_list[4]}:{parameters['upperVariables'][keys_list[4]]},"
            f"{keys_list[5]}:{parameters['upperVariables'][keys_list[5]]} | "
            f"{keys_list[6]}:{parameters['upperVariables'][keys_list[6]]}, "
            f"{keys_list[7]}: {parameters['upperVariables'][keys_list[7]]}"
        )
        keys_list = list(parameters["lowerVariables"].keys())
        print(
            f"Lower trail(E1): {keys_list[0]}:{parameters['lowerVariables'][keys_list[0]]},"
            f"{keys_list[1]}: {parameters['lowerVariables'][keys_list[1]]} | "
            f"{keys_list[2]}:{parameters['lowerVariables'][keys_list[2]]},"
            f"{keys_list[3]}: {parameters['lowerVariables'][keys_list[3]]}"
        )
        print("Rotating inputs...")
        # need to rotate the input(for display as the smt ady added the constraints)

        # rotate the output of E0, same as what we used to do when looking for corresponding beta for alpha
        left_beta = rotl(left_beta, 9)
        right_beta = rotl(right_beta, 9)

        # reverse the steps in "beta_generator", because smt produced the trail
        # to generate beta: X10= ROTL(X10,2) XOR X00
        # you have to decrypt to get ori beta in abct
        if lowerStartRound % 3 == 0:
            temp = rotl((right_delta ^ right_delta_prime), 8)
            tmpVar = left_delta
            left_delta = right_delta
            right_delta = tmpVar

            tmpVar = left_delta_prime
            left_delta_prime = right_delta_prime
            right_delta_prime = tmpVar

            right_delta_prime = right_delta_prime ^ temp ^ left_delta_prime
            right_delta = right_delta ^ temp ^ left_delta

        left_delta_prime = rotl((left_delta ^ left_delta_prime), 14)
        right_delta_prime = rotl((right_delta ^ right_delta_prime), 14)

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
            print(f"One round boomerang switch at R{switchRound}")
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

    # print('parameters["fixedVariables"] : ', parameters["fixedVariables"])
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
            # print("X0L= (X0A^X1A)<<8 ^X0A")
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
    x = (num << pose) | (num >> (16 - pose))
    x &= 0xFFFF
    return x
