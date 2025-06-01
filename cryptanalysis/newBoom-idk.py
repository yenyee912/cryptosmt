"""
boomerang search script made for CHAM and SPARXround
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


def findValidARXBoomerangDifferential(cipher, parameters):
    if cipher.name == "chamBoom":
        searchCHAM(cipher, parameters)
    elif cipher.name == "sparxroundBoom" or cipher.name == "sparxround":
        searchSPARX(cipher, parameters)
    else:
        print("Cipher not support mode 6, please check again.")


def searchEasySPARX(cipher, parameters):
    startTime = time.time()
    switchRound = parameters["switchround"]
    parameters["rounds"] = parameters["rounds"]
    total_prob = 0
    startWeight = parameters["sweight"]

    # Initialise separate blocked trails
    parameters["blockedUpperCharacteristics"] = []
    parameters["blockedLowerCharacteristics"] = []
    while True:
        try:
            upperCharacteristic = searchDifferentialTrail(
                cipher, parameters, startTime, parameters["endweight"]
            )
            if not upperCharacteristic:
                print(
                    f"No upper trail found for the swicth at R{switchRound}. Please check the setting again.\n"
                )
                return

            else:
                # alphas;
                if parameters["part"] == "upper":
                    left_alpha = int(
                        upperCharacteristic.getData()[parameters["uppertrail"]][0], 16
                    )
                    left_alpha_prime = int(
                        upperCharacteristic.getData()[parameters["uppertrail"]][1], 16
                    )
                    right_alpha = int(
                        upperCharacteristic.getData()[parameters["uppertrail"]][2], 16
                    )
                    right_alpha_prime = int(
                        upperCharacteristic.getData()[parameters["uppertrail"]][3], 16
                    )

                    left_alpha = rotr(left_alpha, 7)  # >>>7
                    right_alpha = rotr(right_alpha, 7)

                    print(
                        "alphas: ",
                        format(left_alpha, "04x"),
                        format(left_alpha_prime, "04x"),
                        format(right_alpha, "04x"),
                        format(right_alpha_prime, "04x"),
                        # format(left_beta, "04x"),
                        # format(left_beta_prime, "04x"),
                    )

                elif parameters["part"] == "lower":
                    lowerStartRound = parameters["skipround"] + 1
                    left_beta = int(
                        upperCharacteristic.getData()[lowerStartRound][0], 16
                    )
                    left_beta_prime = int(
                        upperCharacteristic.getData()[lowerStartRound][1], 16
                    )
                    right_beta = int(
                        upperCharacteristic.getData()[lowerStartRound][2], 16
                    )
                    right_beta_prime = int(
                        upperCharacteristic.getData()[lowerStartRound][3], 16
                    )

                    # reverse the linear layer
                    if switchRound % 3 == 0:
                        temp = rotl((right_beta ^ right_beta_prime), 8)
                        tmpVar = left_beta
                        left_beta = right_beta
                        right_beta = tmpVar

                        tmpVar = left_beta_prime
                        left_beta_prime = right_beta_prime
                        right_beta_prime = tmpVar

                        right_beta_prime = right_beta_prime ^ temp ^ left_beta_prime
                        right_beta = right_beta ^ temp ^ left_beta

                    left_beta_prime = rotr((left_beta ^ left_beta_prime), 2)
                    right_beta_prime = rotr((right_beta ^ right_beta_prime), 2)

                    print(
                        "Beta ",
                        format(left_beta, "04x"),
                        format(left_beta_prime, "04x"),
                        format(right_beta, "04x"),
                        format(right_beta_prime, "04x"),
                    )

            if parameters["sweight"] > startWeight:
                startWeight = parameters["sweight"]
            parameters["blockedCharacteristics"].append(
                upperCharacteristic
            )  # actually useless cuz it will block the X00 but still produce same beta

        except Exception as e:
            print("Error occured here...", e)
            return  # this will stop the while loop once there is error


def searchSPARX(cipher, parameters):
    startTime = time.time()
    switchRound = parameters["switchround"]
    parameters["rounds"] = parameters["uppertrail"]
    parameters["part"] = "upper"  # variables to control the encoded HPBS patterns
    total_prob = 0
    parameters["fixedVariables"] = {}
    if len(parameters["upperVariables"]) > 0:
        for d in parameters["upperVariables"]:
            parameters["fixedVariables"].update(d)
    # print(type(parameters["upperVariables"]))
    # print(parameters["upperVariables"])

    # Initialise separate blocked trails
    parameters["blockedUpperCharacteristics"] = []
    parameters["blockedLowerCharacteristics"] = []
    while total_prob == 0:
        try:
            parameters["blockedCharacteristics"].clear()
            parameters["blockedCharacteristics"] = parameters[
                "blockedUpperCharacteristics"
            ]

            upperCharacteristic = searchDifferentialTrail(
                cipher, parameters, startTime, parameters["endweight"]
            )
            if not upperCharacteristic:
                print(
                    f"No upper trail found for the swicth at R{switchRound}. Please check the setting again.\n"
                )
                return

            else:
                upperWeight = parameters["sweight"]

                # extract alphas;
                left_alpha = int(
                    upperCharacteristic.getData()[parameters["uppertrail"]][0], 16
                )
                left_alpha_prime = int(
                    upperCharacteristic.getData()[parameters["uppertrail"]][1], 16
                )
                right_alpha = int(
                    upperCharacteristic.getData()[parameters["uppertrail"]][2], 16
                )
                right_alpha_prime = int(
                    upperCharacteristic.getData()[parameters["uppertrail"]][3], 16
                )

                left_alpha = rotr(left_alpha, 7)  # >>>7
                right_alpha = rotr(right_alpha, 7)

                print(
                    "alphas: ",
                    format(left_alpha, "04x"),
                    format(left_alpha_prime, "04x"),
                    format(right_alpha, "04x"),
                    format(right_alpha_prime, "04x"),
                    # format(left_beta, "04x"),
                    # format(left_beta_prime, "04x"),
                )

                # PREPARE data for lower E1 trail search
                # make sure the skipround is correctly define as it will affect the data extraction and starting round of E1
                # if switchRound % 3 == 0:  # X06
                #     parameters["skipround"] = 99
                # elif (switchRound - 2) % 3 == 0:  # X05
                #     parameters["skipround"] = 1
                # else:
                #     parameters["skipround"] = 0  # X04

                # lowertrail is the length of E1, if lowerStartRound from R2, then the skip round=1, and the "rounds"= lowertrail+lowerStartRound
                parameters["rounds"] = parameters["lowertrail"]
                parameters["part"] = "lower"
                parameters["endweight"] = parameters["endweight"] - upperWeight
                # strat the search from zero, maybe can modify later
                parameters["sweight"] = parameters["lowerweight"]
                parameters["fixedVariables"] = {}
                if len(parameters["lowerVariables"]) > 0:
                    for d in parameters["lowerVariables"]:
                        parameters["fixedVariables"].update(d)

                # skipround set to 1 or 2 doesnt matter, based on observation the trail produced are same
                # just for switch =3x, need to minus the wl2 and wr2

                parameters["blockedCharacteristics"].clear()
                parameters["blockedCharacteristics"] = parameters[
                    "blockedLowerCharacteristics"
                ]

                lowerCharacteristic = searchDifferentialTrail(
                    cipher, parameters, startTime, parameters["endweight"]
                )
                if not lowerCharacteristic:
                    print(
                        f"No compatible lower trail found for the swicth at R{switchRound}. Please check the setting again.\n"
                    )
                    return

                else:

                    lowerStartRound = 0
                    left_beta = int(
                        lowerCharacteristic.getData()[lowerStartRound][0], 16
                    )
                    left_beta_prime = int(
                        lowerCharacteristic.getData()[lowerStartRound][1], 16
                    )
                    right_beta = int(
                        lowerCharacteristic.getData()[lowerStartRound][2], 16
                    )
                    right_beta_prime = int(
                        lowerCharacteristic.getData()[lowerStartRound][3], 16
                    )

                    # reverse the linear layer
                    if switchRound % 3 == 0:
                        temp = rotl((right_beta ^ right_beta_prime), 8)
                        tmpVar = left_beta
                        left_beta = right_beta
                        right_beta = tmpVar

                        tmpVar = left_beta_prime
                        left_beta_prime = right_beta_prime
                        right_beta_prime = tmpVar

                        right_beta_prime = right_beta_prime ^ temp ^ left_beta_prime
                        right_beta = right_beta ^ temp ^ left_beta

                    left_beta_prime = rotr((left_beta ^ left_beta_prime), 2)
                    right_beta_prime = rotr((right_beta ^ right_beta_prime), 2)

                    print(
                        "Beta ",
                        format(left_beta, "04x"),
                        format(left_beta_prime, "04x"),
                        format(right_beta, "04x"),
                        format(right_beta_prime, "04x"),
                    )
                    left_prob = checkAbct.check_abct_prob(
                        left_alpha, left_alpha_prime, left_beta, left_beta_prime
                    )
                    right_prob = checkAbct.check_abct_prob(
                        right_alpha, right_alpha_prime, right_beta, right_beta_prime
                    )
                    # total_prob = 0
                    total_prob = left_prob * right_prob

                    acc_weight = 0
                    for row in lowerCharacteristic.getData()[:lowerStartRound]:
                        acc_weight += abs(int(row[10]) + int(row[11]))

                    if total_prob != 0:
                        total_switch_weight = abs(math.log(left_prob * right_prob, 2))
                        lowerWeight = parameters["sweight"]
                        print("---")
                        print("Total Switch Weight: ", total_switch_weight)
                        print(
                            "Total Weight: ",
                            (upperWeight * 2) + (lowerWeight * 2) + total_switch_weight,
                        )
                        print("---")
                    else:
                        print("Trails not compatible. Start new search. \n")
                        parameters["sweight"] = 0
                        parameters["endweight"] = 50  # maybe can use some constant
                        parameters["part"] = "upper"
                        parameters["fixedVariables"].clear()
                        parameters["rounds"] = parameters["uppertrail"]
                        parameters["skipround"] = 99

                        parameters["blockedCharacteristics"].clear()
                        # parameters["blockedUpperCharacteristics"].append(
                        #     upperCharacteristic
                        # )
                        parameters["blockedLowerCharacteristics"].append(
                            lowerCharacteristic
                        )

        except Exception as e:
            print("Error occured here...", e)
            return  # this will stop the while loop once there is error


def searchCHAM(cipher, parameters):
    """
    cham has ONE side switch ONLY
    """
    startTime = time.time()
    switchRound = parameters["switchround"]
    parameters["rounds"] = parameters["uppertrail"]
    parameters["part"] = "upper"  # variables to control the encoded HPBS patterns
    total_prob = 0

    # Initialise separate blocked trails
    parameters["blockedUpperCharacteristics"] = []
    parameters["blockedLowerCharacteristics"] = []

    while total_prob == 0:

        try:
            characteristic = searchDifferentialTrail(
                cipher, parameters, startTime, parameters["endweight"]
            )
            if not characteristic:
                print(
                    f"No characteristic found for the swicth at R{switchRound}. Please check the variables and weights setting.\n"
                )
                return

            else:
                upperEndRound = parameters["uppertrail"]
                upperWeight = parameters["sweight"]

                # left_alpha = int(characteristic.getData()[0][0], 16)
                # left_alpha_prime = int(characteristic.getData()[0][1], 16)
                # right_alpha = int(characteristic.getData()[0][2], 16)
                # right_alpha_prime = int(characteristic.getData()[0][3], 16)

                left_alpha = int(characteristic.getData()[upperEndRound][0], 16)
                left_alpha_prime = int(characteristic.getData()[upperEndRound][1], 16)
                right_alpha = int(characteristic.getData()[upperEndRound][2], 16)
                right_alpha_prime = int(characteristic.getData()[upperEndRound][3], 16)

                lowerStartRound = switchRound
                # reverse the linear layer here?? 3,0,1,2
                left_beta = int(characteristic.getData()[lowerStartRound][0], 16)
                left_beta_prime = int(characteristic.getData()[lowerStartRound][1], 16)
                right_beta = int(characteristic.getData()[lowerStartRound][2], 16)
                right_beta_prime = int(characteristic.getData()[lowerStartRound][3], 16)

                lowerEndRound = switchRound + parameters["lowertrail"]
                left_delta = int(characteristic.getData()[lowerEndRound][0], 16)
                left_delta_prime = int(characteristic.getData()[lowerEndRound][1], 16)
                right_delta = int(characteristic.getData()[lowerEndRound][2], 16)
                right_delta_prime = int(characteristic.getData()[lowerEndRound][3], 16)

                print("Obtaining characteristics for the switch round...")
                print("Rotating inputs...")
                # need to rotate the input(for display as the smt ady added the constraints)

                # ok, tested, follow liyu paper
                print(
                    format(left_beta_prime, "04x"),
                    format(right_gamma_prime, "04x"),
                    format(left_gamma, "04x"),
                )
                if switchRound % 2 != 0:
                    left_beta_prime = rotl(left_beta_prime, 8)
                    right_gamma_prime = rotl(right_gamma_prime, 15)  # ROTR1(beta)
                    left_gamma = rotl(left_gamma, 8)  # beta' # ROTL8(beta')

                else:
                    left_beta_prime = rotl(left_beta_prime, 1)
                    # shuffle the swap back, refer the pic
                    right_gamma_prime = rotl(right_gamma_prime, 8)  # ROTR8(beta)
                    left_gamma = rotl(left_gamma, 1)  # ROTL1(beta')

                print(f"Matching the switch in Em (Round {switchRound})...")
                # leftSwitchProb = 1.0
                left_switch_prob = checkAbct.check_abct_prob(
                    left_beta, left_beta_prime, right_gamma_prime, left_gamma
                )
                # rightSwitchProb = 0.5
                right_switch_prob = checkAbct.check_abct_prob(
                    right_beta, right_beta_prime, right_gamma, right_gamma_prime
                )

                total_switch_prob = left_switch_prob * right_switch_prob

                if total_switch_prob != 0:
                    total_switch_weight = abs(math.log(total_switch_prob, 2))
                    total_weight = upperWeight + total_switch_weight
                    print("---")
                    print("Total Weight:", totalWeight)
                    print("---")
                    print(
                        f"{upperEndRound} rounds uppertrail: \n{parameters['upperBoomerangVariables']}"
                    )
                    print(f"One round boomerang switch at R{switchRound}")
                    print(
                        f"{parameters['lowertrail']} rounds lowertrail: \n{parameters['lowerBoomerangVariables']}"
                    )
                    break
                else:
                    totalSwitchWeight = 0
                    print("The switch is INVALID. Try again")
                    # block characteristics, try other trail
                    parameters["blockedCharacteristics"].append(characteristic)
                    # parameters["fixedVariables"].clear()
                    # parameters["fixedVariables"] = parameters["upperBoomerangVariables"]
                    print("\n---\n")
                    print(f"Looking for No. {repCount} trail...\n")
                    characteristic = searchDifferentialTrail(
                        cipher, parameters, startTime, parameters["endweight"]
                    )
        except Exception as e:
            print("Error occured here...", e)


def searchDifferentialTrail(cipher, parameters, timestamp, searchLimit):
    """
    Search top or bottom trail (characteristic) of a boomerang
    modify from search.findMinWeightCharacteristic and boomerang.boomerangTrail
    """
    print(f"Starting search for boomerang characteristic with minimal weight for")
    print(
        f"{cipher.name} - Rounds: {parameters['rounds']} Trail: {parameters['part']} Switch: {parameters['switchround']} Wordsize: {parameters['wordsize']}"
    )

    print("MAX weight= {} of the boomerang trail".format(searchLimit))
    print("---")
    start_time = timestamp
    # Set target weight for trail
    # parameters["sweight"] = parameters["weight"]

    characteristic = ""

    print('parameters["fixedVariables"] : ', parameters["fixedVariables"])
    print('parameters["skipround"] : ', parameters["skipround"])
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
        stp_file = "tmp/{}-{}-{}.stp".format(
            cipher.name,
            parameters["part"],
            parameters["rounds"],
            # timestamp,
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
            acc_weight = 0

            if cipher.name == "sparxroundBoom":
                if parameters["boolector"]:
                    characteristic = parsesolveroutput.getCharBoolectorOutput(
                        result, cipher, parameters["rounds"]
                    )
                else:
                    characteristic = parsesolveroutput.getCharSTPOutput(
                        result, cipher, parameters["rounds"]
                    )
                if not parameters["skipround"] == 99:
                    lowerStartRound = parameters["skipround"] + 1
                    for row in characteristic.getData()[:lowerStartRound]:
                        acc_weight += abs(int(row[10]) + int(row[11]))
                        row[10] = "-0"
                        row[11] = "-0"
                    # print(characteristic.getData([2][2]))

                parameters["sweight"] = parameters["sweight"] - acc_weight
            print("---")
            print(
                (
                    "{} - Boomerang trail for {} - Rounds {} - Switch {} - Wordsize {} - "
                    "Weight {} - Time {}s".format(
                        parameters["part"],
                        cipher.name,
                        parameters["rounds"],
                        parameters["switchround"],
                        parameters["wordsize"],
                        parameters["sweight"],
                        current_time,
                    )
                )
            )

            characteristic.printText()
            print("----")
            break
        parameters["sweight"] += 1

    return characteristic


# define ROTL(x, n) ( ((x) << n) | ((x) >> (16 - (n))))
def rotl(num, pose):
    x = (num << pose) | (num >> (16 - pose))
    x &= 0xFFFF
    return x


def rotr(num, pose):
    x = (num >> pose) | (num << (16 - pose))
    x &= 0xFFFF
    return x
