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

import subprocess
import random
import math
import os
import time
import sys

from fractions import gcd

# sparx and cham different?? sparx is left right word state, cham is only left, right not involve in ADD


def findARXBoomerangDifferential(cipher, parameters):
    """
    Performs the complete boomerang differential search
    Probabilistic wwitch is done by ABCT.cpp
    """

    if cipher.name not in ["sparxround", "cham"]:
        raise ValueError(
            "This mode is for ARX ciphers only. For SPN or GFN design, please select mode 5."
        )

    start_time = time.time()
    print("----")
    print("Running initial boomerang search")
    print("----")

    # Find E0 then Em(heuristic) then E1, then clustering(todo)
    boomerangProb = computeBoomerangProb(cipher, parameters, start_time)

    # Compute other boomerang trails for the given input and output differences
    # while not search.reachedTimelimit(start_time, parameters["timelimit"]):
    #     prob = computeBoomerangProb(cipher, parameters, start_time, boomerangProb)
    #     if prob == 99:  # No more upper trails for the given input
    #         break
    #     elif prob == 0:  # No lower trail found for the given limits
    #         print("Trying a different upper trail")
    #     else:
    #         boomerangProb = prob
    #         print("---")
    #         print("Improved boomerang probability = " + str(math.log(boomerangProb, 2)))
    print("\n----")
    print("Boomerang search completed for the following:")
    # print("X0 = {}".format(parameters["boomerangVariables"]["X0"]))
    # print(
    #     "X{} = {}".format(
    #         parameters["lowertrail"],
    #         parameters["boomerangVariables"]["X{}".format(parameters["lowertrail"])],
    #     )
    # )
    print("Final boomerang probability = ", boomerangProb)
    print("----\n")

    # Clear the start/end points to start new boomerang search
    # parameters["boomerangVariables"].clear()

    return 0


def computeBoomerangProb(cipher, parameters, timestamp):
    """
    call by main, responsible for
    - arrange E0 and E1 search,
    - check abct,
    - clustering (in progress, not setting up yet),
    - result boomerang prob for this input and output diff

    # (now)caliberate for sparx in terms of input rotation, refer to excel
    """
    start_time = timestamp

    upperCharacteristic = searchDifferentialTrail(
        cipher, parameters, start_time, "upper"
    )

    # L-beta, L-beta_prime= LEFT halves of output from E0 trail
    # R-beta, R-beta_prime= RIGHT halves of output from E0 trail
    try:
        left_alpha = int(upperCharacteristic.getData()[0][0], 16)
        left_alpha_prime = int(upperCharacteristic.getData()[0][1], 16)
        right_alpha = int(upperCharacteristic.getData()[0][2], 16)
        right_alpha_prime = int(upperCharacteristic.getData()[0][3], 16)

        upperRound = parameters["uppertrail"]
        left_beta = int(upperCharacteristic.getData()[upperRound][0], 16)
        left_beta_prime = int(upperCharacteristic.getData()[upperRound][1], 16)
        right_beta = int(upperCharacteristic.getData()[upperRound][2], 16)
        right_beta_prime = int(upperCharacteristic.getData()[upperRound][3], 16)

    except:
        print("No characteristic found for the given limits")
        # If no more upper characteristics can be found, best boomerang differential for the given input has been found
        parameters["uweight"] = parameters["sweight"]
        parameters["blockedUpperCharacteristics"].append(upperCharacteristic)
        parameters["blockedLowerCharacteristics"].clear()
        return 99

    leftResult = []
    rightResult = []

    # 6	0xAF1A  0xBF30  0x850A  0x9520
    # left_beta = 0xAF1A
    # right_beta = 0x850A
    if cipher.name == "sparxround" or cipher.name == "sparx":
        left_beta = left_beta << 9
        right_beta = right_beta << 9

    elif cipher.name == "cham":
        if upperRound % 2 == 0:  # Em = odd
            left_beta_prime = left_beta_prime << 8
            right_beta_prime = right_beta_prime << 8
        else:  # Em = even
            left_beta_prime = left_beta_prime << 1
            right_beta_prime = right_beta_prime << 1

    print(
        "---\nComputing switch for left halves- {}, {}\n---".format(
            hex(left_beta), hex(left_beta_prime)
        )
    )
    if parameters["abctMode"] == 1:
        try:
            if parameters["leftFilePath"] and parameters["rightFilePath"]:
                leftResult = checkAbct.parse_abct_prob(parameters["leftFilePath"])
                rightResult = checkAbct.parse_abct_prob(parameters["rightFilePath"])

                print("{} valid switches found--".format(len(leftResult)))
                print(leftResult)
        except:
            print("Please provide corresponding path to file(s) to parse.")

    elif parameters["abctMode"] == 2:
        leftResult = checkAbct.compute_abct_switch(
            left_beta, left_beta_prime, start_time
        )
        print("{} valid switches found:".format(len(leftResult)))
        print(leftResult, "\n")

    leftResult = [
        (0, 0, 1),
        (0, 1, 0.5),
        (1, 0, 0.5),
        (1, 1, 0.5),
        (2, 0, 0.9375),
    ]
    rightResult = [
        (0, 1, 0.5),
        (0, 4, 0.5),
        (1, 0, 0.5),
        (1, 1, 0.5),
        (2, 0, 0.5),
        (6, 0, 0.625),
    ]

    if cipher.name == "sparxround":
        x0 = leftResult[2][0]
        x1 = (leftResult[2][1] << 2) ^ x0
        y0 = rightResult[5][0]
        y1 = (rightResult[5][1] << 2) ^ y0

    elif cipher.name == "cham":
        if upperRound % 2 == 0:
            x0 = leftResult[0][0]
            x1 = (leftResult[0][1] << 2) ^ x0
            y0 = rightResult[0][0]
            y1 = (rightResult[0][1] << 2) ^ y0
        else:
            x0 = leftResult[0][0]
            x1 = (leftResult[0][1] << 2) ^ x0
            y0 = rightResult[0][0]
            y1 = (rightResult[0][1] << 2) ^ y0

    parameters["lowerVariables"] = {
        "X00": "0x" + format(x0, "04x"),  # 0x4 is to fix the hex into 16bits
        "X10": "0x" + format(x1, "04x"),
        "Y00": "0x" + format(y0, "04x"),
        "Y10": "0x" + format(y1, "04x"),
    }

    switchProb = leftResult[2][2]  # how to calculate
    parameters["switchProb"] = int(math.log(switchProb, 2))  # prob to weight

    # record weight of upper trail, needed for final weight
    # uweight is just placeholder for upperWeight AKA limit
    upperWeight = parameters["sweight"]
    lowerWeight = parameters["lweight"]  # use for clustering?

    combinationCount = 0
    combinationLimit = len(leftResult) * len(rightResult)
    boomerangProb = []

    if (
        not search.reachedTimelimit(start_time, parameters["timelimit"])
        and lowerWeight < parameters["endweight"]
        # and combinationCount < combinationLimit
    ):
        lowerCharacteristic = searchDifferentialTrail(
            cipher,
            parameters,
            start_time,
            "lower",
        )

        try:
            left_gamma = int(lowerCharacteristic.getData()[0][0], 16)
            left_gamma_prime = int(lowerCharacteristic.getData()[0][1], 16)
            right_gamma = int(lowerCharacteristic.getData()[0][2], 16)
            right_gamma_prime = int(lowerCharacteristic.getData()[0][3], 16)

            lowerRound = parameters["lowertrail"]
            left_delta = int(lowerCharacteristic.getData()[lowerRound][0], 16)
            left_delta_prime = int(lowerCharacteristic.getData()[lowerRound][1], 16)
            right_delta = int(lowerCharacteristic.getData()[lowerRound][2], 16)
            right_delta_prime = int(lowerCharacteristic.getData()[lowerRound][3], 16)

        except:
            print(
                "No lower characteristic found for the given limits or no valid switch"
            )
            parameters["blockedUpperCharacteristics"].append(lowerCharacteristic)
            parameters["blockedLowerCharacteristics"].clear()
            return 0

        # sweight has been owerwrite by E1 search
        lowerWeight = parameters["sweight"]

        parameters["blockedLowerCharacteristics"].append(lowerCharacteristic)

        totalWeight = switchProb + upperWeight * 2 + lowerWeight * 2

        print("total weight of the trail: ", (upperWeight + lowerWeight))
        print("total rounds of the trail: ", (upperRound + lowerRound))

        parameters["blockedUpperCharacteristics"].append(upperCharacteristic)
        # Clear lower trails because the same lower trails can be matched to a different upper trail
        # need this while using while loop
        parameters["blockedLowerCharacteristics"].clear()
        parameters["uweight"] = upperWeight

        # p^2*q^2*r
        boomerangProb.append((parameters, math.log(totalWeight, 2)))

    print(f"{hex((right_alpha^left_alpha)>>9)}, {hex(right_gamma^left_gamma)}")
    print(
        f"{hex(right_alpha_prime^left_alpha_prime)}, {hex(right_gamma_prime^left_gamma_prime)}"
    )

    # print(f"{hex(right_beta^left_alpha)}, {hex(right_gamma^left_gamma)}")

    return boomerangProb


def searchDifferentialTrail(
    cipher, parameters, timestamp, boomerangFace="upper", switchInput=""
):
    """
    Search top or bottom trail (characteristic) of a boomerang
    modify from search.findMinWeightCharacteristic and boomerang.boomerangTrail
    """
    # Set parameters for targeted boomerang face
    if boomerangFace == "upper":
        weight = "uweight"
        trail = "uppertrail"
        block = "blockedUpperCharacteristics"
        searchLimit = parameters["wordsize"]  # 16
        # beta = ""
    else:
        weight = "lweight"
        # fixedPoint = "X0{}".format(parameters["lowertrail"])
        trail = "lowertrail"
        block = "blockedLowerCharacteristics"
        searchLimit = int(
            (
                parameters["wordsize"]
                * 4  # 64= uppertrail*2 + switchProb + lowertrail*2
                - parameters["sweight"] * 2
                - parameters["switchProb"]
            )
            / 2
        )

        # beta = switchInput

    print(
        (
            "Starting search for characteristic with minimal weight for {} trail\n"
            "{} - Rounds: {} Wordsize: {}".format(
                boomerangFace, cipher.name, parameters[trail], parameters["wordsize"]
            )
        )
    )
    print("---")
    start_time = timestamp
    # Set target weight for trail
    parameters["sweight"] = parameters[weight]
    parameters["fixedVariables"].clear()  # will not using fixedVariables params

    # Fix starting point if it has been set, ask user to set input, no fixed pointt
    if trail == "lowertrail" and parameters["lowerVariables"]:
        parameters["fixedVariables"] = parameters["lowerVariables"]

    elif trail == "uppertrail" and parameters["upperVariables"]:
        parameters["fixedVariables"] = parameters["upperVariables"]

    characteristic = ""

    print(parameters["fixedVariables"])

    while (
        not search.reachedTimelimit(start_time, parameters["timelimit"])
        and parameters["sweight"] < searchLimit
    ):
        print(
            "Weight: {} Time: {}s".format(
                parameters["sweight"], round(time.time() - start_time, 2)
            )
        )

        # Construct problem instance for given parameters
        stp_file = "tmp/{}-{}{}-{}-{}.stp".format(
            boomerangFace,
            cipher.name,
            parameters["wordsize"],
            parameters[trail],
            timestamp,
        )

        # Fix number of rounds
        parameters["rounds"] = parameters[trail]

        # Block characteristics and invalid switches
        parameters["blockedCharacteristics"].clear()
        parameters["blockedCharacteristics"] = parameters[block].copy()

        # print(trail, "===== ", parameters)

        cipher.createSTP(stp_file, parameters)
        # Block invalid switches in the stp file
        # if beta != "":
        #     print("Blocking invalid switching differences for {}".format(beta))
        #     blockInvalidSwitches(beta, parameters, stp_file)
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
                    "{} Trail for {} - Rounds {} - Wordsize {} - "
                    "Weight {} - Time {}s".format(
                        boomerangFace,
                        cipher.name,
                        parameters[trail],
                        parameters["wordsize"],
                        parameters["sweight"],
                        current_time,
                    )
                )
            )
            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher, parameters[trail]
                )
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher, parameters[trail]
                )
            characteristic.printText()
            print("----")
            break
        parameters["sweight"] += 1
        print("----")

    if parameters["sweight"] >= parameters["endweight"] and boomerangFace == "upper":
        print("Weight limit has been reached. Ending search.")
        quit()

    return characteristic


def blockVariableValue(stpfile, a, b):
    """
    Adds an assert that a != b to the stp stpfile.
    """
    stpfile.write("\nASSERT(NOT({} = {}));\n".format(a, b))
    # print("ASSERT(NOT({} = {}));".format(a, b))
    return


def boomerangClusterDifferential(
    cipher, parameters, input, output, weight, timestamp, boomerangFace="upper"
):
    """
    Perform clustering for one face of a boomerang differential
    modify from search.computeProbabilityOfDifferentials and boomerang.boomerangDifferential
    """
    # Set parameters for targeted boomerang face. Maintained for consistency.
    if boomerangFace == "upper":
        trail = "uppertrail"
        limit = "upperlimit"
    else:
        trail = "lowertrail"
        limit = "lowerlimit"

    start_time = timestamp

    print("Cluster {} differential".format(boomerangFace))

    # Clear blocked characteristics
    parameters["blockedCharacteristics"].clear()

    # Setup search
    # rnd_string_tmp = '%030x' % random.randrange(16**30)
    diff_prob = 0
    boomerangProb = 1
    characteristics_found = 0
    sat_logfile = "tmp/satlog{}.tmp".format(timestamp)

    parameters["fixedVariables"].clear()
    parameters["fixedVariables"]["X0"] = input
    parameters["fixedVariables"]["X{}".format(parameters[trail])] = output
    parameters["sweight"] = weight

    # TODO: Remove later
    print("XO - ", input)
    print("X{} -".format(parameters[trail]), output)

    # Fix number of rounds
    parameters["rounds"] = parameters[trail]

    # Search until optimal weight + wordsize/8
    while (
        not search.reachedTimelimit(start_time, parameters["timelimit"])
        and parameters["sweight"] < weight + parameters["wordsize"] / parameters[limit]
    ):
        if os.path.isfile(sat_logfile):
            os.remove(sat_logfile)

        stp_file = "tmp/{}{}-{}.stp".format(cipher.name, trail, timestamp)
        cipher.createSTP(stp_file, parameters)

        # Start solver
        sat_process = search.startSATsolver(stp_file)
        log_file = open(sat_logfile, "w")

        # Find the number of solutions with the SAT solver
        print("Finding all trails of weight {}".format(parameters["sweight"]))

        # Watch the process and count solutions
        solutions = 0
        while sat_process.poll() is None:
            line = sat_process.stdout.readline().decode("utf-8")
            log_file.write(line)
            if "s SATISFIABLE" in line:
                solutions += 1
            if solutions % 100 == 0:
                print("\tSolutions: {}\r".format(solutions // 2), end="")

        log_file.close()
        print("\tSolutions: {}".format(solutions // 2))

        assert solutions == search.countSolutionsLogfile(sat_logfile)

        # The encoded CNF contains every solution twice
        solutions //= 2

        # Print result
        diff_prob += math.pow(2, -parameters["sweight"]) * solutions
        characteristics_found += solutions
        if diff_prob > 0.0:
            # print("\tSolutions: {}".format(solutions))
            print("\tTrails found: {}".format(characteristics_found))
            print("\tCurrent Probability: " + str(math.log(diff_prob, 2)))
            print("\tTime: {}s".format(round(time.time() - start_time, 2)))
        parameters["sweight"] += 1

    print("----")
    return diff_prob
