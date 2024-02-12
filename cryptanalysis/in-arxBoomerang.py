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

import pathlib
import time

from fractions import gcd

# sparx and cham different?? sparx is left right word state, cham is only left, right not involve in ADD

libname = pathlib.Path().absolute()


def findARXBoomerangDifferential(cipher, parameters):
    """
    Performs the complete boomerang differential search
    Probabilistic switch is done by ABCT.cpp
    Check user setting, mode etc
    """

    if cipher.name not in ["sparxround", "cham"]:
        raise ValueError(
            "This mode is for ARX ciphers only. For SPN or GFN design, please select mode 5."
        )

    start_time = time.time()
    print("----")
    print("Running initial boomerang search")
    print("----")

    # generate an E0 and a LIST of candidates E1
    boomerangProb = computeBoomerangProb(cipher, parameters, start_time)

    # Compute other boomerang trails for the given input and output differences-- cluster the entire trail
    while not search.reachedTimelimit(start_time, parameters["timelimit"]):
        clusterProb = computeBoomerangProb(
            cipher, parameters, start_time, boomerangProb
        )
        if clusterProb == 99:  # No more upper trails for the given input
            break
        elif clusterProb == 0:  # No lower trail found for the given limits
            print("Trying a different upper trail")
        else:  # found the second trail with such as setting
            boomerangProb = clusterProb
            print("---")
            print("Improved boomerang probability = " + str(math.log(boomerangProb, 2)))


def computeBoomerangProb(cipher, parameters, timestamp, boomerangProb=0):
    """
    - Perform E0 and E1 search based on mode
    - Do clustering?
    - Return the full trails
    """

    searchLimit = ""
    if parameters["uweight"]:
        searchLimit = parameters["uweight"]  # for upper
    else:
        searchLimit = parameters["wordsize"]  # for upper

    start_time = timestamp

    upperCharacteristic = searchDifferentialTrail(
        cipher, parameters, start_time, "upper", searchLimit
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
        parameters["uweight"] = parameters["sweight"]

    except:
        print(
            "No characteristic found for the given limits. Please check the variables and weights setting.\n"
        )
        print("---")
        # parameters["blockedUpperCharacteristics"].append(upperCharacteristic)
        parameters["blockedLowerCharacteristics"].clear()
        # If no more upper characteristics can be found, best boomerang differential for the given input has been found
        parameters["uweight"] = parameters["sweight"]
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

    leftResult = [
        (0, 0, 1),
        # (0, 1, 0.5),
        # (1, 0, 0.5),
        # (1, 1, 0.5),
        # (2, 0, 0.9375),
    ]
    rightResult = [
        (0, 1, 0.5),
        # (0, 4, 0.5),
        # (1, 0, 0.5),
        # (1, 1, 0.5),
        # (2, 0, 0.5),
        # (6, 0, 0.625),
    ]

    combinationCount = 0
    combinationLimit = len(leftResult) * len(rightResult)
    upperWeight = parameters["sweight"]
    boomerangProbList = []
    while (
        not search.reachedTimelimit(start_time, parameters["timelimit"])
        and combinationCount < combinationLimit
        and combinationLimit > 0
    ):
        x0 = 0
        x1 = 0
        y0 = 0
        y1 = 0
        leftProb = 0.0
        rightProb = 0.0
        for left_tuple in leftResult:
            for right_tuple in rightResult:
                x0 = left_tuple[0]
                x1 = left_tuple[1]
                y0 = right_tuple[0]
                y1 = right_tuple[1]
                leftProb = left_tuple[2]
                rightProb = right_tuple[2]
                combinationCount += 1

                if cipher.name == "sparxround":
                    x1 = (x1 << 2) ^ x0
                    y1 = (y1 << 2) ^ y0

                elif cipher.name == "cham":
                    if upperRound % 2 == 0:
                        x1 = (x1 << 2) ^ x0
                        y1 = (y1 << 2) ^ y0
                    else:
                        x1 = (x1 << 2) ^ x0
                        y1 = (y1 << 2) ^ y0

                parameters["lowerVariables"] = {
                    "X00": "0x"
                    + format(x0, "04x"),  # 0x4 is to fix the hex into 16bits
                    "X10": "0x" + format(x1, "04x"),
                    "Y00": "0x" + format(y0, "04x"),
                    "Y10": "0x" + format(y1, "04x"),
                }

                switchProb = abs(
                    int(math.log((leftProb * rightProb), 2))
                )  # prob to weight
                # 64= uppertrail*2 + switchProb + lowertrail*2
                searchLimit = int((64 - (upperWeight * 2) - switchProb) / 2)
                # record weight of upper trail, needed for final weight
                # uweight is just placeholder for upperWeight AKA limit

                lowerWeight = parameters["lweight"]  # use for clustering?
                print(
                    "COMBINATION OF ",
                    combinationCount,
                    ": ",
                    parameters["lowerVariables"],
                )
                print("Switch Prob= ", switchProb)
                lowerCharacteristic = searchDifferentialTrail(
                    cipher, parameters, start_time, "lower", searchLimit
                )

                try:
                    left_gamma = int(lowerCharacteristic.getData()[0][0], 16)
                    left_gamma_prime = int(lowerCharacteristic.getData()[0][1], 16)
                    right_gamma = int(lowerCharacteristic.getData()[0][2], 16)
                    right_gamma_prime = int(lowerCharacteristic.getData()[0][3], 16)

                    lowerRound = parameters["lowertrail"]
                    left_delta = int(lowerCharacteristic.getData()[lowerRound][0], 16)
                    left_delta_prime = int(
                        lowerCharacteristic.getData()[lowerRound][1], 16
                    )
                    right_delta = int(lowerCharacteristic.getData()[lowerRound][2], 16)
                    right_delta_prime = int(
                        lowerCharacteristic.getData()[lowerRound][3], 16
                    )

                    # sweight has been owerwrite by E1 search
                    lowerWeight = parameters["sweight"]
                    totalWeight = switchProb + upperWeight * 2 + lowerWeight * 2

                    print("total weight of the trail: ", (upperWeight + lowerWeight))
                    print("total rounds of the trail: ", (upperRound + lowerRound))
                    parameters["uweight"] = upperWeight

                    lowerOutputDiff = {
                        f"X0{lowerRound}": "0x" + format(left_delta, "04x"),
                        f"X1{lowerRound}": "0x" + format(left_delta_prime, "04x"),
                        f"Y0{lowerRound}": "0x" + format(right_delta, "04x"),
                        f"Y1{lowerRound}": "0x" + format(right_delta_prime, "04x"),
                    }

                    # p^2*q^2*r
                    boomerangProbList.append(
                        (
                            parameters["lowerVariables"].copy(),
                            lowerOutputDiff,
                            parameters["sweight"],
                            totalWeight,
                        )
                    )
                # print(
                #     f"{hex((right_alpha>>9^left_alpha>>9))}, {hex(right_gamma^left_gamma)}"
                # )
                # print(
                #     f"{hex(right_alpha_prime^left_alpha_prime)}, {hex(right_gamma_prime^left_gamma_prime)}"
                # )

                except:
                    print(
                        "No lower characteristic found for the given limits.",
                    )
                    break  # if lower not found, exit the inner loop and try the next combination
    return boomerangProbList


def searchDifferentialTrail(
    cipher, parameters, timestamp, boomerangFace="upper", searchLimit=16
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
        # beta = ""
    else:
        weight = "lweight"
        # fixedPoint = "X0{}".format(parameters["lowertrail"])
        trail = "lowertrail"
        block = "blockedLowerCharacteristics"
        # beta = switchInput

    print(
        (
            "Starting search for characteristic with minimal weight for {} trail\n"
            "{} - Rounds: {} Wordsize: {}".format(
                boomerangFace, cipher.name, parameters[trail], parameters["wordsize"]
            )
        )
    )

    print("MAX weight of the {} trail= {}\n".format(boomerangFace, searchLimit))
    print("---\n")
    start_time = timestamp
    # Set target weight for trail
    parameters["sweight"] = parameters[weight]

    # Clear the variables set
    parameters["fixedVariables"].clear()
    parameters["boomerangVariables"].clear()

    # Fix starting point if it has been set, ask user to set input, no fixed pointt
    if trail == "lowertrail":
        parameters["fixedVariables"] = parameters["lowerVariables"]
        parameters["boomerangVariables"] = parameters["lowerBoomerangVariables"]

    elif trail == "uppertrail":
        parameters["fixedVariables"] = parameters["upperVariables"]
        parameters["boomerangVariables"] = parameters["upperBoomerangVariables"]

    characteristic = ""

    # print(parameters["fixedVariables"])

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
                    "{} trail for {} - Rounds {} - Wordsize {} - "
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
        # print("----")

    if parameters["sweight"] >= parameters["endweight"] and boomerangFace == "upper":
        print("Weight limit has been reached for ONLY E0, ending search.")
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
