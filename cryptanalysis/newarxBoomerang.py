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

# sparx and cham different?? sparx is left right word state, cham is only left, right not involve in ADD

libname = pathlib.Path().absolute()


def findARXBoomerangDifferential(cipher, parameters):
    """
    Performs the complete boomerang differential search
    Probabilistic switch is done by ABCT.cpp
    Check user setting, mode etc
    """

    try:
        if cipher.name not in ["sparxround", "cham"]:
            raise ValueError(
                "This mode is for ARX ciphers only. For SPN or GFN design, please select mode 5."
            )
        if parameters["abctMode"] == 2:
            if parameters["leftFilePath"] == "" or parameters["rightFilePath"] == "":
                raise ValueError(
                    "ABCT mode 2 need input files to start the search, please check leftFilePath and rightFilePath."
                )

    except:
        print("----")
        print(sys.exc_info()[0], "occurred")
        print("Please check your setting.")
        quit()

    start_time = time.time()
    print("----")
    print("Running initial boomerang search")
    print("----")

    # generate an E0 and a LIST of candidates E1
    boomerangProb = computeBoomerangProb(cipher, parameters, start_time)

    # Compute other boomerang trails for the given input and output differences-- cluster the entire trail
    # while not search.reachedTimelimit(start_time, parameters["timelimit"]):
    #     print("~~~~~~~~testtttyyyyy===")
    #     clusterProb = computeBoomerangProb(
    #         cipher, parameters, start_time, boomerangProb
    #     )
    #     if clusterProb == 99:  # No more upper trails for the given input
    #         break
    #     elif clusterProb == 0:  # No lower trail found for the given limits
    #         print("Trying a different upper trail")
    #     else:  # found the second trail with such as setting
    #         boomerangProb = clusterProb
    #         print("---")
    #         print("Improved boomerang probability = " + str(math.log(boomerangProb, 2)))


def computeBoomerangProb(cipher, parameters, timestamp, boomerangProb=0):
    """
    - Perform E0 and E1 search based on mode:
      abctMode = 1  # search E0 >> top 20 best switch (live abct search) >> 20 E1 >> pick best E1
      abctMode = 2  # search E0 >> top 20 best switch (check if files supplied) >> 20 E1 >> pick best E1
      abctMode = 3  # fix E0 and E1 diff (check if variables exist) >> search E0 >> search E1 >> look for ABCT to valid switch
    - Do clustering (todo)
    - Return the full trails info + prob after clustering
    """

    searchLimit = ""
    if parameters["uweight"]:
        searchLimit = parameters["uweight"]  # for upper
    else:
        searchLimit = parameters["wordsize"]  # for upper

    start_time = timestamp
    abctMode = parameters["abctMode"]

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

    except:
        print(
            "No characteristic found for the given limits. Please check the variables and weights setting.\n"
        )
        print("---")
        parameters["blockedUpperCharacteristics"].append(upperCharacteristic)
        parameters["blockedLowerCharacteristics"].clear()
        # If no more upper characteristics can be found, best boomerang differential for the given input has been found
        parameters["uweight"] = parameters["sweight"]
        return 99

    """
      this section of code will only execute if upperCharacteristics found
    """
    # Store optimal weight found for E0
    # so the new round of search of E0 will start from this weight if the first attempt failed(w=99)
    upperWeight = parameters["sweight"]

    parameters["uweight"] = parameters["sweight"]
    # record the fixed variables for clustering
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

    leftUpper = (left_beta, left_beta_prime)
    rightUpper = (right_beta, right_beta_prime)

    # rotate the output, round applicable for round varies cipher: CHAM
    leftUpper, rightUpper = inputRotation(
        cipher.name, leftUpper, rightUpper, upperRound
    )

    leftSwitch = []
    rightSwitch = []

    if abctMode == 1:
        # live search top 20 switches with best prob
        print("Checking valid switches for LHS word state...")
        leftSwitch = checkAbct.compute_abct_switch(
            leftUpper[0], leftUpper[1], start_time
        )
        print("Checking valid switches for RHS word state...")
        rightSwitch = checkAbct.compute_abct_switch(
            rightUpper[0], rightUpper[1], start_time
        )
        lowerProb = computeTop20LowerTrail(
            cipher, parameters, timestamp, leftSwitch, rightSwitch
        )

    elif abctMode == 2:
        # process users' files, filter top 20 switches with best prob
        leftSwitch = checkAbct.parse_abct_prob(parameters["leftFilePath"])
        rightSwitch = checkAbct.parse_abct_prob(parameters["rightFilePath"])
        lowerProb = computeTop20LowerTrail(
            cipher, parameters, timestamp, leftSwitch, rightSwitch
        )

    elif abctMode == 3:
        # which not guarantee to get trail
        lowerProb = computeLowerTrail(
            cipher, parameters, timestamp, leftSwitch, rightSwitch
        )


def computeTop20LowerTrail(cipher, parameters, timestamp, leftSwitch, rightSwitch):
    """
    compute trails list, then select the best upper+lower combo
    """

    combinationCount = 0
    combinationLimit = len(leftSwitch) * len(rightSwitch)
    boomerangProbList = []
    start_time = timestamp

    # record the result from the E0 found
    upperWeight = parameters["uweight"]
    upperRound = parameters["uppertrail"]

    # just for declaration purpose
    lowerWeight = parameters["lweight"]
    lowerRound = parameters["lowertrail"]

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
        for left_tuple in leftSwitch:
            for right_tuple in rightSwitch:
                combinationCount += 1

                # rotate the switches first, then only feed into search
                left_tuple, right_tuple = inputRotation(
                    cipher.name, left_tuple, right_tuple, upperRound
                )

                # update the rotated switches
                x0 = left_tuple[0]
                x1 = left_tuple[1]
                y0 = right_tuple[0]
                y1 = right_tuple[1]
                leftProb = left_tuple[2]
                rightProb = right_tuple[2]

                # 0x4 is to fix the hex into 16bits
                parameters["lowerVariables"] = {
                    "X00": "0x" + format(x0, "04x"),
                    "X10": "0x" + format(x1, "04x"),
                    "Y00": "0x" + format(y0, "04x"),
                    "Y10": "0x" + format(y1, "04x"),
                }

                # convert prob to weight to calculate max weight for E1
                switchProb = abs(int(math.log((leftProb * rightProb), 2)))

                # 64= uppertrail*2 + switchProb + lowertrail*2
                searchLimit = int((64 - (upperWeight * 2) - switchProb) / 2)

                # use for next attempt of E1 search (like E0)
                lowerWeight = parameters["lweight"]

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

                except:
                    print(
                        "No lower characteristic found for the given limits.",
                    )
                    break  # if lower not found, exit the inner loop and try the next combination

                lowerWeight = parameters["sweight"]

                # p^2*q^2*r
                totalWeight = switchProb + upperWeight * 2 + lowerWeight * 2

                print("total weight of the trail: ", (upperWeight + lowerWeight))
                print(
                    "total rounds of the trail: ",
                    (lowerWeight + lowerRound),
                )

                # for print screen purpose
                lowerOutputDiff = {
                    f"X0{lowerRound}": "0x" + format(left_delta, "04x"),
                    f"X1{lowerRound}": "0x" + format(left_delta_prime, "04x"),
                    f"Y0{lowerRound}": "0x" + format(right_delta, "04x"),
                    f"Y1{lowerRound}": "0x" + format(right_delta_prime, "04x"),
                }

                # append 20(might be not) trails computed from valid switches
                boomerangProbList.append(
                    (
                        parameters["lowerVariables"].copy(),  # E1 input
                        lowerOutputDiff,  # E1 output
                        parameters["sweight"],
                        totalWeight,
                    )
                )
    bestWeightTrail = min(boomerangProbList, key=lambda x: x[3])
    # find the best E1
    candidateTrailList = [
        num for num in boomerangProbList if num[3] == bestWeightTrail[3]
    ]

    parameters["uweight"] = bestWeightTrail[3]

    print("\n----")
    print("Boomerang search completed.")
    print("The weight of E0 trail is ", parameters["uweight"])
    inputDiff = {
        key: parameters["upperVariables"][key]
        for key in list(parameters["upperVariables"].keys())[:4]
    }
    outputDiff = {
        key: parameters["upperVariables"][key]
        for key in list(parameters["upperVariables"].keys())[:-4]
    }

    print(
        "Input: {} \nOutput: {} \nWeight of E0 Trail: {}".format(
            inputDiff,
            outputDiff,
            parameters["uweight"],
        )
    )
    print("The weight of best E1 trail is ", bestWeightTrail[3])
    print("The trail(s) with same weight: ")
    for trail in candidateTrailList:
        print(
            "Input: {} \nOutput: {} \nWeight of E1 Trail: {}, Total Weight: {}".format(
                trail[0], trail[1], trail[2], trail[3]
            )
        )

    finalBoomerangProb = math.log(bestWeightTrail[3], 2)

    print("Final boomerang probability = ", finalBoomerangProb)

    return finalBoomerangProb


def computeLowerTrail(cipher, parameters, timestamp, boomerangFace, searchLimit):
    lowerCharacteristic = searchDifferentialTrail(
        cipher, parameters, timestamp, boomerangFace, searchLimit
    )


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


def inputRotation(cipher, leftVars, rightVars, round):
    """
    Rotate the output of E0 and input of E1 for ciphers
    """
    x0 = leftVars[0]
    x1 = leftVars[1]
    y0 = rightVars[0]
    y1 = rightVars[1]

    if cipher == "sparxround":
        x1 = (x1 << 2) ^ x0
        y1 = (y1 << 2) ^ y0

    elif cipher == "cham":
        if round % 2 == 0:
            x1 = (x1 << 2) ^ x0
            y1 = (y1 << 2) ^ y0
        else:
            x1 = (x1 << 2) ^ x0
            y1 = (y1 << 2) ^ y0
    return (leftVars, rightVars)
