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
import datetime


def findValidARXBoomerangDifferential(cipher, parameters):
    if cipher.name == "chamBoom":
        searchCHAM(cipher, parameters)
    elif cipher.name == "sparxroundBoom" or cipher.name == "sparxround":
        checkAbct.check_abct_prob(0x8022, 0x51c1, 0x2800, 0x0a04)
        searchSPARX(cipher, parameters)

    else:
        print("Cipher not support mode 6, please check again.")




def searchSPARX(cipher, parameters):
    total_switch_prob = 0

    parameters["blockedUpperCharacteristics"] = []
    parameters["blockedLowerCharacteristics"] = []
    # used to store abct params, avoid the same diff if this search not compatible, for display purpose also
    parameters["boomerangVariable"] = []

    # data of e0 and e1 trails, for display purpose
    parameters["upperVariable"]= []
    parameters["lowerVariable"]= []

    while total_switch_prob == 0:
        try:
            startTime = time.time()
            switchRound = parameters["switchround"]
            parameters["rounds"] = (
                parameters["uppertrail"] + parameters["lowertrail"] + 1
            )
            upperEndRound= parameters["uppertrail"]
            lowerStartRound = parameters["switchround"]
            lowerEndRound= parameters["rounds"]

            characteristic = searchDifferentialTrail(
                cipher, parameters, startTime, parameters["endweight"]
            )
            if not characteristic:
                print(
                    f"No upper trail found for the swicth at R{switchRound}. Please check the setting again.\n"
                )
                return

            else:
                # extract alphas;
                left_alpha = int(
                    characteristic.getData()[upperEndRound][0], 16
                )
                left_alpha_prime = int(
                    characteristic.getData()[upperEndRound][1], 16
                )
                right_alpha = int(
                    characteristic.getData()[upperEndRound][2], 16
                )
                right_alpha_prime = int(
                    characteristic.getData()[upperEndRound][3], 16
                )

                left_beta = int(
                    characteristic.getData()[lowerStartRound][0], 16
                )
                left_beta_prime = int(
                    characteristic.getData()[lowerStartRound][1], 16
                )
                right_beta = int(
                    characteristic.getData()[lowerStartRound][2], 16
                )
                right_beta_prime = int(
                    characteristic.getData()[lowerStartRound][3], 16
                )
                
                #left branch
                parameters["boomerangVariable"].append({f"X0{upperEndRound}": "0x" + format(left_alpha, "04x")})
                parameters["boomerangVariable"].append({f"X1{upperEndRound}": "0x" + format(left_alpha_prime, "04x")})
                parameters["boomerangVariable"].append({f"X0{lowerStartRound}": "0x" + format(left_beta, "04x")})
                parameters["boomerangVariable"].append({f"X1{lowerStartRound}": "0x" + format(left_beta_prime, "04x")})
                #right branch
                parameters["boomerangVariable"].append({f"Y0{upperEndRound}": "0x" + format(right_alpha, "04x")})
                parameters["boomerangVariable"].append({f"Y1{upperEndRound}": "0x" + format(right_alpha_prime, "04x")})
                parameters["boomerangVariable"].append({f"Y0{lowerStartRound}": "0x" + format(right_beta, "04x")})
                parameters["boomerangVariable"].append({f"Y1{lowerStartRound}": "0x" + format(right_beta_prime, "04x")})

                parameters["upperVariable"].append({f"X00": "0x" + format(int(characteristic.getData()[0][0], 16), "04x")})
                parameters["upperVariable"].append({f"X10": "0x" + format(int(characteristic.getData()[0][1], 16), "04x")})
                parameters["upperVariable"].append({f"Y00": "0x" + format(int(characteristic.getData()[0][2], 16), "04x")})
                parameters["upperVariable"].append({f"Y10": "0x" + format(int(characteristic.getData()[0][3], 16), "04x")})
                parameters["upperVariable"].append({f"X0{upperEndRound}": "0x" + format(left_alpha, "04x")})
                parameters["upperVariable"].append({f"X1{upperEndRound}": "0x" + format(left_alpha_prime, "04x")})
                parameters["upperVariable"].append({f"Y0{upperEndRound}": "0x" + format(right_alpha, "04x")})
                parameters["upperVariable"].append({f"Y1{upperEndRound}": "0x" + format(right_alpha_prime, "04x")})
              
                parameters["lowerVariable"].append({f"X0{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][0], 16), "04x")})
                parameters["lowerVariable"].append({f"X1{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][1], 16), "04x")})
                parameters["lowerVariable"].append({f"Y0{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][2], 16), "04x")})
                parameters["lowerVariable"].append({f"Y1{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][3], 16), "04x")})
                parameters["lowerVariable"].append({f"X0{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][0], 16), "04x")})
                parameters["lowerVariable"].append({f"X1{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][1], 16), "04x")})
                parameters["lowerVariable"].append({f"Y0{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][2], 16), "04x")})
                parameters["lowerVariable"].append({f"Y1{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][3], 16), "04x")})
                
                print("Obtaining differences for the switch round...")
                count = 0
                last_eight = parameters["boomerangVariable"][-8:]
                for item in last_eight:
                    # print(item.items())
                  for key, value in item.items():
                    print(f"{key}: {value}, ", end="")
                    count += 1
                    if count % 4 == 0:
                      print()  # New line after every 4 items
                print("----")
                print("Rotating differences...")

                left_alpha = rotr(left_alpha, 7)  # >>>7
                right_alpha = rotr(right_alpha, 7)

                # reverse the linear layer
                if lowerStartRound % 3 == 0:
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

                print(f"----\nChecking ABCT for switching probability....")
                left_prob = checkAbct.check_abct_prob(
                    left_alpha, left_alpha_prime, left_beta, left_beta_prime
                )
                right_prob = checkAbct.check_abct_prob(
                    right_alpha, right_alpha_prime, right_beta, right_beta_prime
                )
                total_switch_prob = left_prob * right_prob

                #     acc_weight = 0
                #     for row in lowerCharacteristic.getData()[:lowerStartRound]:
                #         acc_weight += abs(int(row[10]) + int(row[11]))

                if total_switch_prob != 0:
                  total_switch_weight = abs(math.log(total_switch_prob, 2))
                  total_weight = (parameters["sweight"] * 2) + total_switch_weight
                  print("----\nTotal Switch Weight:", total_switch_weight)
                  print("Total Weight:", total_weight)
                  print("----")
                  print(f"{parameters["uppertrail"]} rounds uppertrail:",)
                  for item in parameters["upperVariable"]:
                    for key, value in item.items():
                      print(f"{key}: {value}, ", end="")
                  print(f"\nOne round boomerang switch at R{parameters["switchround"]}")
                  print(f"{parameters["lowertrail"]} rounds lowertrail:")
                  for item in parameters["lowerVariable"]:
                    for key, value in item.items():
                      print(f"{key}: {value}, ", end="")
                  print("\n---")
                else:
                    print("Trails not compatible. Start new search. \n")
                    # parameters["fixedVariables"].clear()
                    parameters["sweight"] = parameters["sweight"]
                    parameters["endweight"] = 32  # maybe can use some constant
                    parameters["blockedCharacteristics"].append(characteristic) #might consider remove as it might conflict with fixed variables?
                    

        except Exception as e:
            print("Error occured here...", e)
            return  # this will stop the while loop once there is error


def searchSPARXSplit(cipher, parameters):
    total_prob = 0

    while total_prob == 0:
        try:
            startTime = time.time()
            switchRound = parameters["switchround"]
            parameters["rounds"] = parameters["uppertrail"]
            parameters["part"] = (
                "upper"  # variables to control the encoded HPBS patterns
            )
            parameters["skipround"] = 99
            parameters["fixedVariables"] = {}
            if "upperVariables" in parameters and parameters["upperVariables"]:
                for d in parameters["upperVariables"]:
                    parameters["fixedVariables"].update(d)
            # print(type(parameters["upperVariables"]))
            # print(parameters["upperVariables"])

            # Initialise separate blocked trails
            parameters["blockedUpperCharacteristics"] = []
            parameters["blockedLowerCharacteristics"] = []
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
                if switchRound % 3 == 0:  # X06
                    parameters["skipround"] = 2
                elif (switchRound - 2) % 3 == 0:  # X05
                    parameters["skipround"] = 1
                else:
                    parameters["skipround"] = 0  # X04

                # lowertrail is the length of E1, if lowerStartRound from R2, then the skip round=1, and the "rounds"= lowertrail+lowerStartRound

                # if not parameters["skipround"] == 99:
                parameters["rounds"] = (
                    parameters["lowertrail"] + parameters["skipround"] + 1
                )
                # else:
                #     parameters["rounds"] = parameters["lowertrail"]
                parameters["part"] = "lower"
                parameters["endweight"] = parameters["endweight"] - upperWeight
                # strat the search from zero, maybe can modify later
                parameters["sweight"] = parameters["lowerweight"]
                parameters["fixedVariables"] = {}
                if "lowerVariables" in parameters and parameters["lowerVariables"]:
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
                    if not parameters["skipround"] == 99:
                        lowerStartRound = parameters["skipround"] + 1

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
                        print(left_beta, left_beta_prime, right_beta, right_beta_prime)


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
                            f"Total Weight: {upperWeight} + {lowerWeight} = {(upperWeight * 2) + (lowerWeight * 2) + total_switch_weight}",
                        )
                        print("---")
                    else:
                        print("Trails not compatible. Start new search. \n")
                        parameters["sweight"] = upperWeight
                        parameters["lowerStartWeight"] = parameters["sweight"]
                        parameters["endweight"] = 50  # maybe can use some constant
                        # parameters["part"] = "upper"
                        # parameters["fixedVariables"].clear()
                        # parameters["rounds"] = parameters["uppertrail"]
                        # parameters["skipround"] = 99

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
    parameters["rounds"] = parameters["uppertrail"] + parameters["lowertrail"] + 1
    total_switch_prob = 0

    # Initialise separate blocked trails
    parameters["blockedUpperCharacteristics"] = []
    parameters["blockedLowerCharacteristics"] = []
    parameters["boomerangVariable"]= []
    parameters["upperVariable"]= []
    parameters["lowerVariable"]= []

    while total_switch_prob==0:
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
              lowerStartRound = switchRound

              alpha = int(characteristic.getData()[upperEndRound][0], 16)
              alpha_prime = int(characteristic.getData()[upperEndRound][1], 16)
              beta = int(characteristic.getData()[lowerStartRound][3], 16)
              beta_prime = int(characteristic.getData()[lowerStartRound][0], 16)

              parameters["boomerangVariable"].append({f"X0{upperEndRound}": "0x" + format(alpha, "04x")})
              parameters["boomerangVariable"].append({f"X1{upperEndRound}": "0x" + format(alpha_prime, "04x")})
              parameters["boomerangVariable"].append({f"X3{lowerStartRound}": "0x" + format(beta, "04x")})
              parameters["boomerangVariable"].append({f"X0{lowerStartRound}": "0x" + format(beta_prime, "04x")})

              parameters["upperVariable"].append({f"X00": "0x" + format(int(characteristic.getData()[0][0], 16), "04x")})
              parameters["upperVariable"].append({f"X10": "0x" + format(int(characteristic.getData()[0][1], 16), "04x")})
              parameters["upperVariable"].append({f"X20": "0x" + format(int(characteristic.getData()[0][2], 16), "04x")})
              parameters["upperVariable"].append({f"X30": "0x" + format(int(characteristic.getData()[0][3], 16), "04x")})
              parameters["upperVariable"].append({f"X0{upperEndRound}": "0x" + format(alpha, "04x")})
              parameters["upperVariable"].append({f"X1{upperEndRound}": "0x" + format(alpha_prime, "04x")})
              parameters["upperVariable"].append({f"X2{upperEndRound}": "0x" + format(int(characteristic.getData()[upperEndRound][2], 16), "04x")})
              parameters["upperVariable"].append({f"X3{upperEndRound}": "0x" + format(int(characteristic.getData()[upperEndRound][3], 16), "04x")})
            
              lowerEndRound= parameters["rounds"]
              parameters["lowerVariable"].append({f"X0{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][0], 16), "04x")})
              parameters["lowerVariable"].append({f"X1{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][1], 16), "04x")})
              parameters["lowerVariable"].append({f"X2{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][2], 16), "04x")})
              parameters["lowerVariable"].append({f"X3{lowerStartRound}": "0x" + format(int(characteristic.getData()[lowerStartRound][3], 16), "04x")})
              parameters["lowerVariable"].append({f"X0{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][0], 16), "04x")})
              parameters["lowerVariable"].append({f"X1{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][1], 16), "04x")})
              parameters["lowerVariable"].append({f"X2{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][2], 16), "04x")})
              parameters["lowerVariable"].append({f"X3{lowerEndRound}": "0x" + format(int(characteristic.getData()[lowerEndRound][3], 16), "04x")})
          
              print("Obtaining differences for the switch round...")
              for item in parameters["boomerangVariable"]:
                for key, value in item.items():
                  print(f"{key}: {value}, ", end="")
              
              print("\n----")
              print("Rotating differences...")
              if upperEndRound % 2 == 0: # even to odd, use even round setting
                  alpha_prime = rotl(alpha_prime, 1)
                  beta = rotr(beta, 8)
                  beta_prime = rotl(beta_prime, 1)

              else: # odd to even, use odd setting
                  alpha_prime = rotl(alpha_prime, 8)
                  beta = rotr(beta, 1)  # ROTR1(beta)
                  beta_prime = rotl(beta_prime, 8)  # beta' follow rotation of alpha'

              # print(
              #     "Betas: ",
              #     format(beta, "04x"),
              #     format(beta_prime, "04x"),
              # )

              print(f"----\nChecking ABCT for switching probability....")
              # leftSwitchProb = 1.0
              total_switch_prob = checkAbct.check_abct_prob(
                  alpha, alpha_prime, beta, beta_prime
              )

              if total_switch_prob != 0:
                  total_switch_weight = abs(math.log(total_switch_prob, 2))
                  total_weight = (parameters["sweight"] * 2) + total_switch_weight
                  print("----\nTotal Switch Weight:", total_switch_weight)
                  print("Total Weight:", total_weight)
                  print("----")
                  print(f"{parameters["uppertrail"]} rounds uppertrail:",)
                  for item in parameters["upperVariable"]:
                    for key, value in item.items():
                      print(f"{key}: {value}, ", end="")
                  print(f"\nOne round boomerang switch at R{parameters["switchround"]}")
                  print(f"{parameters["lowertrail"]} rounds lowertrail:")
                  for item in parameters["lowerVariable"]:
                    for key, value in item.items():
                      print(f"{key}: {value}, ", end="")                
              else:
                    print("Trails not compatible. Start new search. \n")
                    parameters["fixedVariables"].clear()
                    parameters["sweight"] = parameters["sweight"]
                    parameters["endweight"] = 32  # maybe can use some constant
                    parameters["blockedCharacteristics"].append(characteristic) #might consider remove as it might conflict with fixed variables?
                    
      except Exception as e:
          print("Error occured here...", e)


def searchDifferentialTrail(cipher, parameters, timestamp, searchLimit):
    """
    Search top or bottom trail (characteristic) of a boomerang
    modify from search.findMinWeightCharacteristic and boomerang.boomerangTrail
    """
    print(f"Starting search for boomerang characteristic with minimal weight for")
    print(
        f"{cipher.name} - Rounds: {parameters['rounds']} Upper: {parameters["uppertrail"]} Lower: {parameters["lowertrail"]} Switch: {parameters['switchround']} Wordsize: {parameters['wordsize']}"
    )

    print("MAX weight= {} of the boomerang trail".format(searchLimit))
    print("---")
    start_time = time.time()

  
    # Set target weight for trail
    # parameters["sweight"] = parameters["weight"]

    characteristic = ""

    print('parameters["fixedVariables"] : ', parameters["fixedVariables"])
    # if cipher.name== "sparxroundBoom":
    #   print('parameters["skipround"] : ', parameters["skipround"])
    # print('parameters["boomerangVariables"] : ', parameters["boomerangVariables"])

    value = datetime.datetime.fromtimestamp(timestamp)

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
        stp_file = "tmp/{}-upper{}-lower{}-{}.stp".format(
            cipher.name,
            parameters["uppertrail"],
            parameters["uppertrail"],
            value.strftime('%Y-%m-%d %H:%M:%S')
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

            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher, parameters["rounds"]
                )
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher, parameters["rounds"]
                )
            # if cipher.name == "sparxroundBoom":
            #     if not parameters["skipround"] == 99:
            #         lowerStartRound = parameters["skipround"] + 1
            #         for row in characteristic.getData()[:lowerStartRound]:
            #             acc_weight += abs(int(row[10]) + int(row[11]))
            #             row[10] = "-0"
            #             row[11] = "-0"
            #         # print(characteristic.getData([2][2]))

            #     parameters["sweight"] = parameters["sweight"] - acc_weight
            print("---")
            print(
                (
                    "Boomerang trail for {} - Rounds {}(upper:{}/lower:{}) - Switch {} - Wordsize {} - "
                    "Weight {} - Time {}s".format(
                        cipher.name,
                        parameters["rounds"],
                        parameters["uppertrail"],
                        parameters["lowertrail"],
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


def searchEasySPARXUpper(cipher, parameters):
    startTime = time.time()
    switchRound = parameters["switchround"]
    parameters["rounds"] = parameters["uppertrail"]
    parameters["part"] = "upper"  # variables to control the encoded HPBS patterns
    total_prob = 0
    parameters["fixedVariables"] = {}
    if "upperVariables" in parameters and parameters["upperVariables"]:
        for d in parameters["upperVariables"]:
            parameters["fixedVariables"].update(d)
    # print(type(parameters["upperVariables"]))
    # print(parameters["upperVariables"])

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

                left_prob = checkAbct.check_abct_prob(
                    left_alpha, left_alpha_prime, 0x2800, 0x0A04
                )
                right_prob = checkAbct.check_abct_prob(
                    right_alpha, right_alpha_prime, 0x2800, 0x0A04
                )
                # total_prob = 0
                total_prob = left_prob * right_prob
                total_switch_weight = 0
                if total_prob != 0:
                    total_switch_weight = abs(math.log(left_prob * right_prob, 2))
                lowerWeight = 17
                print("---")
                print("Total Switch Weight: ", total_switch_weight)
                print(
                    f"Total Weight: {upperWeight} + {lowerWeight} = {(upperWeight * 2) + (lowerWeight * 2) + total_switch_weight}",
                )
                print("---")
                # else:
                # print("Trails not compatible. Start new search. \n")
                parameters["sweight"] = upperWeight
                # parameters["fixedVariables"].clear()
                parameters["rounds"] = parameters["uppertrail"]
                parameters["skipround"] = 99

                parameters["blockedCharacteristics"].append(upperCharacteristic)

        except Exception as e:
            print("Error occured here...", e)
            return  # this will stop the while loop once there is error


def searchEasySPARXLower(cipher, parameters):
    startTime = time.time()
    switchRound = parameters["switchround"]
    parameters["rounds"] = parameters["lowertrail"]
    parameters["sweight"] = parameters["lowerweight"]

    if not parameters["skipround"] == 99:
        parameters["rounds"] = parameters["lowertrail"] + parameters["skipround"] + 1

    parameters["part"] = "lower"  # variables to control the encoded HPBS patterns
    total_prob = 0
    parameters["fixedVariables"] = {}
    if "lowerVariables" in parameters and parameters["lowerVariables"]:
        for d in parameters["lowerVariables"]:
            parameters["fixedVariables"].update(d)
    # print(type(parameters["upperVariables"]))
    # print(parameters["upperVariables"])

    # Initialise separate blocked trails
    parameters["blockedUpperCharacteristics"] = []
    parameters["blockedLowerCharacteristics"] = []
    while True:
        try:

            lowerCharacteristic = searchDifferentialTrail(
                cipher, parameters, startTime, parameters["endweight"]
            )
            if not lowerCharacteristic:
                print(
                    f"No lower trail found for the swicth at R{switchRound}. Please check the setting again.\n"
                )
                return

            else:
                if not parameters["skipround"] == 99:
                    lowerStartRound = parameters["skipround"] + 1

                else:
                    lowerStartRound = 0

                left_beta = int(lowerCharacteristic.getData()[lowerStartRound][0], 16)
                left_beta_prime = int(
                    lowerCharacteristic.getData()[lowerStartRound][1], 16
                )
                right_beta = int(lowerCharacteristic.getData()[lowerStartRound][2], 16)
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
                    0x0000, 0x0000, left_beta, left_beta_prime
                )
                right_prob = checkAbct.check_abct_prob(
                    0x0000, 0x0000, right_beta, right_beta_prime
                )
                # total_prob = 0
                total_prob = left_prob * right_prob
                upperWeight = 15

                acc_weight = 0
                for row in lowerCharacteristic.getData()[:lowerStartRound]:
                    acc_weight += abs(int(row[10]) + int(row[11]))

                total_switch_weight = abs(math.log(left_prob * right_prob, 2))
                lowerWeight = parameters["sweight"]
                print("---")
                print("Total Switch Weight: ", total_switch_weight)
                print(
                    f"Total Weight: {upperWeight} + {lowerWeight} = {(upperWeight * 2) + (lowerWeight * 2) + total_switch_weight}",
                )
                print("---")
                parameters["fixedVariables"].clear()
                parameters["blockedLowerCharacteristics"].append(lowerCharacteristic)

        except Exception as e:
            print("Error occured here...", e)
            return  # this will stop the while loop once there is error
