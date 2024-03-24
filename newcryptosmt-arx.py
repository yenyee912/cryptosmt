"""
Created on Mar 28, 2014

@author: stefan

Version: 5 October, 2021 with Boomerang Support
@author: jesenteh
Note:
To support WARP, the modified stpcommands must be included because the state words for WARP/TWINE is missing
"""

from cryptanalysis import newarxBoomerang, search, boomerang, newBoom
from ciphers import simon, speck, simonlinear, warp, sparxroundBoom
from ciphers import sparx, sparxround, cham
from config import PATH_STP, PATH_CRYPTOMINISAT, PATH_BOOLECTOR

from argparse import ArgumentParser, RawTextHelpFormatter

import yaml
import os
import pathlib

libname = pathlib.Path().absolute()


def startsearch(tool_parameters):
    """
    Starts the search tool for the given parameters
    """

    cipher_suite = {
        "simon": simon.SimonCipher(),
        "speck": speck.SpeckCipher(),
        "simonlinear": simonlinear.SimonLinearCipher(),
        "warp": warp.WarpCipher(),
        "sparxround": sparxround.SPARXRoundCipher(),
        "sparxroundBoom": sparxroundBoom.SPARXRoundCipher(),
        "cham": cham.CHAMCipher(),
    }

    cipher = None

    if tool_parameters["cipher"] in cipher_suite:
        cipher = cipher_suite[tool_parameters["cipher"]]
    else:
        print("Cipher not supported!")
        return

    # Handle program flow
    if tool_parameters["mode"] == 0:
        search.findMinWeightCharacteristic(cipher, tool_parameters)
    elif tool_parameters["mode"] == 1:
        search.searchCharacteristics(cipher, tool_parameters)
    elif tool_parameters["mode"] == 2:
        search.findAllCharacteristics(cipher, tool_parameters)
    elif tool_parameters["mode"] == 3:
        search.findBestConstants(cipher, tool_parameters)
    elif tool_parameters["mode"] == 4:
        search.computeProbabilityOfDifferentials(cipher, tool_parameters)
    elif tool_parameters["mode"] == 5:
        boomerang.computeFeistelBoomerangDifferential(cipher, tool_parameters)
    elif tool_parameters["mode"] == 6:
        newarxBoomerang.findARXBoomerangDifferential(cipher, tool_parameters)
    elif tool_parameters["mode"] == 7:
        newBoom.findARXBoomerangDifferentialByMatchSwitch(cipher, tool_parameters)
    return


def checkenviroment():
    """
    Basic checks if the enviroment is set up correctly
    """

    if not os.path.exists("./tmp/"):
        os.makedirs("./tmp/")

    if not os.path.exists(PATH_STP):
        print("ERROR: Could not find STP binary, please check config.py")
        exit()

    if not os.path.exists(PATH_CRYPTOMINISAT):
        print(
            "WARNING: Could not find CRYPTOMINISAT binary, please check " "config.py."
        )

    if not os.path.exists(PATH_BOOLECTOR):
        print(
            'WARNING: Could not find BOOLECTOR binary, "--boolector" '
            "option not available."
        )

    return


def loadparameters(args):
    """
    Get parameters from the argument list and inputfile.
    """
    # Load default values

    params = {
        "cipher": "sparxroundBoom",
        "rounds": 5,  # uppertrail+ switchround=1r+ lowertrail
        "skipround": 99,
        "switchround": 3,  # which #round to switch
        "uppertrail": 2,  # Number of rounds for E0
        "lowertrail": 3,  # Number of rounds for E1
        "uweight": 0,  # Upper limit of weight for E0
        "lweight": 0,  # Upper limit of weight for E1
        "upperlimit": 0,  # cluster up to +8 (128/16=8) - Upper will not be clustered too often, can be higher
        "lowerlimit": 0,  # cluster up to +4 (128/32=4) - Will be clustered often, set to a conservative value
        "mode": 7,
        "wordsize": 16,
        # "blocksize" : 64,
        "sweight": 0,
        "endweight": 1000,  # set to the higher weight limit + 1 (e.g. if uweight is higher than lweight, set end weight to uweight+1)
        "iterative": False,
        "boolector": False,
        "dot": None,
        "latex": None,
        "nummessages": 1,
        "timelimit": -1,
        "fixedVariables": {},
        "boomerangVariables": {},  # for system use only
        # ---- params for abct
        "lowerBoomerangVariables": {},
        "upperBoomerangVariables": {},
        "lowerVariables": {
            # user use to set fixed starting/ending for E1 trail search
        },
        "upperVariables": {
            # user use to set fixed starting/ending for E0 trail search
        },
        "blockedCharacteristics": [],
        "blockedUpperCharacteristics": [],
        "blockedLowerCharacteristics": [],
    }

    # Check if there is an input file specified
    if args.inputfile:
        with open(args.inputfile[0], "r") as input_file:
            doc = yaml.safe_load(input_file)
            params.update(doc)
            if "fixedVariables" in doc:
                fixed_vars = {}
                for variable in doc["fixedVariables"]:
                    fixed_vars = dict(list(fixed_vars.items()) + list(variable.items()))
                params["fixedVariables"] = fixed_vars

            if "boomerangVariables" in doc:
                boom_vars = {}
                for variable in doc["boomerangVariables"]:
                    boom_vars = dict(list(boom_vars.items()) + list(variable.items()))
                params["boomerangVariables"] = boom_vars

    # Override parameters if they are set on commandline
    if args.cipher:
        params["cipher"] = args.cipher[0]

    if args.rounds:
        params["rounds"] = args.rounds[0]

    if args.uppertrail:
        params["uppertrail"] = args.uppertrail[0]

    if args.uweight:
        params["uweight"] = args.uweight[0]

    if args.lowertrail:
        params["lowertrail"] = args.lowertrail[0]

    if args.lweight:
        params["lweight"] = args.lweight[0]

    if args.wordsize:
        params["wordsize"] = args.wordsize[0]

    if args.blocksize:
        params["blocksize"] = args.blocksize[0]

    if args.sweight:
        params["sweight"] = args.sweight[0]

    if args.endweight:
        params["endweight"] = args.endweight[0]

    if args.mode:
        params["mode"] = args.mode[0]

    if args.timelimit:
        params["timelimit"] = args.timelimit[0]

    if args.iterative:
        params["iterative"] = args.iterative

    if args.boolector:
        params["boolector"] = args.boolector

    if args.nummessages:
        params["nummessages"] = args.nummessages[0]

    if args.dot:
        params["dot"] = args.dot[0]

    if args.latex:
        params["latex"] = args.latex[0]

    return params


def main():
    """
    Parse the arguments and start the request functionality with the provided
    parameters.
    """
    parser = ArgumentParser(
        description="This tool finds the best differential"
        "trail in a cryptopgrahic primitive"
        "using STP and CryptoMiniSat.",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument("--cipher", nargs=1, help="Options: simon, speck, ...")
    parser.add_argument(
        "--sweight", nargs=1, type=int, help="Starting weight for the trail search."
    )
    parser.add_argument(
        "--endweight", nargs=1, type=int, help="Stop search after reaching endweight."
    )
    parser.add_argument(
        "--rounds", nargs=1, type=int, help="The number of rounds for the cipher"
    )
    parser.add_argument(
        "--uppertrail",
        nargs=1,
        type=int,
        help="The number of rounds for the upper trail (boomerang)",
    )
    parser.add_argument(
        "--lowertrail",
        nargs=1,
        type=int,
        help="The number of rounds for the lower trail (boomerang)",
    )
    parser.add_argument(
        "--uweight",
        nargs=1,
        type=int,
        help="Starting weight for upper trail search (boomerang)",
    )
    parser.add_argument(
        "--lweight",
        nargs=1,
        type=int,
        help="Starting weight for lower trail search (boomerang)",
    )
    parser.add_argument(
        "--wordsize", nargs=1, type=int, help="Wordsize used for the cipher."
    )
    parser.add_argument(
        "--blocksize", nargs=1, type=int, help="Blocksize used for the cipher."
    )
    parser.add_argument(
        "--nummessages", nargs=1, type=int, help="Number of message blocks."
    )
    parser.add_argument(
        "--mode",
        nargs=1,
        type=int,
        choices=[0, 1, 2, 3, 4, 5],
        help="0 = search characteristic for fixed round\n"
        "1 = search characteristic for all rounds starting at"
        "the round specified\n"
        "2 = search all characteristic for a specific weight\n"
        "3 = used for key recovery\n"
        "4 = determine the probability of the differential\n"
        "5 = boomerang differential search (please specify --uppertrail and --lowertrail)\n",
    )
    parser.add_argument(
        "--timelimit",
        nargs=1,
        type=int,
        help="Set a timelimit for the search in seconds.",
    )
    parser.add_argument(
        "--iterative",
        action="store_true",
        help="Only search for iterative characteristics",
    )
    parser.add_argument(
        "--boolector", action="store_true", help="Use boolector to find solutions"
    )
    parser.add_argument(
        "--inputfile", nargs=1, help="Use an yaml input file to" "read the parameters."
    )
    parser.add_argument("--dot", nargs=1, help="Print the trail in .dot format.")
    parser.add_argument("--latex", nargs=1, help="Print the trail in .tex format.")

    # Parse command line arguments and construct parameter list.
    args = parser.parse_args()
    params = loadparameters(args)

    # Check if enviroment is setup correctly.
    checkenviroment()

    # Start the solver
    startsearch(params)


if __name__ == "__main__":
    main()
