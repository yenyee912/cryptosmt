"""
Created on Dec 10, 2014

@author: ralph
"""

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class CHAMCipher(AbstractCipher):
    """
    Represents the differential behaviour of CHAM and can be used
    to find differential characteristics for the given parameters.
    """

    name = "chamBoom"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ["X0", "X1", "X2", "X3", "w"]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for CHAM with
        the given parameters.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, "w") as stp_file:
            stp_file.write(
                "% Input File for STP\n% CHAM w={} "
                "rounds={}\n\n\n".format(wordsize, rounds)
            )

            # Setup variable
            # w = weight
            x0 = ["X0{}".format(i) for i in range(rounds + 1)]
            x1 = ["X1{}".format(i) for i in range(rounds + 1)]
            x2 = ["X2{}".format(i) for i in range(rounds + 1)]
            x3 = ["X3{}".format(i) for i in range(rounds + 1)]
            x0x1 = ["X0X1{}".format(i) for i in range(rounds + 1)]
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x0, wordsize)
            stpcommands.setupVariables(stp_file, x1, wordsize)
            stpcommands.setupVariables(stp_file, x2, wordsize)
            stpcommands.setupVariables(stp_file, x3, wordsize)
            stpcommands.setupVariables(stp_file, x0x1, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            # Ignore MSB
            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize, 1)
            rot_x0 = 0
            rot_x1 = 0
            for i in range(rounds):
                if ((i + 1) % 2) == 0:  # even rounds
                    rot_x1 = 8
                    rot_x0 = 1
                else:  # odd rounds
                    rot_x1 = 1
                    rot_x0 = 8

                self.setupCHAMRound(
                    stp_file,
                    x0[i],
                    x1[i],
                    x2[i],
                    x3[i],
                    x0[i + 1],
                    x1[i + 1],
                    x2[i + 1],
                    x3[i + 1],
                    x0x1[i],
                    rot_x0,
                    rot_x1,
                    w[i],
                    wordsize,
                )

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x0 + x1 + x2 + x3, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x0[0], x0[rounds])
                stpcommands.assertVariableValue(stp_file, x1[0], x1[rounds])
                stpcommands.assertVariableValue(stp_file, x2[0], x2[rounds])
                stpcommands.assertVariableValue(stp_file, x3[0], x3[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupCHAMRound(
        self,
        stp_file,
        x0_in,
        x1_in,
        x2_in,
        x3_in,
        x0_out,
        x1_out,
        x2_out,
        x3_out,
        x0x1,
        rot_x0,
        rot_x1,
        w,
        wordsize,
    ):
        """
        Model for differential behaviour of one round CHAM
        """
        command = ""

        # even rounds:
        # X_{i+1}[3] = (X_{i}[0] + (X_{i}[1] << 1)) << 8
        # odd rounds:
        # X_{i+1}[3] = (X_{i}[0] + (X_{i}[1] << 8)) << 1

        command += "ASSERT("
        command += stpcommands.getStringAdd(
            rotl(x1_in, rot_x1, wordsize), x0_in, x0x1, wordsize
        )
        command += ");\n"

        command += "ASSERT({0} = {1});\n".format(x3_out, rotl(x0x1, rot_x0, wordsize))

        # X_{i+1}[2] = X_{i+1}[3]
        # X_{i+1}[1] = X_{i+1}[2]
        # X_{i+1}[0] = X_{i+1}[1]
        command += "ASSERT({0} = {1});\n".format(x2_out, x3_in)
        command += "ASSERT({0} = {1});\n".format(x1_out, x2_in)
        command += "ASSERT({0} = {1});\n".format(x0_out, x1_in)

        # For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(x0_in, rotl(x1_in, rot_x1, wordsize), x0x1)
        command += ");\n"

        stp_file.write(command)
        return

    def setupSwitchConstraints(
        self, stp_file, upperEndRound, switchRound, lowerStartRound
    ):
        """
        - this function is designed for coded switch constraints for ABCT
        - the clauses are served for single switch pattern only
        - 2,2,x,x
        """
        if (lowerStartRound) % self.rounds_per_step == 0:
            """
                when switch round=2,
                - need to make sure X0A2 and X1A2(Y as well), follow the A box rule to preserve the Evenness/Oddness
                - make sure the X03 and X13 shared same eveness/oddness (Y as well)-just to double confirm

                """

            stp_file.write(
                f"ASSERT(NOT(BVXOR((X0A{switchRound}&0b0000000000000011), (X1A{switchRound}&0b0000000000000100)) = 0b0000000000000010));\n"
            )
            stp_file.write(
                f"ASSERT(NOT(BVXOR((Y0A{switchRound}&0b0000000000000011), (Y1A{switchRound}&0b0000000000000100)) = 0b0000000000000010));\n"
            )

        else:
            stp_file.write(
                f"ASSERT(NOT(BVXOR((X0{lowerStartRound}&0b0000000000000011), (X1{lowerStartRound}&0b0000000000000100)) = 0b0000000000000010));\n"
            )
            stp_file.write(
                f"ASSERT(NOT(BVXOR((Y0{lowerStartRound}&0b0000000000000011), (Y1{lowerStartRound}&0b0000000000000100)) = 0b0000000000000010));\n"
            )

        stp_file.write(
            # f"ASSERT((X0{upperEndRound} & 0b0000011110000000) = 0b0000010000000000);\n"
            f"ASSERT((X0{upperEndRound} & 0b0000011110000000) = 0b0000000100000000);\n"
        )
        stp_file.write(
            f"ASSERT((X1{upperEndRound} & 0b0000000000001111) = 0b0000000000000010);\n"
        )
        stp_file.write(
            f"ASSERT((Y0{upperEndRound} & 0b0000011110000000) = 0b0000000100000000);\n"
        )
        stp_file.write(
            f"ASSERT((Y1{upperEndRound} & 0b0000000000001111) = 0b0000000000000010);\n"
        )
        stp_file.write(
            f"ASSERT(NOT(X0{upperEndRound}|X1{upperEndRound}|Y0{upperEndRound}|Y1{upperEndRound}) = 0b0000000000000000);\n"
        )
        stp_file.write(
            f"ASSERT(NOT(X0{lowerStartRound}|X1{lowerStartRound}|Y0{lowerStartRound}|Y1{lowerStartRound}) = 0b0000000000000000);\n"
        )
