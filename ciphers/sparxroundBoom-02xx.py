"""
Created on Mar 29, 2017

@author: ralph

this is model for switch of 0,2,
"""

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class SPARXRoundCipher(AbstractCipher):
    """
    Represents the differential behaviour of SPARX and can be used
    to find differential characteristics for the given parameters.
    """

    name = "sparxroundBoom"
    rounds_per_step = 3

    def getFormatString(self):
        """
        Returns the print format.
        """
        return [
            "X0",
            "X1",
            "Y0",
            "Y1",
            "X0A",
            "X1A",
            "Y0A",
            "Y1A",
            "X0L",
            "X1L",
            "wl",
            "wr",
        ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SPARX with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, "w") as stp_file:
            header = "% Input File for STP\n% SPARX w={}" "rounds={}\n\n\n".format(
                wordsize, rounds
            )
            stp_file.write(header)

            # Setup variables
            # x0, x1 = left, y0, y1 = right
            x0 = ["X0{}".format(i) for i in range(rounds + 1)]
            x1 = ["X1{}".format(i) for i in range(rounds + 1)]
            x0_after_A = ["X0A{}".format(i) for i in range(rounds + 1)]
            x1_after_A = ["X1A{}".format(i) for i in range(rounds + 1)]
            x0_after_L = ["X0L{}".format(i) for i in range(rounds + 1)]
            x1_after_L = ["X1L{}".format(i) for i in range(rounds + 1)]
            y0 = ["Y0{}".format(i) for i in range(rounds + 1)]
            y1 = ["Y1{}".format(i) for i in range(rounds + 1)]
            y0_after_A = ["Y0A{}".format(i) for i in range(rounds + 1)]
            y1_after_A = ["Y1A{}".format(i) for i in range(rounds + 1)]

            # w = weight
            wleft = ["wl{}".format(i) for i in range(rounds)]
            wright = ["wr{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x0, wordsize)
            stpcommands.setupVariables(stp_file, x1, wordsize)
            stpcommands.setupVariables(stp_file, x0_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x1_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x0_after_L, wordsize)
            stpcommands.setupVariables(stp_file, x1_after_L, wordsize)
            stpcommands.setupVariables(stp_file, y0, wordsize)
            stpcommands.setupVariables(stp_file, y1, wordsize)
            stpcommands.setupVariables(stp_file, y0_after_A, wordsize)
            stpcommands.setupVariables(stp_file, y1_after_A, wordsize)
            stpcommands.setupVariables(stp_file, wleft, wordsize)
            stpcommands.setupVariables(stp_file, wright, wordsize)

            # Ignore MSB
            stpcommands.setupWeightComputation(
                stp_file, weight, wleft + wright, wordsize, 1
            )

            for i in range(rounds):
                # if parameters["skipround"] == (i + 1):
                #     continue

                # the model do linear layer at r3-1, then show result in r3, so we need i+1
                if (i + 1) % self.rounds_per_step == 0:
                    if (
                        parameters["switchround"] == (i + 1) % self.rounds_per_step == 0
                    ):  # if switch at front part
                        continue
                    else:
                        self.setupSPECKEYRound(
                            stp_file,
                            x0[i],
                            x1[i],
                            x0_after_A[i],
                            x1_after_A[i],
                            wleft[i],
                            wordsize,
                        )
                        self.setupSPECKEYRound(
                            stp_file,
                            y0[i],
                            y1[i],
                            y0_after_A[i],
                            y1_after_A[i],
                            wright[i],
                            wordsize,
                        )
                        self.setupSPARXRound(
                            stp_file,
                            x0_after_A[i],
                            x1_after_A[i],
                            y0_after_A[i],
                            y1_after_A[i],
                            x0_after_L[i],
                            x1_after_L[i],
                            x0[i + 1],
                            x1[i + 1],
                            y0[i + 1],
                            y1[i + 1],
                        )

                else:
                    if parameters["switchround"] == i:
                        continue
                    else:
                        # do round function left (SPECKEY)
                        self.setupSPECKEYRound(
                            stp_file,
                            x0[i],
                            x1[i],
                            x0[i + 1],
                            x1[i + 1],
                            wleft[i],
                            wordsize,
                        )
                        # do round function right (SPECKEY)
                        self.setupSPECKEYRound(
                            stp_file,
                            y0[i],
                            y1[i],
                            y0[i + 1],
                            y1[i + 1],
                            wright[i],
                            wordsize,
                        )
                        # stp_file.write("i first\n")

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x0 + x1 + y0 + y1, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x0[0], x0[rounds])
                stpcommands.assertVariableValue(stp_file, x1[0], x1[rounds])
                stpcommands.assertVariableValue(stp_file, y0[0], y0[rounds])
                stpcommands.assertVariableValue(stp_file, y1[0], y1[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            if (parameters["switchround"]>0):
                upperEndRound = parameters["uppertrail"]  # round of E0 outputDiff
                lowerStartRound = parameters["switchround"] + 1
                switchRound = parameters["switchround"]

                self.setupSPARXBoomSwitchConstraints(stp_file, upperEndRound, switchRound, lowerStartRound)

            stpcommands.setupQuery(stp_file)

        return

    def setupSPARXBoomSwitchConstraints(self, stp_file, upperEndRound, switchRound, lowerStartRound):
        if (lowerStartRound) % self.rounds_per_step == 0:
            """
                when switch round=2,
                - need to make sure X0A2 and X1A2(Y as well), follow the A box rule to preserve the Evenness/Oddness
                - make sure the X03 and X13 shared same eveness/oddness (Y as well)-just to double confirm
                - 0,2==> check 3rd bits of c is === to 3rd bits of d
                """
            stp_file.write(
                f"ASSERT((X0A{switchRound} & 0b0000000000000100) =  (X1A{switchRound} & 0b0000000000010000));\n"
            )
            stp_file.write(
                f"ASSERT((Y0A{switchRound} & 0b0000000000000100) =  (Y1A{switchRound} & 0b0000000000010000));\n"
            )

        else:
            stp_file.write(
                f"ASSERT((X0{lowerStartRound} & 0b0000000000000100) =  (X1{lowerStartRound} & 0b0000000000010000));\n"
            )
            stp_file.write(
                f"ASSERT((Y0{lowerStartRound} & 0b0000000000000100) =  (Y1{lowerStartRound} & 0b0000000000010000));\n"
            )

        stp_file.write(
                f"ASSERT((X0{upperEndRound} & 0b0000011110000000) = 0b0000000000000000);\n"
            )
        stp_file.write(
                f"ASSERT((X1{upperEndRound} & 0b0000000000001111) = 0b0000000000000010);\n"
            )
        stp_file.write(
                f"ASSERT((Y0{upperEndRound} & 0b0000011110000000) = 0b0000000000000000);\n"
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

    def setupSPARXRound(
        self,
        stp_file,
        x0_in,
        x1_in,
        y0_in,
        y1_in,
        x0_after_L,
        x1_after_L,
        x0_out,
        x1_out,
        y0_out,
        y1_out,
    ):
        """
        Model for differential behaviour of one step SPARX
        """
        command = ""
        command += self.L(x0_in, x1_in, x0_after_L, x1_after_L)

        # Assert(x_out = L(A^a(x_in)) xor A^a(y_in))
        command += "ASSERT(" + x0_out + " = "
        command += "BVXOR(" + x0_after_L + " , " + y0_in + ")"
        command += ");\n"
        command += "ASSERT(" + x1_out + " = "
        command += "BVXOR(" + x1_after_L + " , " + y1_in + ")"
        command += ");\n"

        # Assert(y_out = A^a(x_in))
        command += "ASSERT({} = {});\n".format(y0_out, x0_in)
        command += "ASSERT({} = {});\n".format(y1_out, x1_in)

        stp_file.write(command)
        return

    def setupSPECKEYRound(self, stp_file, x_in, y_in, x_out, y_out, w, wordsize):
        """
        Model for the ARX box (round) function of SPARX which is the
        same as SPECKEY.
        """
        command = ""

        # Assert((x_in >>> 7) + y_in = x_out) use x_out to fix
        command += "ASSERT("
        command += stpcommands.getStringAdd(
            rotr(x_in, 7, wordsize), y_in, x_out, wordsize
        )
        command += ");\n"

        # Assert(x_out xor (y_in <<< 2) = y_out)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += rotl(y_in, 2, wordsize)
        command += "));\n"

        # For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(rotr(x_in, 7, wordsize), y_in, x_out)
        command += ");\n"

        stp_file.write(command)
        return

    def L(self, x_in, y_in, x_out, y_out):
        """
        Model for the L function in SPARX. L is the Feistel function and
        is borrowed from NOEKEON.
        """
        command = ""

        # (x_in xor y_in)
        xor_x_y = "BVXOR(" + x_in + " , " + y_in + ")"
        # (x_in xor y_in) <<< 8)
        rot_x_y = rotl(xor_x_y, 8, 16)

        # Assert(x_out = x_in xor ((x_in xor y_in) <<< 8))
        command += "ASSERT(" + x_out + " = "
        command += "BVXOR(" + x_in + " , " + rot_x_y + "));\n"

        # Assert(y_out = y_in xor ((x_in xor y_in) <<< 8))
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + y_in + " , " + rot_x_y + "));\n"

        return command
