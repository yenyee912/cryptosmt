'''
Created on Aug 17, 2022
@author: yenyee912
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class MibsCipher(AbstractCipher):
    """
    Represents the differential behaviour of MIBS and can be used
    to find differential characteristics for the given parameters.
    """

    name = "mibs"

    def getFormatString(self):
        """
        Returns the print format. 
        X= input, S= sBox, F=pBox, w=weight
        """
        return ['X', 'S', 'F', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for MIBS with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% MIBS-s w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            # x = input (32), 
            # s = S-Box output (16), 
            # f = output of F function after permutation (16)
            # p = swap 32-bit blocks (32)
            x = ["X{}".format(i) for i in range(rounds + 1)]
            f = ["F{}".format(i) for i in range(rounds)]
            s = ["S{}".format(i) for i in range(rounds)]
            p = ["p{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, f, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupMibsRound(stp_file, x[i], s[i], p[i], f[i], x[i+1],
                                     w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupMibsRound(self, stp_file, x_in, s, p, f, x_out, w, wordsize):
        """
        Model for differential behaviour of one round MIBS
        """
        command = ""

        #non-linear substitution layer
        """
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
        4 15 3 8 13 10 12 0 11 5 7 14 2 6 1 9
        """
        mibs_sbox = [0x4, 0xF, 0x3, 0x8, 0xD, 0xA, 0xC,
                     0, 0xB, 0x5, 0x7, 0xE, 0x2, 0x6, 0x1, 0x9]
        for i in range(8, 16): #lhs only
            variables = ["{0}[{1}:{1}]".format(x_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(s, 4*i + 3),
                         "{0}[{1}:{1}]".format(s, 4*i + 2),
                         "{0}[{1}:{1}]".format(s, 4*i + 1),
                         "{0}[{1}:{1}]".format(s, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(mibs_sbox, variables)
            # print (i, variables)

        # exit(0)


        #linear mixing layer
        """
        y1′ = y2 + y3 + y4 + y5 + y6 + y7 
        y2′ = y1 + y3 + y4 + y6 + y7 + y8
        y3′ = y1 + y2 + y4 + y5 + y7 + y8 
        y4′ = y1 + y2 + y3 + y5 + y6 + y8 
        y5′ = y1 +y2 +y4 +y5 +y6 
        y6′ = y1 +y2 +y3 +y6 +y7 
        y7′ = y2 +y3 +y4 +y7 +y8 
        y8′ = y1 +y3 +y4 +y5 +y8 
        
        new- 2 8 1 3 6 7 4 5 
        old- 1 2 3 4 5 6 7 8

        1 go to 2, 2 go to 8, 3 go to 1
        4 go to 3, 5 go to 6, 6 go to 7
        7 go to 4, 8 go to 5
          
        
        L-63:60 59:56 55:52 51:48 47:44 43:40 39:36 35:32 
        R-31:28 27:24 23:20 19:16 15:12 11:8  7:4   3:0
          8     7     6     5     4     3     2     1
        """

        command += "ASSERT({0}[35:32] = BVXOR({1}[35:32], BVXOR({1}[39:36], BVXOR({1}[47:44], BVXOR({1}[51:48], BVXOR({1}[59:56], {1}[63:60]))))));\n".format(f, s)
        command += "ASSERT({0}[39:36] = BVXOR({1}[39:36], BVXOR({1}[43:40], BVXOR({1}[47:44], BVXOR({1}[51:48], BVXOR({1}[55:52], {1}[59:56]))))));\n".format(f, s)
        command += "ASSERT({0}[43:40] = BVXOR({1}[35:32], BVXOR({1}[39:36], BVXOR({1}[43:40], BVXOR({1}[51:48], BVXOR({1}[55:52], {1}[63:60]))))));\n".format(f, s)
        command += "ASSERT({0}[47:44] = BVXOR({1}[39:36], BVXOR({1}[43:40], BVXOR({1}[47:44], BVXOR({1}[59:56], {1}[63:60]))))); \n".format(f, s)
        command += "ASSERT({0}[51:48] = BVXOR({1}[35:32], BVXOR({1}[43:40], BVXOR({1}[47:44], BVXOR({1}[51:48], {1}[63:60])))));\n".format(f, s)
        command += "ASSERT({0}[55:52] = BVXOR({1}[35:32], BVXOR({1}[39:36], BVXOR({1}[47:44], BVXOR({1}[51:48], {1}[55:52])))));\n".format(f, s)
        command += "ASSERT({0}[59:56] = BVXOR({1}[35:32], BVXOR({1}[39:36], BVXOR({1}[43:40], BVXOR({1}[55:52], {1}[59:56])))));\n".format(f, s)
        command += "ASSERT({0}[63:60] = BVXOR({1}[35:32], BVXOR({1}[43:40], BVXOR({1}[47:44], BVXOR({1}[55:52], BVXOR({1}[59:56], {1}[63:60]))))));\n".format(f, s)

        #left= addition- left xor right
        # reverse params(f, x_in) of slim, slim is rhs[0:3] go to fBox
        command += "ASSERT({0}[3:0] = BVXOR({1}[35:32],{2}[3:0]));\n".format(p, f, x_in)
        command += "ASSERT({0}[7:4] = BVXOR({1}[39:36],{2}[7:4]));\n".format(p, f, x_in)
        command += "ASSERT({0}[11:8] = BVXOR({1}[43:40],{2}[11:8]));\n".format(p, f, x_in)
        command += "ASSERT({0}[15:12] = BVXOR({1}[47:44],{2}[15:12]));\n".format(p, f, x_in)
        command += "ASSERT({0}[19:16] = BVXOR({1}[51:48],{2}[19:16]));\n".format(p, f, x_in)
        command += "ASSERT({0}[23:20] = BVXOR({1}[55:52],{2}[23:20]));\n".format(p, f, x_in)
        command += "ASSERT({0}[27:24] = BVXOR({1}[59:56],{2}[27:24]));\n".format(p, f, x_in)
        command += "ASSERT({0}[31:28] = BVXOR({1}[63:60],{2}[31:28]));\n".format(p, f, x_in)

        # rhs remain unchange
        command += "ASSERT({0}[35:32] = {1}[35:32]);\n".format(p, x_in)
        command += "ASSERT({0}[39:36] = {1}[39:36]);\n".format(p, x_in)
        command += "ASSERT({0}[43:40] = {1}[43:40]);\n".format(p, x_in)
        command += "ASSERT({0}[47:44] = {1}[47:44]);\n".format(p, x_in)
        command += "ASSERT({0}[51:48] = {1}[51:48]);\n".format(p, x_in)
        command += "ASSERT({0}[55:52] = {1}[55:52]);\n".format(p, x_in)
        command += "ASSERT({0}[59:56] = {1}[59:56]);\n".format(p, x_in)
        command += "ASSERT({0}[63:60] = {1}[63:60]);\n".format(p, x_in)

        # non zero input
        command += "ASSERT(0x00000000 = {0}[31:0]);\n".format(s)
        command += "ASSERT(0x00000000 = {0}[31:0]);\n".format(w)
        command += "ASSERT(0x00000000 = {0}[31:0]);\n".format(f)
        
        #Swap left and right
        #left
        command += "ASSERT({0}[3:0]   = {1}[35:32]);\n".format(p, x_out)
        command += "ASSERT({0}[7:4]   = {1}[39:36]);\n".format(p, x_out)
        command += "ASSERT({0}[11:8]  = {1}[43:40]);\n".format(p, x_out)
        command += "ASSERT({0}[15:12] = {1}[47:44]);\n".format(p, x_out)
        command += "ASSERT({0}[19:16] = {1}[51:48]);\n".format(p, x_out)
        command += "ASSERT({0}[23:20] = {1}[55:52]);\n".format(p, x_out)
        command += "ASSERT({0}[27:24] = {1}[59:56]);\n".format(p, x_out)
        command += "ASSERT({0}[31:28] = {1}[63:60]);\n".format(p, x_out)

        command += "ASSERT({0}[35:32] = {1}[3:0]);\n".format(p, x_out)
        command += "ASSERT({0}[39:36] = {1}[7:4]);\n".format(p, x_out)
        command += "ASSERT({0}[43:40] = {1}[11:8]);\n".format(p, x_out)
        command += "ASSERT({0}[47:44] = {1}[15:12]);\n".format(p, x_out)
        command += "ASSERT({0}[51:48] = {1}[19:16]);\n".format(p, x_out)
        command += "ASSERT({0}[55:52] = {1}[23:20]);\n".format(p, x_out)
        command += "ASSERT({0}[59:56] = {1}[27:24]);\n".format(p, x_out)
        command += "ASSERT({0}[63:60] = {1}[31:28]);\n".format(p, x_out)

        stp_file.write(command)
        return
