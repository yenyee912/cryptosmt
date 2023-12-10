import itertools


def fractional_to_fixed_point(frac_num, frac_bits=8):
    # int_part = 0  # Single bit for integer part (0 for 0.x and 1 for 1.x)
    frac_part = frac_num
    frac_binary = ''

    for _ in range(frac_bits):
        frac_part *= 2
        bit = int(frac_part)
        frac_binary += str(bit)
        frac_part -= bit

    fixed_point_binary = [int(bit) for bit in frac_binary]

    # rounding
    if (fixed_point_binary[0] == 2):
        fixed_point_binary[0] = 0

    return fixed_point_binary


def addPartialDDT(variables):
    """
  - hardcode the cham_abct_1.txt into CV4 language 
  - remove the if else
  - use for loop carefully, as the pDDT is irregular
  - can experiment with some specific values first
  - cham_abct_1.txt only include 16 bit for -->beta
    """

    trails = []
    # pDDT = [[
    #     0 for _ in range(0x10)]
    #     for _ in range(0x100)]

    infile = open("./input_sparx/cham_exp.txt", "r")

    # first_line = infile.readline()
    # # print("ok", first_line)
    # x = first_line.split(",")

    alpha_diff = 0
    alpha_prime_diff = 0

    beta_diff = 0
    beta_prime_diff = 0

    for line in infile:
      if len(line) > 1:  # empty line still serve 1 length
        x = line.split(",")

        #get fixed
        alpha_diff = (int(x[0], base=16))
        alpha_prime_diff = (int(x[1], base=16))

        
        beta_diff = (int(x[2], base=16))
        beta_prime_diff = (int(x[3], base=16))
        prob = x[4].strip()  # trim input

        tmp = []
        for i in range(16):
          tmp.append((alpha_diff >> i) & 1)
        # tmp.append("...")

        for i in range(16):
          tmp.append((alpha_prime_diff >> i) & 1)
        # tmp.append("...")

        for i in range(16):
          tmp.append((beta_diff >> i) & 1)
        # tmp.append("...")

        for i in range(16):
          tmp.append((beta_prime_diff >> i) & 1)
        # tmp.append("...")

        tmp += fractional_to_fixed_point(float(prob))

        #append inside if loop
        trails.append(tmp)

        # print(tmp, "\n")

    infile.close()

    # Build CNF from invalid trails
    cnf = ""

    reps = len(trails[0])  # 72, len =64+8 --> 4 var + 1 prob
    #can we pregenerate first? prepare all the combiantions of 0 and 1
    # might take longer time

    for prod in itertools.product([0, 1], repeat=len(trails[0])):
        #generate all the probs between 0 and 1, so 64bit is super duper big
      # print(prod)
        # prod= use 0 and 1, to generate an array with len= repeat, in 2^(72) times

        # Trail is not valid---> what this means? can we only generate invalid CNF?
      # print("loop 1: ", rep, " ", prod) #infinite loop 1
      if list(prod) not in trails:
        expr = ["~" if x == 1 else "" for x in list(prod)]
        clause = ""
        # accomodate to 72, as the len of entire a,a',b,b',w=72bits
        for literal in range(12):
          #add4bitsSbox= 12 becuz their bit size is in_diff(4)+outtdiff(4)+w(4)=12
          clause += "{0}{1} | ".format(expr[literal], variables[literal])

          # if (literal==15):
          #   print("loop 2", prod, clause)

        # print(clause)

        # clause=str, slice the first 3 element only
        cnf += "({}) &".format(clause[:-2])
        #str= "apple", (str[:-2])= app

    # print("ASSERT({} = 0bin1);\n".format(cnf[:-2]))
    return "ASSERT({} = 0bin1);\n".format(cnf[:-2])
