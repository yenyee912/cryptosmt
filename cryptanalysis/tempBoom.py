# if parameters["abctMode"] == 1:
#     if parameters["leftFilePath"] != "" and parameters["rightFilePath"] != "":
#         leftResult = checkAbct.parse_abct_prob(parameters["leftFilePath"])
#         rightResult = checkAbct.parse_abct_prob(parameters["rightFilePath"])

#         print(
#             "{} valid switches found for the left halves:".format(len(leftResult))
#         )
#         print(leftResult)
#         print(
#             "{} valid switches found for the right halves:".format(len(rightResult))
#         )
#         print(rightResult)
#     else:
#         print("Please provide corresponding path to file(s) to parse.")

# elif parameters["abctMode"] == 2:
#     print(
#         "Computing switch for left halves- {}, {}\n---".format(
#             hex(left_beta), hex(left_beta_prime)
#         )
#     )
#     leftResult = checkAbct.compute_abct_switch(
#         left_beta, left_beta_prime, start_time
#     )
#     print(
#         "Computing switch for right halves- {}, {}\n---".format(
#             hex(left_beta), hex(left_beta_prime)
#         )
#     )
#     rightResult = checkAbct.compute_abct_switch(
#         right_beta, right_beta_prime, start_time
#     )
#     print("{} valid switches found for the left halves:".format(len(leftResult)))
#     print(leftResult, "\n")
#     print("{} valid switches found for the right halves:".format(len(rightResult)))
#     print(rightResult, "\n")

"""
abctMode = 1  # search E0 >> top 20 best switch >> 20 E1 >> pick best E1
abctMode = 2  # search E0 >> top 20 best switch (with files supplied) >> 20 E1 >> pick best E1
abctMode = 3  # fix E0 and E1 diff >> search E0 >> search E1 >> look for ABCT to valid switch
"""


# bestWeightTrail = min(boomerangProbList, key=lambda x: x[3])
# # find the best E1
# candidateTrailList = [
#     num for num in boomerangProbList if num[3] == bestWeightTrail[3]
# ]

# print("\n----")
# print("Boomerang search completed.")
# print("The weight of E0 trail is ", parameters["uweight"])
# inputDiff = {
#     key: parameters["upperVariables"][key]
#     for key in list(parameters["upperVariables"].keys())[:4]
# }
# outputDiff = {
#     key: parameters["upperVariables"][key]
#     for key in list(parameters["upperVariables"].keys())[:-4]
# }

# print(
#     "Input: {} \nOutput: {} \nWeight of E0 Trail: {}".format(
#         inputDiff,
#         outputDiff,
#         parameters["uweight"],
#     )
# )
# print("The weight of best E1 trail is ", bestWeightTrail[3])
# print("The trail(s) with same weight: ")
# for trail in candidateTrailList:
#     print(
#         "Input: {} \nOutput: {} \nWeight of E1 Trail: {}, Total Weight: {}".format(
#             trail[0], trail[1], trail[2], trail[3]
#         )
#     )

# print("Final boomerang probability = ", math.log(bestWeightTrail[3], 2))
