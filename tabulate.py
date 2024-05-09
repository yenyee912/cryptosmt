import pathlib
import time
import random

libname = pathlib.Path().absolute()


def sort_abct_result(inputList):
    sortedList = sorted(inputList, key=lambda x: x[2], reverse=True)

    # Filter out tuples where the 3rd item is 0
    finalList = [
        tup for tup in sortedList if tup[2] != 0 and (tup[0] < 16 and tup[1] < 16)
    ]

    # if limit > len(finalList):
    #     return finalList[: len(finalList)]
    # else:
    return finalList


def parse_abct_prob():
    # List to store tuples
    results = []

    filePath = libname / "abct_cpp/1.txt"

    # Open the file and read line by line
    with open(filePath, "r") as file:
        file.readline()
        for line in file:
            # Split the line into values
            values = line.strip().split(",")

            # Extract the 3rd, 4th, and 5th values
            entry = (int(values[2], 16), int(values[3], 16), float(values[4]))

            # Append the tuple to the list
            results.append(entry)

    finalResult = sort_abct_result(results)

    return finalResult


def tabulate(data):
    # Find the maximum values for rows and columns
    max_row = 0xF
    max_col = 0xF

    # Create a 2D list initialized with zeros
    table = [[0 for _ in range(max_col + 1)] for _ in range(max_row + 1)]

    # Populate the table with values from the tuples
    for item in data:
        table[item[0]][item[1]] = item[2]

    # Print the tabulated data
    # for row_index in range(len(table)):
    #     for col_index in range(len(table[row_index])):
    #         print(table[row_index][col_index], ", ")
    # print(data)

    max_width = max(
        len(str(table[row][col]))
        for row in range(len(table))
        for col in range(len(table[row]))
    )
    print(max_width)

    header_row = ["{:>{}}".format(bin(i)[2:], max_width + 2) for i in range(16)]
    print(" " * max_width, *header_row)

    for row_index in range(len(table)):
        formatted_row = [
            f"{table[row_index][col_index]:>{max_width}}"
            for col_index in range(len(table[row_index]))
        ]
        print(formatted_row)


def rotl(num, pose):
    x = (num << pose) | (num >> (16 - pose))
    x &= 0xFFFF
    return x


def verify(left_delta, left_delta_prime, right_delta, right_delta_prime):
    temp = rotl((right_delta ^ right_delta_prime), 8)
    tmpVar = left_delta
    left_delta = right_delta
    right_delta = tmpVar

    tmpVar = left_delta_prime
    left_delta_prime = right_delta_prime
    right_delta_prime = tmpVar

    print(left_delta, hex(left_delta_prime), hex(right_delta), right_delta_prime)
    print(hex(temp))

    right_delta_prime = right_delta_prime ^ temp ^ left_delta_prime
    right_delta = right_delta ^ temp ^ left_delta

    print(left_delta, hex(left_delta_prime), right_delta, right_delta_prime)

    left_delta_prime = rotl((left_delta ^ left_delta_prime), 14)
    right_delta_prime = rotl((right_delta ^ right_delta_prime), 14)
    print(left_delta, hex(left_delta_prime), right_delta, right_delta_prime)


def test_sparx_round(skipround, switchround):
    for i in range(10):
        if skipround == i + 1:
            print(f"XXXXXXXX skip {i} for all ops?? XXXXX")
            continue

        if ((i + 1) % 3) == 0:
            print(f"do round {i} left A")
            print(f"do round {i} right A")
            print(f"do round {i} sparx")
        else:
            print(f"do round {i} left A")
            if (skipround + 1) == i + 1:
                print(f"XXXXXXXX skip round {i} right A XXXXX")
                continue
            else:
                print(f"do round {i} right A")
    # print("\n==========sparxBoom========\n")
    # for i in range(10):
    #     if (switchround) == i + 1:
    #         print(f"XXXXXXXX all ops XXXXX")
    #         continue
    #     if ((i + 1) % 3) == 0:
    #         if switchround == (i + 1) % 3 == 0:
    #             continue
    #         else:
    #             print(f"do round {i} left A")
    #             print(f"do round {i} right A")
    #             print(f"do round {i} sparx")

    #     else:
    #         if (switchround) == i:
    #             print(f"XXXXXXXX skip round {i} left A XXXXX")
    #             print(f"XXXXXXXX skip round {i} right A XXXXX")
    #             continue
    #         else:
    #             print(f"do round {i} left A")
    #             print(f"do round {i} right A")


def searchCharac():
    return random.choice([True, False])


def demo_mode2_sparx():
    try:
        charac = searchCharac()

        if not charac:  # If charac is False, stop the loop
            print("no charac")
            return

        while True:
            valid = searchCharac()
            if valid:
                print("ok")
                return
            else:
                print("block")
    except Exception as e:
        print("Error occurred here...", e)


def main():
    demo_mode2_sparx()


if __name__ == "__main__":
    main()
