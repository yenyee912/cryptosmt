import time
from timeit import default_timer as timer

def arx_bct(d_i, d_ip, d_o, d_op):
    start = timer()

    count = 0
    prob = 0.0

    for x in range(WORDSIZE):
        # if (x%1000==0):
          # print("ok")
          for xp in range(WORDSIZE):
            # x3=((x+xp)^n0)-(xp^np)
            # x3 = (((x + xp) % WORDSIZE) ^ d_o) - (xp ^ d_op)
            x3= 0
            x3 = x3 % WORDSIZE  # Modular sub

            # x4=(((x^d0)+(xp^dp))^n0)-(xp^dp^np)
            # x4 = (((x ^ d_i) + (xp ^ d_ip)) % WORDSIZE) ^ d_o - (xp ^ d_ip ^ d_op)
            x4= 0
            x4 = x4 % WORDSIZE  # Modular sub


            diff = x3 ^ x4
            if diff == d_i:
              count += 1
            
          if (x& 0xfff==0):
            print( f"{hex(x)}, {hex(xp)}, {start-timer(): .3f}")

    prob = count / (2 ** 32)

    print(f"{hex(d_i)},{hex(d_ip)},{hex(d_o)},{hex(d_op)}={count}, p= {prob:.5f}")
    print("counter = ", count, "/", (2 ** 32))

    return prob

# Assuming WORDSIZE is defined somewhere before calling the function
WORDSIZE = (2**16)

def main():
  arx_bct(0x355e, 0xbf30, 0x1, 0x2)

if __name__ == '__main__':
  main()
  print(WORDSIZE)