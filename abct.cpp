#include <iostream>
#include <stdio.h>
#include <cmath>

#include "abct.hpp"

using namespace std;

typedef uint32_t word_t; // 16 bit
#define size 65536

long double arx_bct(word_t d_i, word_t d_ip, word_t d_o, word_t d_op){

  long int counter = 0;
  long double prob = 0;

  word_t diff;
  for (word_t x = 0; x < size; x++){
    for (word_t xp = 0; xp < size; xp++){
      // x3=((x+xp)^n0)-(xp^np)
      word_t x3 = ((((x + xp) % size) ^ d_o) - (xp ^ d_op));
      x3 = x3 % size; // Modular sub
      
      // x4=(((x^d0)+(xp^dp))^n0)-(xp^dp^np)
      word_t x4 = ((((x ^ d_i) + (xp ^ d_ip)) % size) ^ d_o) - (xp ^ d_ip ^ d_op);
      x4 = x4 % size; // Modular sub

      diff = x3 ^ x4;
      if (diff == d_i)
      {
        counter++;
      }
    }
  }

  prob = (counter / pow(2, 32));
  cout<< "prob= " << prob << endl;
  cout << "counter= " << counter << endl;

  return prob;
}