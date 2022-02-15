/*

Authors: Aseem Rastogi, Nishant Kumar, Mayank Rathee.

Copyright:
Copyright (c) 2020 Microsoft Research
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#ifndef __EZPC_H_
#define __EZPC_H_
#include "../../../src/abycore/circuit/booleancircuits.h"
#include "../../../src/abycore/sharing/sharing.h"
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <cmath>
using namespace std;

/*
 * somehow we need this redirection for adding Cons gates
 * directly calling PutConsGate gives an error
 */
share* put_cons32_gate(Circuit* c, uint32_t val) {
  uint32_t x = val;
  return c->PutCONSGate(x, (uint32_t)32);
}

share* put_cons64_gate(Circuit* c, uint64_t val) {
  uint64_t x = val;
  return c->PutCONSGate(x, (uint32_t)64);
}

share* put_cons1_gate(Circuit* c, uint64_t val) {
  uint64_t x = val;
  return c->PutCONSGate(x, (uint32_t)1);
}

share* left_shift(Circuit* c, share* val, uint32_t shift_factor) {
  uint32_t share_wire_count = val->get_bitlength();
  share* fresh_zero_share = put_cons32_gate(c, 0);
  std::vector<uint32_t> val_wires = val->get_wires();
  if(share_wire_count == 1){
    cout<<"Error. Share not padded. A share cannot exist with just 1 wire.\n";
  }
  // Note here the assumption is that if we receive the val share as a share of size 32, we output the share as a share of size 32 only and drop the MSBs which overflow the 32 bit constraint.
  for(int i=0; i+shift_factor<share_wire_count; i++){
    fresh_zero_share->set_wire_id(shift_factor+i, val_wires[i]);
  }
  return fresh_zero_share;
}

share* get_zero_share(Circuit* c, int bitlen){
  if (bitlen == 32)
    return put_cons32_gate(c, 0);
  else
    return put_cons64_gate(c, 0);
}

share* logical_right_shift(Circuit* c, share* val, uint32_t shift_factor) {
  int bitlen = val->get_bitlength();
  vector<uint32_t> val_wires = val->get_wires();

  vector<uint32_t> zero_share_wires = (get_zero_share(c, bitlen))->get_wires();
  vector<uint32_t> new_val_wires(bitlen, 0);
  for(int i=0; i<bitlen; i++){
    if (i >= (bitlen - shift_factor)){
      new_val_wires[i] = zero_share_wires[i];
    }
    else{
      new_val_wires[i] = val_wires[i+shift_factor];
    }
  }
  share* x = create_new_share(new_val_wires, c);
  return x;
}

share* arithmetic_right_shift(Circuit* c, share* val, uint32_t shift_factor) {
  int bitlen = val->get_bitlength();
  share* neg_val = c->PutSUBGate(get_zero_share(c, bitlen), val);
  share* is_pos = c->PutGTGate(neg_val, val);
  val = c->PutMUXGate(val, neg_val, is_pos);
  share* x = logical_right_shift(c, val, shift_factor);
  return c->PutMUXGate(x, c->PutSUBGate(get_zero_share(c, bitlen), x), is_pos);
}


share* signedgtbl(Circuit* c, share* x, share* y){
  share* ux = x;
  share* uy = y;
  int32_t __tac_var1 = ( (int32_t)1 <<  (int32_t)31);
  share* __tac_var2 = put_cons32_gate(c, __tac_var1);
  share* signBitX = c->PutANDGate(x, __tac_var2);
  int32_t __tac_var3 = __tac_var1;
  share* __tac_var4 = __tac_var2;
  share* signBitY = c->PutANDGate(y, __tac_var2);
  share* __tac_var5 = c->PutXORGate(signBitX, signBitY);
  share* __tac_var6 = put_cons32_gate(c,  (uint32_t)0);
  share* __tac_var7 = c->PutGTGate(__tac_var5, __tac_var6);
  share* __tac_var8 = __tac_var6;
  share* __tac_var9 = c->PutGTGate(signBitX, __tac_var6);
  share* __tac_var10 = put_cons1_gate(c, 0);
  share* __tac_var11 = put_cons1_gate(c, 1);
  share* __tac_var12 = c->PutMUXGate(__tac_var10, __tac_var11, __tac_var9);
  share* __tac_var13 = c->PutGTGate(ux, uy);
  share* __tac_var14 = c->PutMUXGate(__tac_var12, __tac_var13, __tac_var7);
  return __tac_var14;
}

share* signedarshiftbl(Circuit* c, share* x, uint32_t y){
  share* ux = x;
  int32_t __tac_var15 = ( (int32_t)1 <<  (int32_t)31);
  share* __tac_var16 = put_cons32_gate(c, __tac_var15);
  share* signBitX = c->PutANDGate(x, __tac_var16);
  share* __tac_var17 = put_cons32_gate(c,  (uint32_t)0);
  share* __tac_var18 = c->PutGTGate(signBitX, __tac_var17);
  share* __tac_var19 = __tac_var17;
  share* __tac_var20 = __tac_var17;
  share* __tac_var21 = c->PutSUBGate(__tac_var17, ux);
  share* __tac_var22 = arithmetic_right_shift(c, __tac_var21, y);
  share* __tac_var23 = c->PutSUBGate(__tac_var17, __tac_var22);
  share* __tac_var24 = arithmetic_right_shift(c, ux, y);
  share* __tac_var25 = c->PutMUXGate(__tac_var23, __tac_var24, __tac_var18);
  return __tac_var25;
}

share* unsignedltbl(Circuit* c, share* x, share* y){
  share* __tac_var26 = c->PutGTGate(y, x);
  return __tac_var26;
}

share* signedltbl(Circuit* c, share* x, share* y){
  share* __tac_var27 = signedgtbl(c, y, x);
  return __tac_var27;
}

share* unsignedleqbl(Circuit* c, share* x, share* y){
  share* __tac_var28 = c->PutGTGate(x, y);
  share* __tac_var29 = ((BooleanCircuit *) c)->PutINVGate(__tac_var28);
  return __tac_var29;
}

share* signedleqbl(Circuit* c, share* x, share* y){
  share* __tac_var30 = signedgtbl(c, x, y);
  share* __tac_var31 = ((BooleanCircuit *) c)->PutINVGate(__tac_var30);
  return __tac_var31;
}

share* unsignedgeqbl(Circuit* c, share* x, share* y){
  share* __tac_var32 = c->PutGTGate(y, x);
  share* __tac_var33 = ((BooleanCircuit *) c)->PutINVGate(__tac_var32);
  return __tac_var33;
}

share* signedgeqbl(Circuit* c, share* x, share* y){
  share* __tac_var34 = signedgtbl(c, y, x);
  share* __tac_var35 = ((BooleanCircuit *) c)->PutINVGate(__tac_var34);
  return __tac_var35;
}

share* unsignedequalsbl(Circuit* c, share* x, share* y){
  share* __tac_var36 = unsignedltbl(c, x, y);
  share* __tac_var37 = ((BooleanCircuit *) c)->PutINVGate(__tac_var36);
  share* __tac_var38 = unsignedltbl(c, y, x);
  share* __tac_var39 = ((BooleanCircuit *) c)->PutINVGate(__tac_var38);
  share* __tac_var40 = c->PutANDGate(__tac_var37, __tac_var39);
  return __tac_var40;
}

share* signedequalsbl(Circuit* c, share* x, share* y){
  share* __tac_var41 = signedltbl(c, x, y);
  share* __tac_var42 = ((BooleanCircuit *) c)->PutINVGate(__tac_var41);
  share* __tac_var43 = signedltbl(c, y, x);
  share* __tac_var44 = ((BooleanCircuit *) c)->PutINVGate(__tac_var43);
  share* __tac_var45 = c->PutANDGate(__tac_var42, __tac_var44);
  return __tac_var45;
}

share* longDivision(Circuit* c, share* x, share* y, uint32_t getQuotient){
  share* q = put_cons32_gate(c,  (uint32_t)0);
  share* divisor = q;
  share* cond = put_cons1_gate(c, 0);
  for (uint32_t iter =  (int32_t)0; iter <  (int32_t)32; iter++){
    uint32_t i = ( (int32_t)31 - iter);
    divisor = left_shift(c, divisor,  (uint32_t)1);
    uint32_t __tac_var46 = ( (uint32_t)1 << i);
    share* __tac_var47 = put_cons32_gate(c, __tac_var46);
    share* __tac_var48 = c->PutANDGate(x, __tac_var47);
    share* __tac_var49 = logical_right_shift(c, __tac_var48, i);
    divisor = c->PutADDGate(divisor, __tac_var49);
    cond = unsignedgeqbl(c, divisor, y);
    share* __tac_var50 = c->PutSUBGate(divisor, y);
    divisor = c->PutMUXGate(__tac_var50, divisor, cond);
    q = left_shift(c, q,  (uint32_t)1);
    share* __tac_var51 = put_cons32_gate(c,  (uint32_t)1);
    share* __tac_var52 = c->PutADDGate(q, __tac_var51);
    q = c->PutMUXGate(__tac_var52, q, cond);
  }
  share* __tac_var53 = getQuotient ? q : divisor;
  return __tac_var53;
}

share* unsigneddivbl(Circuit* c, share* x, share* y){
  share* __tac_var54 = longDivision(c, x, y, 1);
  return __tac_var54;
}

share* unsigneddival(Circuit* c, share* x, share* y){
  share* bx = c->PutA2YGate(x);
  share* by = c->PutA2YGate(y);
  share* __tac_var55 = unsigneddivbl(c, bx, by);
  return __tac_var55;
}

share* signeddivbl(Circuit* c, share* x, share* y){
  share* __tac_var56 = put_cons32_gate(c,  (int32_t)0);
  share* isXNeg = signedltbl(c, x, __tac_var56);
  share* __tac_var57 = __tac_var56;
  share* isYNeg = signedltbl(c, y, __tac_var56);
  share* __tac_var58 = __tac_var56;
  share* __tac_var59 = c->PutSUBGate(__tac_var56, x);
  share* ux = c->PutMUXGate(__tac_var59, x, isXNeg);
  share* __tac_var60 = __tac_var56;
  share* __tac_var61 = c->PutSUBGate(__tac_var56, y);
  share* uy = c->PutMUXGate(__tac_var61, y, isYNeg);
  share* ures = unsigneddivbl(c, ux, uy);
  share* isResNeg = c->PutXORGate(isXNeg, isYNeg);
  share* __tac_var62 = put_cons32_gate(c,  (uint32_t)0);
  share* __tac_var63 = c->PutSUBGate(__tac_var62, ures);
  share* __tac_var64 = c->PutMUXGate(__tac_var63, ures, isResNeg);
  return __tac_var64;
}

share* signeddival(Circuit* c, share* x, share* y){
  share* bx = c->PutA2YGate(x);
  share* by = c->PutA2YGate(y);
  share* __tac_var65 = signeddivbl(c, bx, by);
  return __tac_var65;
}

share* unsignedmodbl(Circuit* c, share* x, share* y){
  share* __tac_var66 = longDivision(c, x, y, 0);
  return __tac_var66;
}

share* unsignedmodal(Circuit* c, share* x, share* y){
  share* bx = c->PutA2YGate(x);
  share* by = c->PutA2YGate(y);
  share* __tac_var67 = unsignedmodbl(c, bx, by);
  return __tac_var67;
}

share* signedmodbl(Circuit* c, share* x, share* y){
  share* __tac_var68 = put_cons32_gate(c,  (int32_t)0);
  share* isXNeg = signedltbl(c, x, __tac_var68);
  share* __tac_var69 = __tac_var68;
  share* isYNeg = signedltbl(c, y, __tac_var68);
  share* __tac_var70 = __tac_var68;
  share* __tac_var71 = c->PutSUBGate(__tac_var68, x);
  share* ux = c->PutMUXGate(__tac_var71, x, isXNeg);
  share* __tac_var72 = __tac_var68;
  share* __tac_var73 = c->PutSUBGate(__tac_var68, y);
  share* uy = c->PutMUXGate(__tac_var73, y, isYNeg);
  share* urem = unsignedmodbl(c, ux, uy);
  share* __tac_var74 = put_cons32_gate(c,  (uint32_t)0);
  share* __tac_var75 = c->PutSUBGate(__tac_var74, urem);
  share* __tac_var76 = c->PutMUXGate(__tac_var75, urem, isXNeg);
  return __tac_var76;
}

share* signedmodal(Circuit* c, share* x, share* y){
  share* bx = c->PutA2YGate(x);
  share* by = c->PutA2YGate(y);
  share* __tac_var77 = signedmodbl(c, bx, by);
  return __tac_var77;
}

/*
 * we maintain a queue of outputs
 * basically every OUTPUT adds an OUTGate,
 * and adds the returned share to this queue
 * this queue is then flushed at the end after we have done exec
 */

struct output_queue_elmt {
  ostream& os;  //output stream to which we will output (cout or files), can this be a reference to prevent copying?
  e_role role;  //who should we output the clear value to
  enum {PrintMsg, PrintValue } kind;
  string msg;
  share *ptr;
};

typedef vector<output_queue_elmt> output_queue;
/*
 * called from the EzPC generated code
 */
void add_to_output_queue(output_queue &q,
			 share *ptr,
			 e_role role,
			 ostream &os)
{
  struct output_queue_elmt elmt { os, role, output_queue_elmt::PrintValue, "", ptr };
  q.push_back(elmt);
}

void add_print_msg_to_output_queue (output_queue &q, string msg, e_role role, ostream &os)
{
  struct output_queue_elmt elmt { os, role, output_queue_elmt::PrintMsg, msg, NULL };
  q.push_back(elmt); 
}

/*
 * flush the queue
 * both parties call this function with their role
 * called from the EzPC generated code
 */
void flush_output_queue(output_queue &q, e_role role, uint32_t bitlen)
{
  for(output_queue::iterator it = q.begin(); it != q.end(); ++it) {  //iterate over the queue
    if (it->kind == output_queue_elmt::PrintValue) {
      if(it->role == ALL || it->role == role) {  //if the queue element role is same as mine
        if(bitlen == 32) {  //output to the stream
          it->os << it->ptr->get_clear_value<uint32_t>() << endl;
        } else {
          it->os << it->ptr->get_clear_value<uint64_t>() << endl;
        }
      }
    } else {
      if(it->role == ALL || it->role == role) {  //if the queue element role is same as mine
        it->os << it->msg << endl;
      }
    }
  }
}
#endif

