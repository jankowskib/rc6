/* rc6.c */
/*
This file is part of the AVR-Crypto-Lib.
Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
* File:	rc6.c
* Author:	Daniel Otte
* Date: 	06.08.2006
* License: GPL
* Description: Implementation of the RC6 cipher algorithm.
* 	This implementation is restricted to 32-bit words and to keys up to 65535 bit in length (but this is
*  quite easy to expand), but free in the choice of number of rounds (0 to 125).
* 	so it is RC6-32/r/b
* THIS ONLY WORKS FOR LITTLE ENDIAN!!!
*/

//#include <stdint.h>
//#include <stdlib.h>
#include <ruby.h>
#include "rc6.h"

#define P32 0xB7E15163		/* e -2 */
#define Q32 0x9E3779B9		/* Golden Ratio -1 */

uint32_t rotl32(uint32_t a, uint8_t n){
  n &= 0x1f; /* higher rotates would not bring anything */
  return ( (a<<n)| (a>>(32-n)) );
}

uint32_t rotr32(uint32_t a, uint8_t n){
  n &= 0x1f; /* higher rotates would not bring anything */
  return ( (a>>n)| (a<<(32-n)) );
}

void Init_rc6() {
  VALUE c = rb_define_class("RC6", rb_cObject);

  rb_define_alloc_func(c, method_rc6_alloc);

  rb_define_method(c, "initialize", RUBY_METHOD_FUNC(method_rc6_init), 1);
  rb_define_method(c, "decrypt!", RUBY_METHOD_FUNC(method_rc6_dec_bang), 1);
  rb_define_method(c, "decrypt", RUBY_METHOD_FUNC(method_rc6_dec), 1);
  rb_define_method(c, "encrypt!", RUBY_METHOD_FUNC(method_rc6_enc_bang), 1);
  rb_define_method(c, "encrypt", RUBY_METHOD_FUNC(method_rc6_enc), 1);
  rb_define_method(c, "key", RUBY_METHOD_FUNC(method_rc6_key), 0);
}

rc6_ctx_t* get_context(VALUE self) {
  rc6_ctx_t* p;
  Data_Get_Struct(self, rc6_ctx_t, p);
  return p;
}


VALUE method_rc6_key(VALUE self) {
  rc6_ctx_t* context = get_context(self);
  VALUE key = rb_ary_new2(44);
  int i;
  for(i=0;i<44;++i)
    rb_ary_store(key, i, INT2FIX(context->s[i]));

  return key;
}

void method_rc6_free(rc6_ctx_t* context) {
  free(context);
}

VALUE method_rc6_alloc(VALUE self) {
  return Data_Wrap_Struct(self, NULL, method_rc6_free, calloc(1, sizeof(rc6_ctx_t)));
}

VALUE method_rc6_init(VALUE self, VALUE key) {
  Check_Type(key, T_STRING);
  rc6_ctx_t* context = get_context(self);

  rc6_initl(StringValuePtr (key), 256, 20, context);

  return self;
}


uint8_t rc6_initl(void* key, uint16_t keylength_b, uint8_t rounds, rc6_ctx_t *s){
  uint8_t i,j;
  uint16_t v,p,c;
  uint32_t a,b, l=0;

  s->rounds=rounds;

  c = keylength_b/32;
  if (keylength_b%32) {
    ++c;
    j=(keylength_b%32)/8;
    if(keylength_b%8)
      ++j;

    for (i=0; i<j; ++i)
      ((uint8_t*)&l)[i] = ((uint8_t*)key)[(c-1)*4 + i];
    } else {
      l = ((uint32_t*)key)[c-1];
    }

    s->s[0] = P32;
    for(i=1; i<2*rounds+4; ++i){
      s->s[i] = s->s[i-1] + Q32;
    }

    a=b=j=i=0;
    v = 3 * ((c > 2*rounds+4)?c:(2*rounds+4));

  for(p=1; p<=v; ++p){
    a = s->s[i] = rotl32(s->s[i] + a + b, 3);
    if (j==c-1){
      b = l = rotl32(l+a+b, a+b);
    } else {
      b = ((uint32_t*)key)[j] = rotl32(((uint32_t*)key)[j]+a+b, a+b);
    }
    i = (i+1) % (2*rounds+4);
    j = (j+1) % c;
  }

  return 1;
}

        #define LG_W 5
        #define A (((uint32_t*)block)[0])
        #define B (((uint32_t*)block)[1])
        #define C (((uint32_t*)block)[2])
        #define D (((uint32_t*)block)[3])

        VALUE method_rc6_enc(VALUE self, VALUE data) {
          VALUE str = rb_str_dup(data);
          rb_str_modify(str);
          return method_rc6_enc_bang(self, str);
        }

        VALUE method_rc6_dec(VALUE self, VALUE data) {
          VALUE str = rb_str_dup(data);
          rb_str_modify(str);
          return method_rc6_dec_bang(self, str);
        }

        VALUE method_rc6_enc_bang(VALUE self, VALUE data) {
          rc6_ctx_t* ctx = get_context(self);
          int i;

          int str_len = RSTRING_LEN(data);
          char* str = RSTRING_PTR(data);
          char* end = RSTRING_END(data);
          rb_str_modify(data);

          if (rb_block_given_p()) {
            while(str<end) {
              priv_rc6_enc(ctx, str);
              rb_yield(rb_tainted_str_new(str, 16));
              str += 16;
            }
          } else {

            while(str<end) {
              priv_rc6_enc(ctx, str);
              str+=16;
            }
          }
          return data;
        }

        VALUE method_rc6_dec_bang(VALUE self, VALUE data) {
          rc6_ctx_t* ctx = get_context(self);
          int i;

          int str_len = RSTRING_LEN(data);
          char* str = RSTRING_PTR(data);
          char* end = RSTRING_END(data);

          rb_str_modify(data);

          if (rb_block_given_p()) {
            while(str<end) {
              priv_rc6_dec(ctx, str);
              rb_yield(rb_tainted_str_new(str, 16));
              str += 16;
            }
          } else {
            while(str<end) {
              priv_rc6_dec(ctx, str);
              str+=16;
            }
          }
          return data;
        }

        VALUE priv_rc6_enc(rc6_ctx_t* context, void* block) {
          uint8_t i;
          uint32_t t,u,x; /* greetings to Linux? */
          B += context->s[0];
          D += context->s[1];
          for (i=1; i<=20; ++i){
            t = rotl32(B * (2*B+1), LG_W);
            u = rotl32(D * (2*D+1), LG_W);
            A = rotl32((A ^ t), u) + context->s[2*i];
            C = rotl32((C ^ u), t) + context->s[2*i+1];
            x = A;
            A = B;
            B = C;
            C = D;
            D = x;
          }
          A += context->s[42];
          C += context->s[43];
          return Qnil;
        }

        VALUE priv_rc6_dec(rc6_ctx_t* context, void* block) {
          uint8_t i;
          uint32_t t,u,x; /* greetings to Linux? */

          C -= context->s[43];
          A -= context->s[42];

          for (i=20; i>0; --i){
            x=D;
            D=C;
            C=B;
            B=A;
            A=x;
            u = rotl32(D * (2*D+1), LG_W);
            t = rotl32(B * (2*B+1), LG_W);
            C = rotr32(C - context->s[2*i+1], t) ^ u;
            A = rotr32(A - context->s[2*i+0], u) ^ t;
          }
          D -= context->s[1];
          B -= context->s[0];
          return Qnil;
        }
