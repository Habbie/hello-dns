#pragma once
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <string.h>

#define SMARTENUMSTART(x) static constexpr std::pair<x, const char*> enumtypemap##x[]= {
#define SENUM(x,a1) { x::a1, #a1},
#define SENUM2(x, a1, ...) SENUM(x,a1) SENUM(x, __VA_ARGS__)
#define SENUM3(x, a1, ...)  SENUM(x,a1) SENUM2(x, __VA_ARGS__)
#define SENUM4(x, a1, ...)  SENUM(x,a1) SENUM3(x, __VA_ARGS__)
#define SENUM5(x, a1, ...)  SENUM(x,a1) SENUM4(x, __VA_ARGS__)
#define SENUM6(x, a1, ...)  SENUM(x,a1) SENUM5(x, __VA_ARGS__)
#define SENUM7(x, a1, ...)  SENUM(x,a1) SENUM6(x, __VA_ARGS__)
#define SENUM8(x, a1, ...)  SENUM(x,a1) SENUM7(x, __VA_ARGS__)
#define SENUM9(x, a1, ...)  SENUM(x,a1) SENUM8(x, __VA_ARGS__)
#define SENUM10(x, a1, ...) SENUM(x,a1) SENUM9(x, __VA_ARGS__)
#define SENUM11(x, a1, ...) SENUM(x,a1) SENUM10(x, __VA_ARGS__)
#define SENUM12(x, a1, ...) SENUM(x,a1) SENUM11(x, __VA_ARGS__)
#define SENUM13(x, a1, ...) SENUM(x,a1) SENUM12(x, __VA_ARGS__)

#define SMARTENUMEND(x) };                                             \
inline const char* toString(const x& t)                                \
{                                                                      \
 for(const auto &a : enumtypemap##x)                                   \
   if(a.first == t)                                                    \
       return a.second;                                                \
  return "?";                                                          \
}                                                                      \
inline x make##x(const char* from) {                                   \
for(const auto& a : enumtypemap##x)                                    \
  if(!strcmp(a.second, from))                                          \
    return a.first;                                                    \
  throw std::runtime_error("Unknown value '" + std::string(from) + "' for enum "#x); \
 }                                                                     \
inline std::ostream& operator<<(std::ostream &os, const x& s) {        \
  os << toString(s); return os; }                                      \
                                                                      
#define COMBOENUM4(x, a1,b1,a2,b2,a3,b3,a4,b4) enum class x : uint16_t {     \
    a1=b1, a2=b2, a3=b3, a4=b4 }; SMARTENUMSTART(x) SENUM4(x, a1, a2, a3,a4) \
  SMARTENUMEND(x)  
