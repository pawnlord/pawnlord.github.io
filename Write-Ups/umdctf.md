# umdctf
Challenges I solved during umdctf

# typecheck
Hint:
```
My C++ code won't type check. Can you fix that for me?
Note: you will need to set -ftemplate-depth=10000 when compiling.
```

## overview
This was a C++ rev challenge involving the template system. It had an input which was the flag, and an input that was the program. It created lists using some variadic templates, and then could use stack like behavior by popping or pushing by invoking further templates.

### main types
The first type used was a list:
```cpp
struct nil_t {};

template<class T, class U>
struct cons {
    using car = T;
    using cdr = U;
};
template <class T>
using car_t = typename T::car;

template <class T>
using cdr_t = typename T::cdr;

template <class ... Ts>
struct list;

template <>
struct list<> {
    using type = nil_t;
};

template <class T, class ... Ts>
struct list<T, Ts...> {
    using type = cons<T, list<Ts...>>;
};
```
A quick overview:  
1. `cons` is a pair of elements, used to store an element in the list concatenated with another list  
2. `car_t` gets the first item of `cons`, `cdr_t` gets the second item of `cons`  
3. List makes tail lists concatenated with the head at every step down
A note: the list uses variadic template args, which, like variadic function args, can match any number of arguments. It can also match no arguments, which gives us the base case. 

The next type used, which is the main form of item used in the vm, is a value type:
```c++
template <int v> struct V { static const constexpr int value = v ; };
```
A conventient way of making a list of value types of integers is also provided, which is used by the large prog and flag lists.
```cpp
template <int ... is>
struct int_list;

template <int i>
struct int_list<i> {
    using type = cons<V<i>, nil_t>;
};

template <int i, int ... is> 
struct int_list<i, is...> {
    using type = cons<V<i>, typename int_list<is...>::type>;
};

template <int ... is>
using int_list_t = typename int_list<is...>::type;
```
This is similar to the list above, but it automatically makes everything of type V. Luckily, C++ templates are duck typed so we don't need to worry about int_list not being a list.

## reversing
### instructions
The main loop of the VM is near the bottom, so we will start bottom up.  
The entry point is here, and is the first template instantiation called by main.cpp:
```cpp
template <typename S, typename IT, typename In>
using vm_t = typename vm<S, IT, In>::type;
```
Now, we specifically match instructions. There are 5 instructions, represented by numbers 0 through 4, and each of them has their own template specialization. We will go through each of them individually, with their respective data structures.  
#### instruction 0
```cpp
template <typename S>
struct A;

template <int a, int b, typename rest>
struct A<cons<V<a>, cons<V<b>, rest>>> {
    using type = cons<V<a + b>, rest>;
};

template <typename S>
using A_t = typename A<S>::type;

// ...

template <typename S, typename R, typename In>
struct vm<S, cons<V<0>, R>, In>  {
    using type = typename vm<A_t<S>, R, In>::type;
};
```
The first thing to note is that S, the first value, is the stack. R is the rest of the program, and In is the provided flag.   
The `vm<5, ...>` code will essentially give `A_t` the stack to mess around with, and then pass in the stack that `A_t` returns to the next iteration of the vm.
`A_t` is a wrapper around getting the "type" (really, the new stack) of the A struct with parameter S (really, the stack).  
Now, the meet of the instruction is in it's own definition, were it pops a value of the stack using cons pattern matching, and then adds the two values together, pushing them back on to the stack.
#### instruction 1
```cpp
template <typename S>
struct M;

template <int a, int b, typename rest>
struct M<cons<V<a>, cons<V<b>, rest>>> {
    using type = cons<V<a * b>, rest>;
};
// ...
template <typename S, typename R, typename In>
struct vm<S, cons<V<1>, R>, In>  {
    using type = typename vm<M_t<S>, R, In>::type;
};
```
This is similar to the first, except multiplication instead.

#### instruction 2
```cpp
template <int v, typename S>
struct P {
    using type = cons<V<v>, S>;
};
// ...
template <typename S, int PV, typename R, typename In>
struct vm<S, cons<V<2>, cons<V<PV>, R>>, In>  {
    using type = typename vm<P_t<PV, S>, R, In>::type;
};
```
This Takes the value PV from the program (pattern matched along with it's instruction number) and then pushes it to the stack, keeping the rest of the stack in place
#### instruction 3
```cpp
template <int i, typename T>
struct g;

template <int v, typename R>
struct g<0, cons<V<v>, R>> {
    static const constexpr int value = v;
};

template <int N, typename X, typename R>
struct g<N, cons<X, R>> {
    static const constexpr int value = g<N-1, R>::value;
};
// ...
template <typename S, int N, typename R, typename In>
struct vm<S, cons<V<3>, cons<V<N>, R>>, In> {
    using type = typename vm<cons<V<g<N, In>::value>, S>, R, In>::type;
};
```
This is, in my opinion, the weirdest one. It takes a parameter N off the stack and then, recursively, goes from `g<N, ...>` to `g<0, ...>`, popping a value off the list passed in to g each time (which, in this case, is the In value, or the flag that we are checkking). So, essentailly, this indexes to In by the next number in the array.
#### instruction 4
```cpp
template <int v, int v_, typename R>
struct T<v, cons<V<v_>, R>> {
    using type = std::enable_if_t<v == v_, R>;
};
// ...
template <typename S, int PV, typename R, typename In>
struct vm<S, cons<V<4>, cons<V<PV>, R>>, In>  {
    using type = typename vm<T_t<PV, S>, R, In>::type;
};
```
This is an `==` operator. It pops a value off the stack and then checks it with the next value in the program, and then bushes the value (either true or false) onto the stack.
## the solution
The final solution is simple: at this point we can assume it does a bunch of operations, and then cheks it using instruction 4. So, we "decompile" it to a z3 using a python script. Here's the solve:

```py
from pwn import *
from z3 import *
from prog import *

In = []
for i in range(100):
    In.append(Int("In[" + str(i) + "]"))

"""
bytecode:
    0 = add 0, 1
    1 = mul 0, 1
    2 = push imm
    3 = push In[imm]
    4 = check 0 == imm
"""

s = Solver()

stack = []

i = 0
while i < len(prog):
    instr = prog[i]
    if instr == 0:
        print(hex(i), "--", "add")
        a = stack.pop()
        b = stack.pop()
        stack.append(a + b)
    elif instr == 1:
        print(hex(i), "--", "mul")
        a = stack.pop()
        b = stack.pop()
        stack.append(a * b)
    elif instr == 2:
        val = prog[i + 1]
        i += 1
        print(hex(i), "--", "push " + str(val))
        stack.append(val)
    elif instr == 3:
        val = prog[i + 1]
        i += 1
        print(hex(i), "--", "push In[" + str(val) + "]")
        stack.append(In[val])
    elif instr == 4:
        val = prog[i + 1]
        i += 1
        print(hex(i), "--", "cmp", val)
        val_ = stack.pop()
        stack.append(val_ == val)
    i += 1
print(stack)

for cond in stack:
    s.add(cond)

print(s.check())
m = s.model()

for val in In:
    print(chr(m[val].as_long()), end="")
```