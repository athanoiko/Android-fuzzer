# Vulnerability discovery in Android System through fuzzing

## Our Fuzzing Architecture

Our fuzzing approach for implementing our own in memory, dynamically instrumented
and coverage guided fuzzer is to use part of the logic of one of the must
effective fuzzers and transfer them in memory. This fuzzer is AFL. The idea for
this approach comes from the fact that AFL is one of the most efficient tools for that
fuzzing but lacks abilities that can be offered by Frida toolkit. These abilities that are
coming from dynamic instrumentation are things like bypassing login forms or other
authentications mechanisms, attacking multi-language applications with the same 
implementations and other. Attacking multi-language applications is very crucial
when attacking Android applications as they use in most cases a mix of Java and
C/C++ code and normally would need to use a different approach for fuzzing java
bytecodes and native libraries in same time.