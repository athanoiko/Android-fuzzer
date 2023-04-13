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

The operations we mentioned above are the following:
* bitflip: Invert one or several consecutive bits in a test case with 1 bit stepover. Operation modes: bitflip 1/1, bitflip 2/1, bitflip 4/1.
* byteflip: Invert one or several consecutive bytes in a test case, with 8 bits stepover. Operation modes: bitflip 8/8, bitflip 16/8, bitflip 32/8.
* arithmetic increase/decrease: Perform addition and subtraction operations on one byte or more consecutive bytes. Operation modes: interest 8/8, interest 16/8, interest 32/8.
* user extras: Overwrite or insert bytes in the test cases with user-provided tokens. Operation modes: user (over), user (insert).
* auto extras: Overwrite bytes in the test cases with tokens recognized by the fuzzer during bitflip 1/1.
* random bytes: Randomly select one byte of the test case and set the byte to a random value.
* delete bytes: Randomly select several consecutive bytes and delete them.
* insert bytes: Randomly copy some bytes from a test case and insert them to another location in this test case.
* overwrite bytes: Randomly overwrite several consecutive bytes in a test case.
* cross over: Splice two parts from two different test cases to form a new test case.

The fuzzer is created with Frida’s instrumentation language, javascript. For information on how to use it, you can find in my [Master's Thesis](https://github.com/AthanasiosOikonomou/Android-fuzzer/blob/main/Vulnerability%20discovery%20in%20Android%20System%20through%20fuzzing.pdf) 