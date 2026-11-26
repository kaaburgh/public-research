/* B12: bounded x86-64 RDRAND/RDSEED smoke test; prints counts only. */
#include <cpuid.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>

#define SAMPLE(F, T, I, TARGET) \
__attribute__((target(TARGET), noinline)) static int F(uint64_t *out) { \
    T x = 0; int ok = I(&x); *out = x; return ok; \
}
SAMPLE(rand16, unsigned short, _rdrand16_step, "rdrnd")
SAMPLE(rand32, unsigned int, _rdrand32_step, "rdrnd")
SAMPLE(rand64, unsigned long long, _rdrand64_step, "rdrnd")
SAMPLE(seed16, unsigned short, _rdseed16_step, "rdseed")
SAMPLE(seed32, unsigned int, _rdseed32_step, "rdseed")
SAMPLE(seed64, unsigned long long, _rdseed64_step, "rdseed")

static void test(const char *name, int supported, int (*f)(uint64_t *), uint64_t mask) {
    unsigned ok = 0, fail = 0, zero = 0, ones = 0, equal = 0;
    uint64_t prev = 0, v;
    if (!supported) { printf("%s unsupported by CPUID\n", name); return; }
    for (unsigned i = 0; i < 4096; i++) {
        if (!f(&v)) { fail++; continue; }
        zero += v == 0; ones += v == mask;
        if (ok && prev == v) equal++;
        prev = v; ok++;
    }
    printf("%s success=%u carry_clear=%u zero=%u all_ones=%u adjacent_equal=%u\n",
           name, ok, fail, zero, ones, equal);
}

int main(void) {
    unsigned a, b, c, d;
    int rdrand = __get_cpuid(1, &a, &b, &c, &d) && (c & bit_RDRND);
    int rdseed = __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & bit_RDSEED);
    test("rdrand16", rdrand, rand16, UINT16_MAX);
    test("rdrand32", rdrand, rand32, UINT32_MAX);
    test("rdrand64", rdrand, rand64, UINT64_MAX);
    test("rdseed16", rdseed, seed16, UINT16_MAX);
    test("rdseed32", rdseed, seed32, UINT32_MAX);
    test("rdseed64", rdseed, seed64, UINT64_MAX);
    return 0;
}
