#import "@preview/codly:1.3.0": *
#import "@preview/codly-languages:0.1.1": *
#set page(margin: (x: 1.6cm, y: 1.4cm), numbering: "1", columns: 2)
#set text(font: "New Computer Modern", size: 9pt)
#set par(justify: true, leading: 0.5em)
#set heading(numbering: "1.")
#show heading.where(level: 1): it => { v(0.3em); text(size: 12pt, weight: "bold", it); v(0.15em) }
#show heading.where(level: 2): it => { v(0.2em); text(size: 10pt, weight: "bold", it); v(0.1em) }
#show figure.caption: it => text(size: 8pt, it)
#set figure(gap: 6pt)
#show raw.where(block: true): set text(size: 7pt)
#show table: set text(size: 8pt)
#show: codly-init.with()

#place(top + center, scope: "parent", float: true)[
  #align(center)[
    #text(size: 16pt, weight: "bold")[Hybrid Image Encryption\ Using RSA and AES]
    #v(2mm)
    #text(size: 10pt)[Smai Abdelmalek #h(1cm) Hadiouche Azouaou]
    #v(1mm)
    #text(size: 8.5pt, fill: gray)[Practical Work — Prof. A.K. Oudjida, NHSM, Sidi-Abdellah — May 2026]
    #v(1mm)
    #line(length: 100%, stroke: 0.4pt)
  ]
]

= Introduction

This report presents a hybrid image encryption system implemented in C. We build three encryption pipelines, test them on two images a 720×720 colored butterfly and a 254×255 black-and-white butterfly and evaluate their performance and cryptographic strength.

The three tasks are:

+ *Task 1 --- Raw RSA:* Direct block by block RSA encryption of pixel data. Each block of $k-1$ bytes is encrypted as $c = m^e mod n$.
+ *Task 2 --- RSA + OAEP:* OAEP padding is applied before RSA, introducing randomness for semantic security. The usable block size decreases to $k - 2h - 2$ bytes ($h = 32$ for SHA-256).
+ *Task 3 --- Hybrid:* A random AES-256 key is encrypted once with RSA+OAEP; the bulk image is encrypted with AES-256-CBC. This is the standard approach for today's encryption.

Since the test images are provided as PNG (compressed), we convert to BMP for pixel-level security analysis computing histograms on compressed PNG bytes would measure properties of the DEFLATE stream, not the actual pixels. Both PNG and BMP are processed through all three tasks for comprehensive results.

= Implementation

Our system is organized into four modules, each with a clean C header interface:

*Bignum library* (`bignum.h`) --- Arbitrary-precision arithmetic over 32-bit limbs. Provides addition, subtraction, schoolbook multiplication, restoring division, modular exponentiation, Extended Euclidean GCD, modular inverse, Miller-Rabin primality testing (40 rounds), and CSPRNG-backed prime generation via `RAND_bytes` offered by OpenSSL the bignum structure is defined as:

```c
typedef struct {
  uint32_t limbs[BN_MAX_LIMBS];
  int len, sign;
} bignum_t;
```

*RSA* (`rsa.h`) --- Key generation computes $n=p q$, $e=65537$, $d=e^(-1) mod phi(n)$, and CRT parameters $d_p, d_q, q^(-1) mod p$. Decryption uses the Chinese Remainder Theorem for ~4× speedup:
$ m_1 = c^(d_p) mod p, quad m_2 = c^(d_q) mod q $
$ m = m_2 + q dot [q^(-1)(m_1 - m_2) mod p] $

```c
typedef struct {
  bignum_t n, e, d, p, q;
  bignum_t dp, dq, qinv;  // CRT params
  int bits;
} rsa_key_t;
```

*OAEP* (`oaep.h`) --- PKCS\#1 v2.2 padding using SHA-256 and MGF1. \ 
*AES-CBC* (`aes_cbc.h`) --- OpenSSL wrapper for AES-256-CBC with PKCS\#7 padding.

All RSA arithmetic is hand implemented; only AES and SHA-256 (for OAEP/MGF1) use OpenSSL.

== OAEP Padding Scheme

OAEP transforms deterministic RSA into a semantically secure scheme by injecting randomness. Given message $M$, key size $k$ bytes, and hash length $h$:

#block(stroke: 0.4pt + gray, inset: 6pt, radius: 3pt, width: 100%)[
  #set text(size: 8pt)
  *OAEP Encode($M$, $k$):*
  + Compute $"lHash" = "SHA256"("")$
  + Build $"DB" = "lHash" || underbrace(00 dots 00, "PS") || "01" || M$ #h(1fr) _($k - h - 1$ bytes)_
  + Generate random seed $r in {0,1}^h$
  + $"maskedDB" = "DB" xor "MGF1"(r, |"DB"|)$
  + $"maskedSeed" = r xor "MGF1"("maskedDB", h)$
  + Output $"EM" = "00" || "maskedSeed" || "maskedDB"$
]

MGF1 stretches a seed into an arbitrary-length mask by hashing $"seed" || "counter"$. The double-masking ensures identical messages produce different ciphertexts each time, since the random seed $r$ changes on every call.

```c
int oaep_encode(const uint8_t *msg, size_t msg_len, size_t k, uint8_t *em)
{
	size_t max_msg = OAEP_MAX_MSG_LEN(k);
	if (msg_len > max_msg) {
		fprintf(stderr, "oaep_encode: message too long (%zu > %zu)\n",
			msg_len, max_msg);
		return -1;
	}

	size_t db_len = k - OAEP_HASH_LEN - 1;
	uint8_t *db = (uint8_t *)calloc(db_len, 1);
	uint8_t seed[OAEP_HASH_LEN];

	/* DB = lHash ‖ PS(zeros) ‖ 0x01 ‖ M */
	lhash(db);
	/* PS is already zeros from calloc */
	size_t ps_len = db_len - OAEP_HASH_LEN - 1 - msg_len;
	db[OAEP_HASH_LEN + ps_len] = 0x01;
	memcpy(db + OAEP_HASH_LEN + ps_len + 1, msg, msg_len);

	/* Generate random seed */
	RAND_bytes(seed, OAEP_HASH_LEN);

	/* maskedDB = DB ⊕ MGF1(seed) */
	uint8_t *db_mask = (uint8_t *)malloc(db_len);
	mgf1_sha256(seed, OAEP_HASH_LEN, db_mask, db_len);
	for (size_t i = 0; i < db_len; i++)
		db[i] ^= db_mask[i];

	/* maskedSeed = seed ⊕ MGF1(maskedDB) */
	uint8_t seed_mask[OAEP_HASH_LEN];
	mgf1_sha256(db, db_len, seed_mask, OAEP_HASH_LEN);
	for (size_t i = 0; i < OAEP_HASH_LEN; i++)
		seed[i] ^= seed_mask[i];

	/* EM = 0x00 ‖ maskedSeed ‖ maskedDB */
	em[0] = 0x00;
	memcpy(em + 1, seed, OAEP_HASH_LEN);
	memcpy(em + 1 + OAEP_HASH_LEN, db, db_len);

	free(db);
	free(db_mask);
	return 0;
}
```

= Performance Analysis

== Theoretical Complexity

#figure(
  table(
    columns: 4,
    inset: (x: 4pt, y: 3pt),
    align: center + horizon,
    stroke: 0.4pt,
    table.header([*Task*], [*Encrypt*], [*Decrypt*], [*Blocks*]),
    [1: Raw RSA], $O(N k^2 log e)$, $O(N k^2 log d)$, $N = ceil(n/(k-1))$,
    [2: RSA+OAEP], $O(N' k^2 log e)$, $O(N' k^2 log d)$, $N' = ceil(n/(k-66))$,
    [3: Hybrid], $O(n) + O(k^2 log e)$, $O(n) + O(k^2 log d)$, [1 RSA + AES],
  ),
  caption: [Complexity ($n$=data size, $k$=128 bytes for 1024-bit RSA).]
) <tab-complexity>

Tasks 1--2 perform $N$ modular exponentiations per image, each costing $O(k^2 log e)$ with schoolbook multiplication. Task 3 performs exactly *one* RSA operation (on the 32 byte AES key) plus a linear term with hardware acceleration.

== Measured Execution Times

We test on both PNG file bytes and BMP raw pixels.

#figure(
  table(
    columns: 5,
    inset: (x: 3pt, y: 2.5pt),
    align: center + horizon,
    stroke: 0.4pt,
    table.header([*Task*], [*Enc (ms)*], [*Dec (ms)*], [*Enc (ms)*], [*Dec (ms)*]),
    table.cell(colspan: 1)[], table.cell(colspan: 2)[_Colored (720×720)_], table.cell(colspan: 2)[_B&W (254×255)_],
    table.cell(colspan: 5)[*PNG file bytes*],
    [1: Raw RSA], [5 982], [162 886], [2 981], [81 067],
    [2: RSA+OAEP], [11 426], [339 896], [6 053], [166 526],
    [3: Hybrid], [*6*], [*155*], [*7*], [*153*],
    table.cell(colspan: 5)[*BMP raw pixels*],
    [1: Raw RSA], [60 824], [1 811 840], [8 196], [221 715],
    [2: RSA+OAEP], [129 867], [3 734 811], [17 059], [460 843],
    [3: Hybrid], [*7*], [*148*], [*7*], [*154*],
  ),
  caption: [Performance comparison (1024-bit RSA). Task 3 times are nearly identical across all inputs.]
) <tab-perf>

#figure(
  grid(
    columns: 2,
    column-gutter: 3mm,
    image("../output_colored/plots/performance_bmp.png", width: 100%),
    image("../output_blackandwhite/plots/performance_bmp.png", width: 100%),
  ),
  caption: [BMP performance (log scale): colored (left) vs B&W (right).]
) <fig-perf>

*Discussion.* Task 3 is ~20 000× faster than Task 1 on the colored BMP. For Tasks 1--2, execution time scales linearly with data size: the colored BMP (1.55 MB) takes ~10× longer than the B&W BMP (193 KB), which directly matches the 10× difference in pixel count. Task 3 remains constant at ~7 ms encrypt / ~150 ms decrypt regardless of image size, because RSA is applied only once (to encrypt the 32 byte AES key), and AES is well optimized comparing to RSA.

Decryption is always slower than encryption because $d$ is much larger than $e = 65537$; our CRT implementation provides ~4× speedup over naive $c^d mod n$. Task 2 is ~2× slower than Task 1 because OAEP reduces the usable payload from $k-1$ to $k-66$ bytes per block, roughly doubling the block count.

The B&W vs. colored comparison confirms linear scaling: the ratio of timings closely matches the ratio of data sizes ($1555200 / 193305 approx 8$), as expected from the $O(N)$ block count dependency.

= Security-Strength Evaluation

All metrics below are computed on BMP pixel data to ensure analysis operates on actual pixel values, since operating on the PNG file will study the compression DEFLATE stream rather then pixel values.

== Visual & Histogram Analysis

@fig-visual shows that all three tasks produce visually random noise from the original butterfly image. However, the histograms reveal a crucial difference.

#figure(
  image("../output_colored/plots/visual_comparison.png", width: 100%),
  caption: [Original and encrypted images. All tasks produce visually random output.]
) <fig-visual>

@fig-hist-orig shows the original image's RGB histograms: the distribution is highly non uniform, with strong peaks corresponding to the dominant colors in the butterfly. A good encryption algorithm is expected to flatten this distribution to approximate uniform randomness.

#figure(
  image("../output_colored/plots/histogram_original.png", width: 100%),
  caption: [Original image: peaked, non-uniform pixel distribution across all channels.]
) <fig-hist-orig>

@fig-hist-enc compares the encrypted histograms. Task 1 (Raw RSA) shows residual spikes because deterministic RSA maps identical plaintext blocks to identical ciphertext blocks, leaking statistical patterns. Tasks 2 and 3 achieve near perfectly flat distributions, confirming that OAEP's randomization eliminates this weakness.

#figure(
  grid(
    columns: 1,
    column-gutter: 2mm,
    image("../output_colored/plots/histogram_task1.png", width: 100%),
    image("../output_colored/plots/histogram_task2.png", width: 100%),
    image("../output_colored/plots/histogram_task3.png", width: 100%),
  ),
  caption: [Encrypted histograms: Task 1 (left) retains spikes; Tasks 2 (center) and 3 (right) are flat.]
) <fig-hist-enc>

== Entropy

Shannon entropy measures randomness per pixel. The theoretical maximum for 8-bit data is $H = 8.0$ bits.

#figure(
  table(
    columns: 5,
    inset: (x: 4pt, y: 2.5pt),
    align: center + horizon,
    stroke: 0.4pt,
    table.header([*Image*], [*R*], [*G*], [*B*], [*Avg*]),
    table.cell(colspan: 5)[_Colored butterfly_],
    [Original], [1.861], [1.787], [1.798], [1.815],
    [Task 1], [7.733], [7.734], [7.734], [7.734],
    [Task 2], [7.9995], [7.9995], [7.9996], [7.9995],
    [Task 3], [*7.9997*], [*7.9996*], [*7.9996*], [*7.9996*],
    table.cell(colspan: 5)[_B&W butterfly_],
    [Original], [5.404], [5.434], [5.403], [5.414],
    [Task 1], [7.981], [7.978], [7.977], [7.979],
    [Task 2], [7.997], [7.997], [7.997], [7.997],
    [Task 3], [*7.997*], [*7.997*], [*7.997*], [*7.997*],
  ),
  caption: [Shannon entropy per channel. Tasks 2--3 approach ideal (8.0) on both images.]
) <tab-entropy>

Task 1 achieves only 7.73 on the colored image because raw RSA is deterministic. The B&W image starts with higher base entropy 5.41 vs 1.82 due to its grayscale gradient, and Task 1 reaches 7.98 closer to ideal but still below Tasks 2--3.

== Correlation Tests

Adjacent pixel correlation measures residual spatial structure. Ideal: $approx 0$.

#figure(
  table(
    columns: 5,
    inset: (x: 4pt, y: 2.5pt),
    align: center + horizon,
    stroke: 0.4pt,
    table.header([*Image*], [*Horiz*], [*Vert*], [*Diag*], [*Avg |r|*]),
    table.cell(colspan: 5)[_Colored butterfly (R channel)_],
    [Original], [0.975], [0.942], [0.928], [0.948],
    [Task 1], [0.016], [0.041], [−0.050], [0.036],
    [Task 2], [0.022], [0.050], [−0.021], [0.031],
    [Task 3], [*−0.002*], [*0.024*], [*−0.009*], [*0.012*],
    table.cell(colspan: 5)[_B&W butterfly (R channel)_],
    [Original], [0.935], [0.936], [0.889], [0.920],
    [Task 1], [0.033], [−0.022], [−0.042], [0.032],
    [Task 2], [−0.025], [0.011], [0.010], [0.015],
    [Task 3], [*0.013*], [*−0.008*], [*0.021*], [*0.014*],
  ),
  caption: [Correlation coefficients. All tasks destroy spatial correlation; Task 3 is lowest.]
) <tab-corr>

#figure(
  image("../output_colored/plots/correlation_scatter.png", width: 100%),
  caption: [Correlation scatter (R, horizontal): original shows strong linear relationship; encrypted images show uniform scatter.]
) <fig-corr>

== Chi-Squared & NPCR/UACI

The $chi^2$ test measures deviation from uniform distribution (ideal $approx 255$ the mean of the sample). NPCR and UACI measure sensitivity to plaintext changes (ideal NPCR $> 99.6%$).

#figure(
  grid(
    columns: (1.2fr, 1fr),
    column-gutter: 3mm,
    table(
      columns: 4,
      inset: (x: 3pt, y: 2.5pt),
      align: center + horizon,
      stroke: 0.4pt,
      table.header([*Image*], [$chi^2$ R], [$chi^2$ G], [$chi^2$ B]),
      [Original], [66.4M], [72.0M], [68.9M],
      [Task 1], [223K], [221K], [221K],
      [Task 2], [348], [326], [321],
      [Task 3], [*214*], [*287*], [*253*],
    ),
    table(
      columns: 3,
      inset: (x: 3pt, y: 2.5pt),
      align: center + horizon,
      stroke: 0.4pt,
      table.header([*Task*], [*NPCR %*], [*UACI %*]),
      [1], [99.78], [47.55],
      [2], [99.61], [47.79],
      [3], [99.61], [47.67],
    ),
  ),
  caption: [$chi^2$ test (left) and NPCR/UACI (right) for colored image. Tasks 2--3 approach ideal $chi^2 approx 255$.]
) <tab-chi>

Task 1's $chi^2 approx 222 "K"$ reflects the non-uniform histogram caused by deterministic RSA. Tasks 2--3 achieve $chi^2 < 350$, very close to the expected value of ~255 for a truly uniform distribution. All tasks exceed the 99.6% NPCR threshold.

== Security Summary

#figure(
  table(
    columns: 6,
    inset: (x: 3pt, y: 3pt),
    align: center + horizon,
    stroke: 0.4pt,
    table.header([*Criterion*], [*Ideal*], [*Original*], [*Task 1*], [*Task 2*], [*Task 3*]),
    [Entropy], [8.0], [1.82], [7.73], [8.00], [*8.00*],
    [Corr |r|], [0.00], [0.95], [0.04], [0.03], [*0.01*],
    [$chi^2$], [~255], [69M], [222K], [331], [*251*],
    [Semantic], [✓], [—], [✗], [✓], [*✓*],
    [Speed], [Fast], [—], [Slow], [Slower], [*Fast*],
  ),
  caption: [Overall comparison. Task 3 achieves the best result on every criterion.]
) <tab-summary>

= Conclusion

Task 3 (Hybrid RSA+OAEP + AES-256-CBC) dominates across all dimensions: near ideal entropy (7.9996), lowest correlation (0.012), smallest $chi^2$ deviation (251), semantic security via OAEP, and a 20 000× speed advantage over pure RSA it didnt take an entire day to run like previous tasks. The performance confirms that Tasks 1--2 are impractical for real images: the colored BMP took over 60 minutes to decrypt with RSA alone. Task 3 completes the same work in 148 ms. This validates the standard of using asymmetric cryptography exclusively for key exchange while leaving the bulk encryption to symmetric ciphers like AES.
