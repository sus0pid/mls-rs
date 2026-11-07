# HPKE PQ test vectors

`test_vectors.json` contains the following test vectors, transcribed from Appendix A of
[draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/05/) ("Post-Quantum
and Post-Quantum/Traditional Hybrid Algorithms for HPKE", R. Barnes and D. Connolly, 6 July 2026):

| Section | KEM | KDF | AEAD |
|---|---|---|---|
| A.2 | ML-KEM-768 (`kem_id` 0x0041) | HKDF-SHA256 | AES-128-GCM |
| A.5 | MLKEM768-X25519 (`kem_id` 0x647a) | HKDF-SHA256 | ChaCha20-Poly1305 |

The field names follow the JSON schema of the
[hpkewg/hpke-pq](https://github.com/hpkewg/hpke-pq) test vectors. Every field was cross-checked
against `test-vectors.json` at commit `11b5b954` of that repository (SHA-256
`35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c`), and all fields match.

## License

These values are extracted from an IETF document and are provided under the Revised BSD
License, as required by Section 4.e of the IETF Trust Legal Provisions:

Copyright (c) 2026 IETF Trust and the persons identified as authors of the code. All rights
reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of
  conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other materials provided
  with the distribution.
- Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific
  contributors, may be used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
