"""
pqc_benchmark.py — Classical vs Post-Quantum Cryptography Benchmark
Measures RSA-2048 and ECDH P-256 locally.
Kyber numbers from official NIST PQC benchmarks.
Usage: python pqc_benchmark.py
"""

import json
import time
import statistics
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

ITERATIONS = 100

def bench(fn, n=ITERATIONS):
    times = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return times

def bench_rsa():
    print("  Benchmarking RSA-2048...")
    keygen_times = bench(lambda: rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()))
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    message = b"neurawall_session_key_32byteslong!"
    enc_times = bench(lambda: public_key.encrypt(message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)))
    ciphertext = public_key.encrypt(message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    dec_times = bench(lambda: private_key.decrypt(ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)))
    pub_bytes = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_bytes = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return {"algorithm": "RSA-2048", "type": "Classical", "source": "measured",
            "keygen_ms": round(statistics.mean(keygen_times), 3),
            "encap_ms": round(statistics.mean(enc_times), 3),
            "decap_ms": round(statistics.mean(dec_times), 3),
            "public_key_bytes": len(pub_bytes), "private_key_bytes": len(priv_bytes),
            "ciphertext_bytes": len(ciphertext), "quantum_safe": False}

def bench_ecdh():
    print("  Benchmarking ECDH P-256...")
    keygen_times = bench(lambda: ec.generate_private_key(ec.SECP256R1(), default_backend()))
    def do_ecdh():
        a = ec.generate_private_key(ec.SECP256R1(), default_backend())
        b = ec.generate_private_key(ec.SECP256R1(), default_backend())
        a.exchange(ec.ECDH(), b.public_key())
    exchange_times = bench(do_ecdh)
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_bytes = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_bytes = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return {"algorithm": "ECDH P-256", "type": "Classical", "source": "measured",
            "keygen_ms": round(statistics.mean(keygen_times), 3),
            "encap_ms": round(statistics.mean(exchange_times), 3),
            "decap_ms": 0.0,
            "public_key_bytes": len(pub_bytes), "private_key_bytes": len(priv_bytes),
            "ciphertext_bytes": 65, "quantum_safe": False}

def kyber_reference_numbers():
    print("  Loading Kyber reference numbers (NIST PQC official benchmarks)...")
    return [
        {"algorithm": "Kyber-512",  "type": "Post-Quantum", "source": "NIST PQC ref [8]",
         "keygen_ms": 0.022, "encap_ms": 0.027, "decap_ms": 0.025,
         "public_key_bytes": 800,  "private_key_bytes": 1632, "ciphertext_bytes": 768,
         "quantum_safe": True, "security_level": "NIST Level 1 (AES-128)"},
        {"algorithm": "Kyber-768",  "type": "Post-Quantum", "source": "NIST PQC ref [8]",
         "keygen_ms": 0.037, "encap_ms": 0.045, "decap_ms": 0.041,
         "public_key_bytes": 1184, "private_key_bytes": 2400, "ciphertext_bytes": 1088,
         "quantum_safe": True, "security_level": "NIST Level 3 (AES-192)"},
        {"algorithm": "Kyber-1024", "type": "Post-Quantum", "source": "NIST PQC ref [8]",
         "keygen_ms": 0.053, "encap_ms": 0.064, "decap_ms": 0.058,
         "public_key_bytes": 1568, "private_key_bytes": 3168, "ciphertext_bytes": 1568,
         "quantum_safe": True, "security_level": "NIST Level 5 (AES-256)"},
    ]

def run_pqc_benchmark():
    print()
    print("=" * 72)
    print("  PQC BENCHMARK: Classical vs Post-Quantum Cryptography")
    print("=" * 72)
    print(f"  Classical algorithms: measured locally ({ITERATIONS} iterations)")
    print(f"  Kyber: NIST PQC official reference benchmarks")
    print()

    results = [bench_rsa(), bench_ecdh()] + kyber_reference_numbers()

    lines = [
        "", "=" * 72,
        "  TABLE III: Classical vs Post-Quantum Cryptographic Performance",
        "=" * 72, "",
        f"  {'Algorithm':<14} {'Type':<14} {'KeyGen':>9} {'Encap':>9} {'Decap':>8} {'PubKey':>8} {'CT':>7} {'QSafe':>6}",
        "  " + "-" * 68,
    ]

    for r in results:
        typ  = "Classical" if not r["quantum_safe"] else "PQC"
        dec  = f"{r['decap_ms']:.3f}ms" if r["decap_ms"] > 0 else "N/A"
        src  = " *" if r["source"] != "measured" else "  "
        lines.append(
            f"  {r['algorithm']:<14} {typ:<14} {r['keygen_ms']:>8.3f}ms "
            f"{r['encap_ms']:>8.3f}ms {dec:>8} "
            f"{r['public_key_bytes']:>7}B {r['ciphertext_bytes']:>6}B "
            f"{'YES' if r['quantum_safe'] else 'NO':>6}{src}"
        )

    rsa_r    = next(r for r in results if "RSA"  in r["algorithm"])
    kyber512 = next(r for r in results if "512"  in r["algorithm"])
    kg_x  = rsa_r["keygen_ms"] / kyber512["keygen_ms"]
    enc_x = rsa_r["encap_ms"]  / kyber512["encap_ms"]

    lines += [
        "",
        "  * Kyber: NIST PQC official reference benchmarks (Intel Core i7).",
        "    RSA/ECDH measured on this machine.",
        "",
        "  KEY FINDINGS",
        "  ------------",
        f"  Kyber-512 key generation : {kyber512['keygen_ms']:.3f}ms vs RSA-2048: {rsa_r['keygen_ms']:.3f}ms ({kg_x:.0f}x faster)",
        f"  Kyber-512 encapsulation  : {kyber512['encap_ms']:.3f}ms vs RSA-2048: {rsa_r['encap_ms']:.3f}ms ({enc_x:.0f}x faster)",
        f"  Kyber-512 public key     : {kyber512['public_key_bytes']}B vs RSA-2048: {rsa_r['public_key_bytes']}B",
        f"  All Kyber variants resist Shor's algorithm. RSA and ECDH do not.",
        "",
        "  neurawall PHASE 5 RECOMMENDATION",
        "  ----------------------------------",
        f"  Kyber-512 is recommended as the default KEM for neurawall.",
        f"  At {kyber512['encap_ms']:.3f}ms encapsulation time it adds negligible",
        f"  overhead to HTTP key exchange while providing NIST Level 1",
        f"  quantum resistance.",
        "",
        "  PAPER SUMMARY",
        "  -------------",
        f"  Table III compares RSA-2048 and ECDH P-256 (measured, {ITERATIONS} iterations)",
        f"  against CRYSTALS-Kyber (NIST PQC reference). Kyber-512 key",
        f"  generation is {kg_x:.0f}x faster than RSA-2048 while providing",
        f"  quantum resistance. Public keys are larger ({kyber512['public_key_bytes']}B vs {rsa_r['public_key_bytes']}B)",
        f"  — an acceptable tradeoff for post-quantum HTTP security.",
        "", "=" * 72, "",
    ]

    report = "\n".join(lines)
    print(report)

    with open("pqc_results.json", "w", encoding="utf-8") as f:
        json.dump({"iterations": ITERATIONS, "results": results}, f, indent=2)
    with open("pqc_report.txt", "w", encoding="utf-8") as f:
        f.write(report)
    print("  Saved: pqc_results.json + pqc_report.txt\n")

if __name__ == "__main__":
    run_pqc_benchmark()

