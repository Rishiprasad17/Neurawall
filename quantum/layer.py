"""
Phase 5 — Quantum layer

Two components:
1. Post-quantum key exchange using CRYSTALS-Kyber
   (via liboqs-python when available, stubs otherwise)
2. Quantum ML anomaly scoring using PennyLane
   (via pennylane when available, stubs otherwise)

This file is intentionally forward-looking — it runs in stub mode
today and activates when you install the quantum dependencies.

Install (when ready):
    pip install open-quantum-safe pennylane
"""
import logging

from ..core.config import neurawallConfig
from ..core.models import RequestContext

logger = logging.getLogger("neurawall.quantum")


class QuantumLayer:
    def __init__(self, config: neurawallConfig):
        self.config = config
        self._kyber_available = self._try_import_kyber()
        self._pennylane_available = self._try_import_pennylane()
        logger.info(
            f"Quantum layer init | "
            f"Kyber={'ON' if self._kyber_available else 'STUB'} | "
            f"QML={'ON' if self._pennylane_available else 'STUB'}"
        )

    def _try_import_kyber(self) -> bool:
        try:
            import oqs  # open-quantum-safe
            self._oqs = oqs
            return True
        except ImportError:
            return False

    def _try_import_pennylane(self) -> bool:
        try:
            import pennylane as qml
            self._qml = qml
            return True
        except ImportError:
            return False

    async def pre_request(self, ctx: RequestContext):
        """Run quantum pre-checks before the request is forwarded."""
        if self.config.post_quantum_crypto and self._kyber_available:
            await self._kyber_handshake(ctx)
        else:
            logger.debug(f"[{ctx.request_id}] Quantum crypto stub (install open-quantum-safe)")

    async def _kyber_handshake(self, ctx: RequestContext):
        """
        CRYSTALS-Kyber key encapsulation.
        In a real deployment this negotiates a session key
        with the client using post-quantum KEM.
        """
        try:
            with self._oqs.KeyEncapsulation("Kyber512") as kem:
                public_key = kem.generate_keypair()
                ciphertext, shared_secret = kem.encap_secret(public_key)
                # Store shared_secret in ctx for downstream signing
                ctx.headers["X-Quantum-Session"] = shared_secret.hex()[:16]
                logger.debug(f"[{ctx.request_id}] Kyber512 handshake OK")
        except Exception as e:
            logger.warning(f"Kyber handshake failed: {e}")


class QMLScorer:
    """
    Quantum ML anomaly score refinement.
    Called from AnomalyDetector when qml_anomaly_model=True.
    """

    @staticmethod
    async def refine(classical_score: float, ctx: RequestContext) -> float:
        try:
            import pennylane as qml
            import numpy as np

            dev = qml.device("default.qubit", wires=2)

            @qml.qnode(dev)
            def circuit(x):
                qml.RY(x[0] * np.pi, wires=0)
                qml.RY(x[1] * np.pi, wires=1)
                qml.CNOT(wires=[0, 1])
                return qml.expval(qml.PauliZ(0))

            # Encode classical score + path length as quantum features
            features = [classical_score, min(len(ctx.path) / 100.0, 1.0)]
            q_out = circuit(features)

            # Blend: 70% classical, 30% quantum
            refined = 0.7 * classical_score + 0.3 * (1 - (float(q_out) + 1) / 2)
            logger.debug(f"[{ctx.request_id}] QML refined score: {classical_score:.3f} → {refined:.3f}")
            return refined

        except ImportError:
            logger.debug("PennyLane not installed — QML scoring skipped")
            return classical_score
        except Exception as e:
            logger.warning(f"QML scoring error: {e}")
            return classical_score
