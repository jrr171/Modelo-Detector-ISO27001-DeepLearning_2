"""
Clasificador de Nivel de Madurez — MLP Profundo (PyTorch)
==========================================================
Red neuronal feed-forward profunda que predice el nivel de madurez COBIT (0–5)
a partir de estadísticas de los 4 dominios del Anexo A de ISO/IEC 27001:2022.

Arquitectura:
  Input:   24 features = 4 dominios × {score_norm, tasa_riesgo, log_eventos, cobertura_ip}
  Capa 1:  128 neuronas + BatchNorm + ReLU + Dropout(0.3)
  Capa 2:  64  neuronas + BatchNorm + ReLU + Dropout(0.2)
  Capa 3:  32  neuronas + ReLU
  Output:  6   neuronas + Softmax  → probabilidad por nivel COBIT (0–5)

Técnicas DL: BatchNorm, Dropout, Weight Decay (L2), Adam,
             LR Scheduler, Early Stopping, Synthetic Data Augmentation,
             Label Smoothing para generalización.
"""

import numpy as np
try:
    import torch
    TORCH_OK = True
except ImportError:
    TORCH_OK = False
    import warnings; warnings.warn(f"PyTorch no instalado en {__file__}. Instalar con: pip install torch")
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from typing import Dict, List, Tuple
from analyzer.event_classifier import DomainStats
from rules.iso27001_controls import ISO27001_DOMAINS, MATURITY_LEVELS

torch.manual_seed(42)
np.random.seed(42)

DEVICE    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
N_DOMAINS = 4     # A.5, A.6, A.7, A.8
N_STATS   = 6     # features por dominio
N_INPUT   = N_DOMAINS * N_STATS   # 24 features
N_CLASSES = 6     # niveles COBIT 0-5


class _MLPNet(nn.Module):
    """
    MLP profundo con BatchNorm y Dropout para clasificación de nivel de madurez.
    Cuatro capas ocultas con regularización completa para evitar overfitting.
    """
    def __init__(self, input_dim=N_INPUT, n_classes=N_CLASSES, dropout=0.3):
        super().__init__()
        self.net = nn.Sequential(
            # Capa 1: extracción de patrones
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128), nn.ReLU(), nn.Dropout(dropout),
            # Capa 2: representación intermedia
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),  nn.ReLU(), nn.Dropout(dropout * 0.7),
            # Capa 3: refinamiento
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),  nn.ReLU(), nn.Dropout(dropout * 0.5),
            # Capa 4: representación final
            nn.Linear(32, 16),   nn.ReLU(),
            # Output
            nn.Linear(16, n_classes),
        )
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                nn.init.zeros_(m.bias)

    def forward(self, x):
        return self.net(x)


class MaturityClassifier:
    """
    Clasificador MLP profundo (PyTorch) para predecir nivel de madurez COBIT 0–5
    a partir de estadísticas de los 4 dominios del Anexo A ISO/IEC 27001:2022.
    """
    DOMAIN_KEYS = list(ISO27001_DOMAINS.keys())

    def __init__(self, dropout=0.3):
        self.net       = _MLPNet(N_INPUT, N_CLASSES, dropout).to(DEVICE)
        self.criterion = nn.CrossEntropyLoss(label_smoothing=0.05)
        self._fitted   = False
        self._mean     = None
        self._std      = None
        self.train_losses_: List[float] = []
        self.val_losses_:   List[float] = []
        self.train_acc_:    List[float] = []
        self.val_acc_:      List[float] = []

    # ── Feature engineering ────────────────────────────────────────
    @staticmethod
    def domain_stats_to_vector(stats: Dict[str, DomainStats]) -> np.ndarray:
        """
        Convierte estadísticas de dominio en vector de 24 features:
        Por cada dominio: [score_norm, tasa_riesgo, log10_eventos,
                          cobertura_ip, cobertura_usuario, tasa_segura]
        """
        feats = []
        max_ev = max((s.total_events for s in stats.values()), default=1) or 1
        for key in MaturityClassifier.DOMAIN_KEYS:
            s = stats.get(key)
            if s is None or s.total_events == 0:
                feats.extend([0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            else:
                score_n  = s.risk_rate                               # 0–1
                risk_r   = float(s.risk_events) / max_ev             # normalizado
                log_ev   = np.log10(s.total_events + 1) / np.log10(max_ev + 1)
                cov_ip   = min(1.0, len(s.unique_ips)    / 50.0)
                cov_usr  = min(1.0, len(s.unique_users)  / 30.0)
                safe_r   = float(s.safe_events) / max(s.total_events, 1)
                feats.extend([score_n, risk_r, log_ev, cov_ip, cov_usr, safe_r])
        return np.array(feats, dtype=np.float32)

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        if self._mean is None:
            self._mean = X.mean(axis=0, keepdims=True)
            self._std  = X.std(axis=0, keepdims=True) + 1e-8
        return (X - self._mean) / self._std

    def _accuracy(self, logits: torch.Tensor, y: torch.Tensor) -> float:
        return (logits.argmax(dim=1) == y).float().mean().item()

    # ── Synthetic data generation ──────────────────────────────────
    @staticmethod
    def _synthetic_data(n_per=600) -> Tuple[np.ndarray, np.ndarray]:
        """
        Genera datos sintéticos balanceados para cada nivel COBIT (0–5).
        Simula distribuciones de estadísticas de dominio plausibles por nivel.
        """
        rng = np.random.default_rng(42)
        X, y = [], []
        # Perfiles de riesgo por nivel COBIT
        risk_profiles = {
            0: (0.85, 0.10),   # Nivel 0 — casi todo es riesgo
            1: (0.65, 0.12),   # Nivel 1 — mayoría de riesgo
            2: (0.40, 0.12),   # Nivel 2 — mucho riesgo
            3: (0.20, 0.10),   # Nivel 3 — riesgo moderado
            4: (0.08, 0.05),   # Nivel 4 — poco riesgo
            5: (0.02, 0.02),   # Nivel 5 — mínimo riesgo
        }
        ev_profiles = {
            0: (0.05, 0.03),   # Pocos logs
            1: (0.15, 0.06),
            2: (0.35, 0.10),
            3: (0.55, 0.10),
            4: (0.75, 0.10),
            5: (0.90, 0.05),   # Muchos logs, alta cobertura
        }
        for level in range(N_CLASSES):
            risk_mu, risk_sig = risk_profiles[level]
            ev_mu,   ev_sig   = ev_profiles[level]
            for _ in range(n_per):
                feats = []
                for _ in range(N_DOMAINS):
                    risk_r  = float(np.clip(rng.normal(risk_mu, risk_sig), 0, 1))
                    log_ev  = float(np.clip(rng.normal(ev_mu,   ev_sig),   0, 1))
                    cov_ip  = float(np.clip(rng.normal(ev_mu,   ev_sig),   0, 1))
                    cov_usr = float(np.clip(rng.normal(ev_mu * 0.8, ev_sig), 0, 1))
                    safe_r  = 1.0 - risk_r + rng.normal(0, 0.03)
                    safe_r  = float(np.clip(safe_r, 0, 1))
                    feats.extend([risk_r, risk_r * 0.5, log_ev, cov_ip, cov_usr, safe_r])
                X.append(feats); y.append(level)
        X = np.array(X, dtype=np.float32)
        y = np.array(y, dtype=np.int64)
        # Shuffle
        idx = np.random.permutation(len(X))
        return X[idx], y[idx]

    # ── Training ───────────────────────────────────────────────────
    def fit(self, domain_stats: Dict[str, DomainStats] = None,
            epochs=50, lr=1e-3, batch_size=64, patience=8,
            val_split=0.2, verbose=0, **kw):

        X_syn, y_syn = self._synthetic_data(n_per=600)

        # Si hay datos reales, añadirlos (data augmentation)
        if domain_stats:
            real_vec = self.domain_stats_to_vector(domain_stats)
            from rules.iso27001_controls import get_maturity_level
            # Calcular nivel real aproximado
            avg_risk = np.mean([s.risk_rate for s in domain_stats.values()])
            real_lvl = get_maturity_level((1 - avg_risk) * 100)
            # Augmentar con variaciones del dato real
            rng2 = np.random.default_rng(123)
            noise = rng2.normal(0, 0.02, (50, len(real_vec))).astype(np.float32)
            X_real = np.clip(real_vec + noise, 0, 1)
            y_real = np.full(50, real_lvl, dtype=np.int64)
            X_syn  = np.vstack([X_syn, X_real])
            y_syn  = np.hstack([y_syn, y_real])

        X_norm = self._normalize(X_syn)

        n_val  = max(1, int(len(X_norm) * val_split))
        idx    = np.random.permutation(len(X_norm))
        X_val, y_val = X_norm[idx[:n_val]], y_syn[idx[:n_val]]
        X_tr,  y_tr  = X_norm[idx[n_val:]], y_syn[idx[n_val:]]

        ds  = TensorDataset(torch.tensor(X_tr),  torch.tensor(y_tr))
        lds = DataLoader(ds, batch_size=batch_size, shuffle=True)
        Xv  = torch.tensor(X_val).to(DEVICE)
        yv  = torch.tensor(y_val).to(DEVICE)

        optimizer = optim.AdamW(self.net.parameters(), lr=lr, weight_decay=1e-3)
        scheduler = optim.lr_scheduler.OneCycleLR(
            optimizer, max_lr=lr * 5,
            steps_per_epoch=len(lds), epochs=epochs
        )

        best_val, no_improve = float("inf"), 0
        best_state = None

        for ep in range(1, epochs + 1):
            self.net.train()
            ep_loss, ep_acc = 0.0, 0.0
            for xb, yb in lds:
                xb, yb = xb.to(DEVICE), yb.to(DEVICE)
                optimizer.zero_grad()
                out  = self.net(xb)
                loss = self.criterion(out, yb)
                loss.backward()
                nn.utils.clip_grad_norm_(self.net.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                ep_loss += loss.item()
                ep_acc  += self._accuracy(out, yb)

            n_batches = max(len(lds), 1)
            ep_loss  /= n_batches
            ep_acc   /= n_batches

            self.net.eval()
            with torch.no_grad():
                vout     = self.net(Xv)
                val_loss = self.criterion(vout, yv).item()
                val_acc  = self._accuracy(vout, yv)

            self.train_losses_.append(round(ep_loss, 6))
            self.val_losses_.append(round(val_loss,  6))
            self.train_acc_.append(round(ep_acc,     4))
            self.val_acc_.append(round(val_acc,      4))

            if val_loss < best_val - 1e-5:
                best_val, no_improve = val_loss, 0
                best_state = {k: v.clone() for k, v in self.net.state_dict().items()}
            else:
                no_improve += 1
                if no_improve >= patience:
                    if verbose: print(f"  MLP early stop epoch {ep}")
                    break

        if best_state:
            self.net.load_state_dict(best_state)
        self._fitted = True
        return self

    # ── Inference ──────────────────────────────────────────────────
    def predict_proba(self, stats: Dict[str, DomainStats]) -> np.ndarray:
        vec  = self.domain_stats_to_vector(stats)
        vec  = self._normalize(vec[np.newaxis])
        t    = torch.tensor(vec, dtype=torch.float32).to(DEVICE)
        self.net.eval()
        with torch.no_grad():
            logits = self.net(t)
            probs  = torch.softmax(logits, dim=1).cpu().numpy()[0]
        return probs

    def predict_level(self, stats: Dict[str, DomainStats]) -> int:
        return int(np.argmax(self.predict_proba(stats)))

    def predict_with_confidence(self, stats: Dict[str, DomainStats]) -> Tuple[int, float, Dict]:
        probs    = self.predict_proba(stats)
        level    = int(np.argmax(probs))
        return level, float(probs[level]), {i: float(probs[i]) for i in range(N_CLASSES)}

    def summary(self) -> Dict:
        n_params = sum(p.numel() for p in self.net.parameters() if p.requires_grad)
        return {
            "model": "MLP Profundo Clasificador (PyTorch)",
            "architecture": "24→128→64→32→16→6 (BatchNorm+Dropout+LabelSmoothing)",
            "framework": f"PyTorch {torch.__version__}",
            "device": str(DEVICE),
            "parameters": n_params,
            "n_features": N_INPUT,
            "n_classes": N_CLASSES,
            "epochs_trained": len(self.train_losses_),
            "final_train_loss": round(self.train_losses_[-1], 6) if self.train_losses_ else 0,
            "final_val_loss":   round(self.val_losses_[-1],   6) if self.val_losses_   else 0,
            "final_val_acc":    round(self.val_acc_[-1],       4) if self.val_acc_      else 0,
        }
