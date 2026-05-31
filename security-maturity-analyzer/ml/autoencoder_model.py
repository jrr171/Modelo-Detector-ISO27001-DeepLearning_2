"""
Autoencoder para Detección de Anomalías — PyTorch
===================================================
Red neuronal profunda tipo Autoencoder entrenada SOLO con eventos normales.
Detecta anomalías calculando el error de reconstrucción (MSE) por evento:
  - Eventos normales → bajo MSE (el modelo los reconstruye bien)
  - Anomalías       → alto MSE (el modelo no los reconoce)

Arquitectura: Encoder 63→32→16→8 | Decoder 8→16→32→63
Técnicas DL:  BatchNorm, Dropout, Adam, Early Stopping, scheduler ReduceLROnPlateau
"""

import numpy as np
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_OK = True
except ImportError:
    TORCH_OK = False
    import warnings
    warnings.warn("PyTorch no disponible — Autoencoder usará implementación NumPy de respaldo.")
from typing import List, Dict
from analyzer.log_parser import LogEntry
from ml.feature_extractor import LogFeatureExtractor, N_TOTAL

torch.manual_seed(42)
np.random.seed(42)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


if TORCH_OK:
 class _AENet(nn.Module):
    """
    Autoencoder profundo con BatchNorm y Dropout.
    Encoder: 63 → 32 → 16 → 8
    Decoder: 8  → 16 → 32 → 63
    """
    def __init__(self, input_dim=N_TOTAL, bottleneck=8, dropout=0.2):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.BatchNorm1d(32), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(32, 16),        nn.BatchNorm1d(16), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(16, bottleneck),nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, 16), nn.BatchNorm1d(16), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(16, 32),         nn.BatchNorm1d(32), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(32, input_dim),  nn.Sigmoid(),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def encode(self, x):
        return self.encoder(x)


class LogAutoencoder:
    """
    Autoencoder PyTorch para detección de anomalías en logs ISO/IEC 27001:2022.
    Umbral automático en el percentil 95 del error de reconstrucción.
    """
    THRESHOLD_PERCENTILE = 95

    def __init__(self, lr=1e-3, weight_decay=1e-4, dropout=0.2, bottleneck=8):
        self.lr           = lr
        self.weight_decay = weight_decay
        self.extractor    = LogFeatureExtractor()
        self.net          = _AENet(N_TOTAL, bottleneck, dropout).to(DEVICE)
        self.criterion    = nn.MSELoss()
        self.threshold_   = 0.05
        self.train_losses_: List[float] = []
        self.val_losses_:   List[float] = []
        self._fitted = False
        self._min = self._max = None

    # ── Feature extraction ─────────────────────────────────────────
    def _to_tensor(self, entries: List[LogEntry]) -> torch.Tensor:
        X = np.array([self.extractor.extract(e) for e in entries], dtype=np.float32)
        if self._min is None:
            self._min = X.min(axis=0, keepdims=True)
            self._max = X.max(axis=0, keepdims=True)
        rng = np.where(self._max - self._min > 0, self._max - self._min, 1.0)
        X = (X - self._min) / rng
        return torch.tensor(X, dtype=torch.float32)

    # ── Training ───────────────────────────────────────────────────
    def fit(self, entries: List[LogEntry], epochs=30, batch_size=64,
            patience=5, val_split=0.15, verbose=0, **kw):
        if len(entries) < 10:
            return self

        X = self._to_tensor(entries)
        n_val  = max(1, int(len(X) * val_split))
        idx    = torch.randperm(len(X))
        X_val  = X[idx[:n_val]].to(DEVICE)
        X_tr   = X[idx[n_val:]].to(DEVICE)

        loader = DataLoader(TensorDataset(X_tr, X_tr), batch_size=batch_size, shuffle=True)

        optimizer = optim.Adam(self.net.parameters(), lr=self.lr, weight_decay=self.weight_decay)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)

        best_val, no_improve = float("inf"), 0
        best_state = None

        self.net.train()
        for ep in range(1, epochs + 1):
            ep_loss = 0.0
            for xb, yb in loader:
                optimizer.zero_grad()
                out  = self.net(xb)
                loss = self.criterion(out, yb)
                loss.backward()
                nn.utils.clip_grad_norm_(self.net.parameters(), 1.0)
                optimizer.step()
                ep_loss += loss.item()
            ep_loss /= max(len(loader), 1)

            self.net.eval()
            with torch.no_grad():
                val_loss = self.criterion(self.net(X_val), X_val).item()
            self.net.train()

            self.train_losses_.append(round(ep_loss, 6))
            self.val_losses_.append(round(val_loss, 6))
            scheduler.step(val_loss)

            if val_loss < best_val - 1e-5:
                best_val, no_improve = val_loss, 0
                best_state = {k: v.clone() for k, v in self.net.state_dict().items()}
            else:
                no_improve += 1
                if no_improve >= patience:
                    if verbose: print(f"  AE early stop epoch {ep}")
                    break

        if best_state:
            self.net.load_state_dict(best_state)

        # Calcular umbral P95 sobre errores de reconstrucción del training set
        self.net.eval()
        with torch.no_grad():
            recon = self.net(X_tr)
            errs  = ((recon - X_tr) ** 2).mean(dim=1).cpu().numpy()
        self.threshold_ = float(np.percentile(errs, self.THRESHOLD_PERCENTILE))
        self._fitted = True
        return self

    # ── Inference ──────────────────────────────────────────────────
    def anomaly_scores(self, entries: List[LogEntry]) -> np.ndarray:
        if not entries: return np.array([])
        self.net.eval()
        X = self._to_tensor(entries).to(DEVICE)
        with torch.no_grad():
            recon = self.net(X)
        return ((recon - X) ** 2).mean(dim=1).cpu().numpy()

    def predict(self, entries: List[LogEntry]) -> np.ndarray:
        scores = self.anomaly_scores(entries)
        return (scores > self.threshold_).astype(int)

    def summary(self) -> Dict:
        n_params = sum(p.numel() for p in self.net.parameters() if p.requires_grad)
        return {
            "model": "Autoencoder PyTorch",
            "architecture": "63→32→16→8→16→32→63 (BatchNorm + Dropout)",
            "framework": f"PyTorch {torch.__version__}",
            "device": str(DEVICE),
            "parameters": n_params,
            "epochs_trained": len(self.train_losses_),
            "threshold_p95": round(self.threshold_, 6),
            "final_train_loss": round(self.train_losses_[-1], 6) if self.train_losses_ else 0,
            "final_val_loss":   round(self.val_losses_[-1], 6)   if self.val_losses_   else 0,
        }
