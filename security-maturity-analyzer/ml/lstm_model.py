"""
Detector de Amenazas en Secuencias — LSTM Bidireccional (PyTorch)
==================================================================
Red neuronal recurrente que analiza VENTANAS de 20 eventos consecutivos
para detectar patrones temporales de ataque (fuerza bruta, movimiento
lateral, exfiltración escalonada) que el análisis evento-por-evento no detecta.

Arquitectura real LSTM:
  Input:   (batch, 20, N_NUMERIC)          — 20 eventos × features numéricas
  BiLSTM:  (batch, 20, 128)  hidden=64×2  — Bidireccional, 2 capas
  Atención: context vector (batch, 128)    — Mecanismo de atención
  MLP:     128 → 64 → 32 → 1             — Clasificación binaria (ataque/normal)
  Output:  sigmoid → probabilidad de ataque

Técnicas DL: BiLSTM, Attention mechanism, BatchNorm, Dropout, Adam,
             class_weight balanceo, Early Stopping, Gradient Clipping
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
from typing import List, Dict, Tuple
from analyzer.log_parser import LogEntry
from ml.feature_extractor import LogFeatureExtractor, N_NUMERIC

torch.manual_seed(42)
np.random.seed(42)

DEVICE     = torch.device("cuda" if torch.cuda.is_available() else "cpu")
WIN_SIZE   = 20   # Ventana temporal de eventos


class _AttentionLayer(nn.Module):
    """Mecanismo de atención aditiva (Bahdanau) sobre la secuencia LSTM."""
    def __init__(self, hidden_dim):
        super().__init__()
        self.attn = nn.Linear(hidden_dim, 1)

    def forward(self, lstm_out):
        # lstm_out: (batch, seq, hidden)
        weights = torch.softmax(self.attn(lstm_out), dim=1)   # (batch, seq, 1)
        context = (weights * lstm_out).sum(dim=1)              # (batch, hidden)
        return context, weights.squeeze(-1)


class _BiLSTMNet(nn.Module):
    """
    LSTM Bidireccional con mecanismo de atención para detección de amenazas.
    BiLSTM captura tanto el contexto pasado como el futuro en cada paso temporal.
    """
    def __init__(self, input_dim=N_NUMERIC, hidden=64, n_layers=2, dropout=0.3):
        super().__init__()
        self.hidden     = hidden
        self.n_layers   = n_layers
        self.bilstm     = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden,
            num_layers=n_layers,
            bidirectional=True,
            dropout=dropout if n_layers > 1 else 0,
            batch_first=True,
        )
        self.attention  = _AttentionLayer(hidden * 2)   # ×2 por bidireccional
        self.classifier = nn.Sequential(
            nn.Linear(hidden * 2, 64), nn.BatchNorm1d(64), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(64, 32),         nn.ReLU(),
            nn.Linear(32, 1),          nn.Sigmoid(),
        )

    def forward(self, x):
        # x: (batch, seq_len, input_dim)
        lstm_out, _ = self.bilstm(x)           # (batch, seq, hidden*2)
        context, _  = self.attention(lstm_out) # (batch, hidden*2)
        return self.classifier(context).squeeze(-1)


class LSTMThreatDetector:
    """
    Detector de amenazas temporales con BiLSTM + Atención (PyTorch).
    Analiza secuencias de 20 eventos para detectar patrones de ataque
    que son invisibles al análisis evento por evento.
    """

    def __init__(self, hidden=64, n_layers=2, dropout=0.3):
        self.extractor  = LogFeatureExtractor()
        self.net        = _BiLSTMNet(N_NUMERIC, hidden, n_layers, dropout).to(DEVICE)
        self.criterion  = nn.BCELoss()
        self._fitted    = False
        self.train_losses_: List[float] = []
        self.val_losses_:   List[float] = []
        self.train_acc_:    List[float] = []
        self.val_acc_:      List[float] = []
        self._scaler_mean   = None
        self._scaler_std    = None

    def _extract_features(self, entries: List[LogEntry]) -> np.ndarray:
        return np.array([
            self.extractor.extract_numeric(e) for e in entries
        ], dtype=np.float32)

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        if self._scaler_mean is None:
            self._scaler_mean = X.mean(axis=0, keepdims=True)
            self._scaler_std  = X.std(axis=0, keepdims=True) + 1e-8
        return (X - self._scaler_mean) / self._scaler_std

    def _make_windows(self, entries: List[LogEntry], label: int
                      ) -> Tuple[np.ndarray, np.ndarray]:
        """Desliza una ventana de WIN_SIZE sobre la secuencia de eventos."""
        feats = self._extract_features(entries)
        if len(feats) < WIN_SIZE:
            # Padding con ceros si hay pocos eventos
            pad   = np.zeros((WIN_SIZE - len(feats), feats.shape[1]), dtype=np.float32)
            feats = np.vstack([feats, pad])
            return feats[np.newaxis], np.array([label], dtype=np.float32)
        X, y = [], []
        for i in range(0, len(feats) - WIN_SIZE + 1, max(1, WIN_SIZE // 2)):
            X.append(feats[i:i + WIN_SIZE])
            y.append(label)
        return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32)

    def _accuracy(self, out: torch.Tensor, y: torch.Tensor) -> float:
        preds = (out >= 0.5).float()
        return (preds == y).float().mean().item()

    # ── Training ───────────────────────────────────────────────────
    def fit(self, normal_entries: List[LogEntry], attack_entries: List[LogEntry],
            epochs=25, lr=1e-3, batch_size=32, patience=6,
            val_split=0.2, verbose=0, **kw):

        if len(normal_entries) < WIN_SIZE:
            normal_entries = normal_entries * (WIN_SIZE // max(len(normal_entries), 1) + 1)

        Xn, yn = self._make_windows(normal_entries, label=0)
        Xa, ya = self._make_windows(attack_entries or normal_entries[:5], label=1)

        X = np.vstack([Xn, Xa]); y = np.hstack([yn, ya])
        # Normalizar features (en dim. de secuencia)
        flat = X.reshape(-1, X.shape[-1])
        flat = self._normalize(flat)
        X    = flat.reshape(X.shape)

        # Shuffle y split
        idx   = np.random.permutation(len(X))
        X, y  = X[idx], y[idx]
        n_val = max(1, int(len(X) * val_split))
        X_val, y_val = X[:n_val], y[:n_val]
        X_tr,  y_tr  = X[n_val:], y[n_val:]

        # Class weights para datos desbalanceados
        pos_weight = torch.tensor([len(yn) / max(len(ya), 1)], dtype=torch.float32).to(DEVICE)
        criterion  = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

        ds  = TensorDataset(torch.tensor(X_tr), torch.tensor(y_tr))
        lds = DataLoader(ds, batch_size=batch_size, shuffle=True)

        optimizer = optim.Adam(self.net.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        best_val, no_improve = float("inf"), 0
        best_state = None

        for ep in range(1, epochs + 1):
            self.net.train()
            ep_loss, ep_acc = 0.0, 0.0
            for xb, yb in lds:
                xb, yb = xb.to(DEVICE), yb.to(DEVICE)
                optimizer.zero_grad()
                out  = self.net(xb)
                loss = criterion(out, yb)
                loss.backward()
                nn.utils.clip_grad_norm_(self.net.parameters(), 1.0)
                optimizer.step()
                ep_loss += loss.item()
                ep_acc  += self._accuracy(torch.sigmoid(out), yb)
            scheduler.step()

            n_batches = max(len(lds), 1)
            ep_loss  /= n_batches
            ep_acc   /= n_batches

            self.net.eval()
            with torch.no_grad():
                Xv = torch.tensor(X_val).to(DEVICE)
                yv = torch.tensor(y_val).to(DEVICE)
                vout    = self.net(Xv)
                val_loss = criterion(vout, yv).item()
                val_acc  = self._accuracy(torch.sigmoid(vout), yv)

            self.train_losses_.append(round(ep_loss,  6))
            self.val_losses_.append(round(val_loss, 6))
            self.train_acc_.append(round(ep_acc,    4))
            self.val_acc_.append(round(val_acc,   4))

            if val_loss < best_val - 1e-5:
                best_val, no_improve = val_loss, 0
                best_state = {k: v.clone() for k, v in self.net.state_dict().items()}
            else:
                no_improve += 1
                if no_improve >= patience:
                    if verbose: print(f"  LSTM early stop epoch {ep}")
                    break

        if best_state:
            self.net.load_state_dict(best_state)
        self._fitted = True
        return self

    # ── Inference ──────────────────────────────────────────────────
    def predict_threat_probs(self, entries: List[LogEntry]) -> np.ndarray:
        if not entries or not self._fitted:
            return np.zeros(max(len(entries), 1))
        feats = self._extract_features(entries)
        feats = self._normalize(feats)
        probs = []
        self.net.eval()
        for i in range(0, max(1, len(feats) - WIN_SIZE + 1), max(1, WIN_SIZE // 2)):
            win  = feats[i:i + WIN_SIZE]
            if len(win) < WIN_SIZE:
                pad = np.zeros((WIN_SIZE - len(win), win.shape[1]), dtype=np.float32)
                win = np.vstack([win, pad])
            t = torch.tensor(win[np.newaxis], dtype=torch.float32).to(DEVICE)
            with torch.no_grad():
                p = torch.sigmoid(self.net(t)).item()
            probs.append(p)
        return np.array(probs)

    def overall_threat_level(self, entries: List[LogEntry]) -> Dict:
        probs = self.predict_threat_probs(entries)
        if len(probs) == 0:
            return {"mean_threat_prob": 0.0, "max_threat_prob": 0.0,
                    "pct_high_threat": 0.0, "pct_medium_threat": 0.0,
                    "pct_low_threat": 100.0, "total_sequences": 0}
        pct_high   = float(np.mean(probs > 0.75) * 100)
        pct_medium = float(np.mean((probs > 0.50) & (probs <= 0.75)) * 100)
        pct_low    = max(0.0, 100.0 - pct_high - pct_medium)
        return {
            "mean_threat_prob":   float(np.mean(probs)),
            "max_threat_prob":    float(np.max(probs)),
            "pct_high_threat":    pct_high,
            "pct_medium_threat":  pct_medium,
            "pct_low_threat":     pct_low,
            "total_sequences":    len(probs),
        }

    def summary(self) -> Dict:
        n_params = sum(p.numel() for p in self.net.parameters() if p.requires_grad)
        return {
            "model": "LSTM Bidireccional + Atención (PyTorch)",
            "architecture": f"Input({N_NUMERIC})→BiLSTM(64×2)→Atención→64→32→1(sigmoid)",
            "framework": f"PyTorch {torch.__version__}",
            "device": str(DEVICE),
            "parameters": n_params,
            "window_size": WIN_SIZE,
            "epochs_trained": len(self.train_losses_),
            "final_train_loss": round(self.train_losses_[-1], 6) if self.train_losses_ else 0,
            "final_val_loss":   round(self.val_losses_[-1],   6) if self.val_losses_   else 0,
            "final_val_acc":    round(self.val_acc_[-1],       4) if self.val_acc_      else 0,
        }
