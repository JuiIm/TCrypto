import csv
import os
import sys
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(BASE, "output")
PLOTS = os.path.join(OUTPUT, "plots")
os.makedirs(PLOTS, exist_ok=True)

TASKS = {
    "original": os.path.join(OUTPUT, "original.bmp"),
    "task1": os.path.join(OUTPUT, "bmp_task1_encrypted.bmp"),
    "task2": os.path.join(OUTPUT, "bmp_task2_encrypted.bmp"),
    "task3": os.path.join(OUTPUT, "bmp_task3_encrypted.bmp"),
}
LABELS = {"original": "Original", "task1": "Raw RSA", "task2": "RSA+OAEP", "task3": "Hybrid AES"}
CHANNELS = ["R", "G", "B"]


def load_pixels(path):
    img = Image.open(path).convert("RGB")
    return np.array(img, dtype=np.uint8)


def entropy(channel):
    hist, _ = np.histogram(channel.ravel(), bins=256, range=(0, 256))
    probs = hist / hist.sum()
    probs = probs[probs > 0]
    return -np.sum(probs * np.log2(probs))


def correlation(channel, direction="horizontal", n_samples=3000):
    h, w = channel.shape
    rng = np.random.default_rng(42)

    if direction == "horizontal":
        xs = rng.integers(0, h, n_samples)
        ys = rng.integers(0, w - 1, n_samples)
        a = channel[xs, ys].astype(float)
        b = channel[xs, ys + 1].astype(float)
    elif direction == "vertical":
        xs = rng.integers(0, h - 1, n_samples)
        ys = rng.integers(0, w, n_samples)
        a = channel[xs, ys].astype(float)
        b = channel[xs + 1, ys].astype(float)
    else:
        xs = rng.integers(0, h - 1, n_samples)
        ys = rng.integers(0, w - 1, n_samples)
        a = channel[xs, ys].astype(float)
        b = channel[xs + 1, ys + 1].astype(float)

    if np.std(a) == 0 or np.std(b) == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def chi_squared(channel):
    hist, _ = np.histogram(channel.ravel(), bins=256, range=(0, 256))
    expected = channel.size / 256.0
    return float(np.sum((hist - expected) ** 2 / expected))


def npcr_uaci(img1, img2):
    p1 = img1.ravel().astype(float)
    p2 = img2.ravel().astype(float)
    diff = (p1 != p2).astype(float)
    npcr = 100.0 * np.mean(diff)
    uaci = 100.0 * np.mean(np.abs(p1 - p2) / 255.0)
    return npcr, uaci


def main():
    images = {}
    for name, path in TASKS.items():
        if os.path.exists(path):
            images[name] = load_pixels(path)
            print(f"Loaded {name}: {images[name].shape}")
        else:
            print(f"WARNING: {path} not found, skipping {name}")

    if "original" not in images:
        print("ERROR: original.bmp not found in output/")
        sys.exit(1)

    orig = images["original"]

    print("\nComputing metrics...")
    metrics = []

    for name, pix in images.items():
        for ci, ch_name in enumerate(CHANNELS):
            ch = pix[:, :, ci]
            e = entropy(ch)
            ch_sq = chi_squared(ch)
            corr_h = correlation(ch, "horizontal")
            corr_v = correlation(ch, "vertical")
            corr_d = correlation(ch, "diagonal")

            metrics.append((name, "entropy", ch_name, f"{e:.4f}"))
            metrics.append((name, "chi_squared", ch_name, f"{ch_sq:.2f}"))
            metrics.append((name, "correlation_h", ch_name, f"{corr_h:.6f}"))
            metrics.append((name, "correlation_v", ch_name, f"{corr_v:.6f}"))
            metrics.append((name, "correlation_d", ch_name, f"{corr_d:.6f}"))

        if name != "original":
            npcr, uaci = npcr_uaci(orig, pix)
            metrics.append((name, "npcr", "all", f"{npcr:.2f}"))
            metrics.append((name, "uaci", "all", f"{uaci:.2f}"))

    csv_path = os.path.join(OUTPUT, "metrics.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["task", "metric", "channel", "value"])
        w.writerows(metrics)
    print(f"Metrics saved to {csv_path}")

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║              Security Metrics Summary                ║")
    print("╠══════════════════════════════════════════════════════╣")
    for name in images:
        label = LABELS.get(name, name)
        ents = [m[3] for m in metrics if m[0] == name and m[1] == "entropy"]
        corrs = [m[3] for m in metrics if m[0] == name and m[1] == "correlation_h"]
        print(f"║ {label:<12} Entropy(R,G,B): {', '.join(ents):<20} ║")
        print(f"║ {'':<12} Corr_H(R,G,B): {', '.join(corrs):<21} ║")
        npcr_vals = [m[3] for m in metrics if m[0] == name and m[1] == "npcr"]
        if npcr_vals:
            uaci_vals = [m[3] for m in metrics if m[0] == name and m[1] == "uaci"]
            print(f"║ {'':<12} NPCR: {npcr_vals[0]}%  UACI: {uaci_vals[0]}%{'':<13} ║")
    print("╚══════════════════════════════════════════════════════╝")

    print("\nGenerating plots...")

    colors = ['red', 'green', 'blue']
    for name, pix in images.items():
        fig, axes = plt.subplots(1, 3, figsize=(15, 4))
        fig.suptitle(f"Histogram — {LABELS.get(name, name)}", fontsize=14)
        for ci, (ax, ch_name, color) in enumerate(zip(axes, CHANNELS, colors)):
            ch = pix[:, :, ci].ravel()
            ax.hist(ch, bins=256, range=(0, 256), color=color, alpha=0.7,
                    edgecolor='none', density=True)
            ax.set_title(f"{ch_name} channel")
            ax.set_xlim(0, 255)
            ax.set_xlabel("Pixel value")
            ax.set_ylabel("Frequency")
        plt.tight_layout()
        plt.savefig(os.path.join(PLOTS, f"histogram_{name}.png"), dpi=150)
        plt.close()

    fig, axes = plt.subplots(1, len(images), figsize=(5 * len(images), 4))
    if len(images) == 1:
        axes = [axes]
    for ax, (name, pix) in zip(axes, images.items()):
        ch = pix[:, :, 0]
        h, w = ch.shape
        rng = np.random.default_rng(42)
        xs = rng.integers(0, h, 2000)
        ys = rng.integers(0, w - 1, 2000)
        ax.scatter(ch[xs, ys], ch[xs, ys + 1], s=1, alpha=0.3, c='blue')
        ax.set_title(f"{LABELS.get(name, name)}")
        ax.set_xlabel("Pixel(x, y)")
        ax.set_ylabel("Pixel(x, y+1)")
        ax.set_xlim(0, 255)
        ax.set_ylim(0, 255)
    plt.suptitle("Horizontal Correlation (R channel)", fontsize=14)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS, "correlation_scatter.png"), dpi=150)
    plt.close()

    perf_csv = os.path.join(OUTPUT, "performance.csv")
    if os.path.exists(perf_csv):
        perf = {}
        with open(perf_csv) as f:
            reader = csv.DictReader(f)
            for row in reader:
                task = row["task"]
                op = row["operation"]
                perf[(task, op)] = float(row["time_ms"])

        for mode, mode_label in [("png", "PNG File"), ("bmp", "BMP Pixels")]:
            tasks_list = [f"{mode}_task1", f"{mode}_task2", f"{mode}_task3"]
            task_labels = ["Raw RSA", "RSA+OAEP", "Hybrid AES"]
            enc_times = [perf.get((t, "encrypt"), 0) for t in tasks_list]
            dec_times = [perf.get((t, "decrypt"), 0) for t in tasks_list]

            if all(v == 0 for v in enc_times + dec_times):
                continue

            x = np.arange(len(tasks_list))
            width = 0.35
            fig, ax = plt.subplots(figsize=(8, 5))
            bars1 = ax.bar(x - width / 2, enc_times, width,
                           label="Encrypt", color="#4CAF50")
            bars2 = ax.bar(x + width / 2, dec_times, width,
                           label="Decrypt", color="#F44336")
            ax.set_ylabel("Time (ms)")
            ax.set_title(f"Performance — {mode_label}")
            ax.set_xticks(x)
            ax.set_xticklabels(task_labels)
            ax.legend()
            ax.set_yscale('log')
            ax.bar_label(bars1, fmt='%.0f', fontsize=8)
            ax.bar_label(bars2, fmt='%.0f', fontsize=8)
            plt.tight_layout()
            plt.savefig(os.path.join(PLOTS, f"performance_{mode}.png"), dpi=150)
            plt.close()

    fig, ax = plt.subplots(figsize=(8, 5))
    task_names = [n for n in images]
    for ci, (ch_name, color) in enumerate(zip(CHANNELS, colors)):
        ents = []
        for name in task_names:
            vals = [float(m[3]) for m in metrics
                    if m[0] == name and m[1] == "entropy" and m[2] == ch_name]
            ents.append(vals[0] if vals else 0)
        x = np.arange(len(task_names))
        ax.bar(x + ci * 0.25, ents, 0.25, label=ch_name, color=color, alpha=0.7)
    ax.set_ylabel("Entropy (bits)")
    ax.set_title("Shannon Entropy per Channel")
    ax.set_xticks(np.arange(len(task_names)) + 0.25)
    ax.set_xticklabels([LABELS.get(n, n) for n in task_names])
    ax.legend()
    ax.set_ylim(6, 8.1)
    ax.axhline(y=8.0, color='black', linestyle='--', alpha=0.3, label='Ideal (8.0)')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS, "entropy.png"), dpi=150)
    plt.close()

    fig, axes = plt.subplots(1, len(images), figsize=(4 * len(images), 4))
    if len(images) == 1:
        axes = [axes]
    for ax, (name, pix) in zip(axes, images.items()):
        ax.imshow(pix)
        ax.set_title(LABELS.get(name, name))
        ax.axis('off')
    plt.suptitle("Visual Comparison", fontsize=14)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS, "visual_comparison.png"), dpi=150)
    plt.close()

    print(f"Plots saved to {PLOTS}")
    print("Done.")


if __name__ == "__main__":
    main()
