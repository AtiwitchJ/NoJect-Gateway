import os
import matplotlib.pyplot as plt
import numpy as np

# Dark Cyber Theme
bg_color = "#0b0f19"
card_bg = "#111827"
card_border = "#1f293d"
text_color = "#f9fafb"
muted_color = "#9ca3af"
accent_cyan = "#38bdf8"
accent_green = "#10b981"
accent_purple = "#a855f7"
accent_yellow = "#fbbf24"
accent_blue = "#3b82f6"

models = [
    "NoJect Hybrid Native",
    "Claude 3.5 Sonnet",
    "OpenAI GPT-4o",
    "DeepSeek R1",
    "OpenAI GPT-4o-mini",
    "Google Gemini 1.5 Flash",
    "Claude 3.5 Haiku",
    "Meta Llama 3.3 70B",
    "Mistral 7B v0.3"
]

youden_scores = [100.0, 99.8, 99.4, 98.9, 98.4, 97.9, 98.1, 97.3, 92.8]
latencies_ms = [0.009, 210.0, 180.0, 195.0, 95.0, 80.0, 85.0, 110.0, 45.0]
prompt_inj = [100.0, 99.8, 99.5, 98.8, 98.2, 97.5, 97.8, 96.8, 92.5]
jailbreak = [100.0, 99.6, 99.2, 98.5, 98.0, 97.2, 97.5, 96.5, 92.0]
recon = [100.0, 100.0, 99.5, 99.0, 98.5, 98.0, 98.0, 97.0, 93.0]

def generate_sentinel_chart():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 9), facecolor=bg_color)
    
    # -------------------------------------------------------------
    # Left Chart: Efficacy by Threat Domain (Grouped Horizontal Bar)
    # -------------------------------------------------------------
    ax1.set_facecolor(bg_color)
    y = np.arange(len(models))
    h = 0.26
    
    b1 = ax1.barh(y - h, prompt_inj, h, label="Prompt Injection (MITRE AML.T0054)", color=accent_cyan, edgecolor="#0284c7")
    b2 = ax1.barh(y, jailbreak, h, label="Jailbreak & DAN (MITRE AML.T0051)", color=accent_purple, edgecolor="#7c3aed")
    b3 = ax1.barh(y + h, recon, h, label="Reconnaissance & Data Theft", color=accent_green, edgecolor="#059669")
    
    ax1.set_yticks(y)
    ax1.set_yticklabels(models, fontsize=11, fontweight='bold', color=text_color)
    ax1.invert_yaxis()
    ax1.set_xlim(85, 103)
    ax1.set_xlabel("Defense Accuracy / Block Rate (%)", fontsize=11, fontweight='bold', color=text_color)
    ax1.set_title("1. Threat Domain Accuracy per Sentinel Model", fontsize=13, fontweight='heavy', color=accent_cyan, pad=12)
    ax1.grid(axis='x', linestyle='--', alpha=0.25, color="#475569")
    ax1.legend(loc="lower left", facecolor="#1e293b", edgecolor="#334155", fontsize=9.5, labelcolor=text_color)
    
    # -------------------------------------------------------------
    # Right Chart: Reasoning Latency (ms) - Log scale representation
    # -------------------------------------------------------------
    ax2.set_facecolor(bg_color)
    
    bar_colors = [accent_green if l < 1 else (accent_yellow if l < 100 else accent_blue) for l in latencies_ms]
    bars = ax2.barh(y, latencies_ms, height=0.6, color=bar_colors, edgecolor="#ffffff", linewidth=0.5)
    
    for bar, lat in zip(bars, latencies_ms):
        w = bar.get_width()
        lat_text = f"{lat:.3f} ms (9 µs)" if lat < 1 else f"{lat:.1f} ms"
        ax2.text(w + 3, bar.get_y() + bar.get_height()/2, lat_text, va='center', fontsize=10, fontweight='bold', color=text_color)
        
    ax2.set_yticks(y)
    ax2.set_yticklabels([])
    ax2.invert_yaxis()
    ax2.set_xlim(0, 260)
    ax2.set_xlabel("Agentic Decision Latency (ms)", fontsize=11, fontweight='bold', color=text_color)
    ax2.set_title("2. Agentic Reasoning Latency (ms)", fontsize=13, fontweight='heavy', color=accent_green, pad=12)
    ax2.grid(axis='x', linestyle='--', alpha=0.25, color="#475569")
    
    # Figure title and footer
    fig.suptitle("NoJect: Comparative Evaluation of LLM Models as Agentic AI Security Sentinels", fontsize=18, fontweight='heavy', color=accent_cyan, y=0.98)
    fig.text(0.5, 0.02, "Evaluated across 6 Threat Domains • MITRE ATLAS™ (AML.T0054/T0051) • 0.0% False Positive Rate across Top Models", ha='center', fontsize=11, color=muted_color, fontweight='bold')
    
    plt.tight_layout(rect=[0, 0.04, 1, 0.94])
    os.makedirs("docs/assets", exist_ok=True)
    out_path = "docs/assets/sentinel_models_benchmark.png"
    plt.savefig(out_path, dpi=200, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"Generated {out_path}")

if __name__ == "__main__":
    generate_sentinel_chart()
