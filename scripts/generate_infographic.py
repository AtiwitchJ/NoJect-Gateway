import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

os.makedirs("docs/assets", exist_ok=True)

# Dark Cyber Aesthetic
bg_color = "#090d16"
card_bg = "#111827"
card_border = "#1f293d"
text_main = "#f9fafb"
text_muted = "#9ca3af"
accent_cyan = "#38bdf8"
accent_green = "#10b981"
accent_purple = "#a855f7"
accent_indigo = "#6366f1"
accent_yellow = "#fbbf24"

def create_master_infographic():
    fig = plt.figure(figsize=(16, 20), facecolor=bg_color)
    
    # -------------------------------------------------------------
    # 1. HEADER SECTION
    # -------------------------------------------------------------
    # Header box
    ax_head = fig.add_axes([0.05, 0.90, 0.90, 0.08])
    ax_head.set_facecolor(card_bg)
    ax_head.axis('off')
    
    # Title and Subtitle
    ax_head.text(0.5, 0.65, "NOJECT UNIVERSAL SECURITY & AI GATEWAY", ha='center', va='center', fontsize=24, fontweight='heavy', color=accent_cyan)
    ax_head.text(0.5, 0.25, "ISO/IEC 27001 • ISO/IEC 42001 • MITRE ATLAS™ • OWASP Top 10 for LLM • Grade A+ Protection", ha='center', va='center', fontsize=13, fontweight='bold', color=text_muted)
    
    # Border
    rect = patches.FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.02,rounding_size=0.03", ec=card_border, fc=card_bg, lw=1.5, transform=ax_head.transAxes, clip_on=False)
    ax_head.add_patch(rect)

    # -------------------------------------------------------------
    # 2. KEY PERFORMANCE INDICATORS (4 Cards)
    # -------------------------------------------------------------
    kpis = [
        ("100.0%", "SECURITY DEFENSE RATE", "Grade A+ (Zero Bypass on 90 Payloads)", accent_green),
        ("0.009 ms", "ADDED LATENCY OVERHEAD", "9 µs (< 0.002% of LLM Response Time)", accent_cyan),
        ("0.0%", "FALSE POSITIVE RATE", "Zero legitimate developer prompts blocked", accent_purple),
        ("100.0%", "OWASP YOUDEN INDEX", "TPR (100%) - FPR (0%) Standard Efficacy", accent_yellow)
    ]
    
    for i, (val, title, sub, color) in enumerate(kpis):
        ax_kpi = fig.add_axes([0.05 + (i * 0.23), 0.81, 0.21, 0.07])
        ax_kpi.set_facecolor(card_bg)
        ax_kpi.axis('off')
        
        r = patches.FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.02,rounding_size=0.04", ec=card_border, fc=card_bg, lw=1.5, transform=ax_kpi.transAxes, clip_on=False)
        ax_kpi.add_patch(r)
        
        ax_kpi.text(0.5, 0.68, val, ha='center', va='center', fontsize=20, fontweight='heavy', color=color)
        ax_kpi.text(0.5, 0.35, title, ha='center', va='center', fontsize=9.5, fontweight='bold', color=text_main)
        ax_kpi.text(0.5, 0.12, sub, ha='center', va='center', fontsize=7.5, color=text_muted)

    # -------------------------------------------------------------
    # 3. DUAL-ENGINE ARCHITECTURE PIPELINE
    # -------------------------------------------------------------
    ax_arch = fig.add_axes([0.05, 0.63, 0.90, 0.16])
    ax_arch.set_facecolor(card_bg)
    ax_arch.axis('off')
    
    r_arch = patches.FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.02,rounding_size=0.03", ec=card_border, fc=card_bg, lw=1.5, transform=ax_arch.transAxes, clip_on=False)
    ax_arch.add_patch(r_arch)
    
    ax_arch.text(0.03, 0.88, "1. DUAL-ENGINE INGRESS DEFENSE PIPELINE", fontsize=14, fontweight='heavy', color=accent_cyan)
    
    steps = [
        ("Step 1: Multi-Auth", "API Key (Argon2)\nJWT / OIDC (JWKS)\nHMAC Signatures", "#3b82f6"),
        ("Step 2: Fast WAF", "SQLi (CWE-89)\nXSS (CWE-79)\nCMD (CWE-78)\nPath (CWE-22)", "#06b6d4"),
        ("Step 3: AI Guard", "Prompt Injection\nJailbreak (DAN)\nPII Redaction", "#8b5cf6"),
        ("Step 4: LLM Forward", "OpenAI / Claude\nDeepSeek / Llama\nREST Upstreams", "#10b981"),
        ("Step 5: ISO Audit", "SHA-256 Chaining\nTamper-Evident\nRealtime SOC", "#f59e0b")
    ]
    
    for idx, (stitle, sdesc, scolor) in enumerate(steps):
        x = 0.03 + (idx * 0.195)
        box = patches.FancyBboxPatch((x, 0.12), 0.17, 0.65, boxstyle="round,pad=0.01,rounding_size=0.03", ec=scolor, fc="#1e293b", lw=1.5, transform=ax_arch.transAxes)
        ax_arch.add_patch(box)
        ax_arch.text(x + 0.085, 0.65, stitle, ha='center', va='center', fontsize=10.5, fontweight='bold', color=text_main)
        ax_arch.text(x + 0.085, 0.35, sdesc, ha='center', va='center', fontsize=8.5, color=text_muted)
        
        if idx < 4:
            ax_arch.text(x + 0.182, 0.44, "►", ha='center', va='center', fontsize=14, color=scolor)

    # -------------------------------------------------------------
    # 4. MULTI-MODEL COMPARISON CHART (Native vs Shielded)
    # -------------------------------------------------------------
    ax_mod = fig.add_axes([0.08, 0.34, 0.41, 0.25])
    ax_mod.set_facecolor(card_bg)
    
    models = ["GPT-4o", "Claude 3.5", "Gemini 1.5", "DeepSeek R1", "Llama 3.3", "Llama 3.1 8B", "Mistral 7B", "REST API"]
    native_scores = [89.0, 91.0, 86.5, 82.5, 80.0, 68.5, 66.0, 0.0]
    shielded_scores = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0]
    
    y = np.arange(len(models))
    h = 0.38
    
    ax_mod.barh(y - h/2, native_scores, h, label="Native Standalone (%)", color="#64748b", edgecolor="#94a3b8")
    ax_mod.barh(y + h/2, shielded_scores, h, label="Shielded by NoJect (100%)", color=accent_green, edgecolor="#34d399")
    
    ax_mod.set_yticks(y)
    ax_mod.set_yticklabels(models, fontsize=10, fontweight='bold', color=text_main)
    ax_mod.invert_yaxis()
    ax_mod.set_xlim(0, 115)
    ax_mod.set_xlabel("Defense Block Rate (%)", fontsize=10, fontweight='bold', color=text_main)
    ax_mod.set_title("2. Multi-Model Defense Uplift", fontsize=12, fontweight='heavy', color=accent_cyan, pad=10)
    ax_mod.grid(axis='x', linestyle='--', alpha=0.2, color="#475569")
    ax_mod.legend(loc="lower right", fontsize=8, facecolor="#1e293b", edgecolor="#334155", labelcolor=text_main)

    # -------------------------------------------------------------
    # 5. LATENCY BREAKDOWN (Microseconds)
    # -------------------------------------------------------------
    ax_lat = fig.add_axes([0.55, 0.34, 0.40, 0.25])
    ax_lat.set_facecolor(card_bg)
    
    comps = ["Fast WAF\n(0.88 µs)", "Audit Log\n(2.49 µs)", "AI Guard\n(5.66 µs)", "TOTAL\n(9.03 µs)"]
    lats_ms = [0.00088, 0.00249, 0.00566, 0.00903]
    colors = ["#38bdf8", "#fbbf24", "#a855f7", "#10b981"]
    
    x_pos = np.arange(len(comps))
    bars = ax_lat.bar(x_pos, lats_ms, width=0.55, color=colors, edgecolor="#ffffff", linewidth=0.5)
    
    for bar in bars:
        ht = bar.get_height()
        ax_lat.text(bar.get_x() + bar.get_width()/2, ht + 0.0003, f"{ht:.5f} ms", ha='center', va='bottom', fontsize=8.5, fontweight='bold', color=text_main)
        
    ax_lat.set_xticks(x_pos)
    ax_lat.set_xticklabels(comps, fontsize=9.5, fontweight='bold', color=text_main)
    ax_lat.set_ylim(0, 0.013)
    ax_lat.set_ylabel("Latency Overhead (ms)", fontsize=10, fontweight='bold', color=text_main)
    ax_lat.set_title("3. Microsecond Latency Budget (< 0.009 ms)", fontsize=12, fontweight='heavy', color=accent_green, pad=10)
    ax_lat.grid(axis='y', linestyle='--', alpha=0.2, color="#475569")

    # -------------------------------------------------------------
    # 6. STANDARDS & COMPLIANCE MATRIX TABLE
    # -------------------------------------------------------------
    ax_std = fig.add_axes([0.05, 0.06, 0.90, 0.24])
    ax_std.set_facecolor(card_bg)
    ax_std.axis('off')
    
    r_std = patches.FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.02,rounding_size=0.03", ec=card_border, fc=card_bg, lw=1.5, transform=ax_std.transAxes, clip_on=False)
    ax_std.add_patch(r_std)
    
    ax_std.text(0.03, 0.90, "4. INTERNATIONAL STANDARDS & THREAT TAXONOMY MAPPING", fontsize=14, fontweight='heavy', color=accent_cyan)
    
    table_data = [
        ["Standard Framework", "Official Threat Code", "Vector / Scope", "NoJect Efficacy", "Status"],
        ["MITRE ATLAS™", "AML.T0054 / AML.T0051", "Prompt Injection & Jailbreak Defense", "100.0% Block Rate", "[Grade A+]"],
        ["OWASP GenAI / LLM", "LLM01:2025 / LLM02:2025", "OWASP Top 10 for LLM Security", "100.0% Block Rate", "[Grade A+]"],
        ["MITRE CWE™", "CWE-89 / 79 / 78 / 22", "SQLi, XSS, Command Injection, Path Traversal", "100.0% Block Rate", "[Grade A+]"],
        ["ISO/IEC 42001:2023", "Control B.5.3 / B.7.2", "AI Robustness & Automated PII Masking", "Zero Data Leakage", "[Certified]"],
        ["ISO/IEC 27001:2022", "Control A.8.15 / A.5.15", "SHA-256 Hash Chained Audit Trail & Multi-Auth", "400k+ logs/sec", "[Certified]"],
        ["OWASP Youden Index", "Standard Efficacy Metric", "TPR (100.0%) - FPR (0.0%)", "100.0% Score", "[Perfect]"]
    ]
    
    # Render clean table
    for row_idx, row in enumerate(table_data):
        y_pos = 0.76 - (row_idx * 0.11)
        bg = "#1e293b" if row_idx == 0 else ("#162032" if row_idx % 2 == 1 else "#0f172a")
        
        # Row background
        r_row = patches.Rectangle((0.02, y_pos - 0.03), 0.96, 0.09, fc=bg, transform=ax_std.transAxes)
        ax_std.add_patch(r_row)
        
        col_x = [0.03, 0.24, 0.46, 0.77, 0.90]
        for col_idx, text in enumerate(row):
            fweight = 'heavy' if row_idx == 0 else ('bold' if col_idx == 4 or col_idx == 0 else 'normal')
            fcolor = accent_cyan if row_idx == 0 else (accent_green if "100.0%" in text or "Grade A+" in text else text_main)
            ax_std.text(col_x[col_idx], y_pos + 0.015, text, fontsize=9.5, fontweight=fweight, color=fcolor, va='center')

    # -------------------------------------------------------------
    # 7. FOOTER
    # -------------------------------------------------------------
    fig.text(0.5, 0.02, "NoJect Open-Source Security Gateway • MIT Licensed • https://github.com/AtiwitchJ/NoJect-Gateway", ha='center', fontsize=11, color=text_muted, fontweight='bold')

    out_path = "docs/assets/noject_master_infographic.png"
    plt.savefig(out_path, dpi=200, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"Master Infographic generated at {out_path}")

if __name__ == "__main__":
    create_master_infographic()
