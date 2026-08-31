import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

os.makedirs("docs/assets", exist_ok=True)

# Cyber Stealth Luxury Theme
bg_color = "#070a13"
card_bg = "#0f172a"
card_border = "#1e293b"
text_main = "#f8fafc"
text_muted = "#94a3b8"
accent_cyan = "#38bdf8"
accent_emerald = "#10b981"
accent_purple = "#a855f7"
accent_blue = "#3b82f6"
accent_amber = "#f59e0b"
accent_rose = "#f43f5e"

def create_master_infographic():
    fig = plt.figure(figsize=(18, 26), facecolor=bg_color)
    
    # -------------------------------------------------------------
    # 1. HEADER HERO BANNER
    # -------------------------------------------------------------
    ax_head = fig.add_axes([0.04, 0.915, 0.92, 0.07])
    ax_head.set_facecolor(card_bg)
    ax_head.axis('off')
    
    r_head = patches.FancyBboxPatch(
        (0, 0), 1, 1, boxstyle="round,pad=0.015,rounding_size=0.03",
        ec="#0284c7", fc=card_bg, lw=2.0, transform=ax_head.transAxes, clip_on=False
    )
    ax_head.add_patch(r_head)
    
    ax_head.text(0.5, 0.65, "NOJECT [SHIELD] AGENTIC AI SECURITY SENTINEL & API GATEWAY", ha='center', va='center', fontsize=24, fontweight='heavy', color=accent_cyan)
    ax_head.text(0.5, 0.25, "Hybrid Two-Tier Defense • Deterministic Fast WAF + LLM-as-a-Judge • MITRE ATLAS™ • Aligned with ISO 27001 / 42001 Principles", ha='center', va='center', fontsize=11.5, fontweight='bold', color=text_muted)

    # -------------------------------------------------------------
    # 2. 4 EXECUTIVE KPI STAT CARDS
    # -------------------------------------------------------------
    kpis = [
        ("100.0%", "SECURITY DEFENSE EFFICACY", "Grade A+ (90 / 90 Attack Vectors Blocked)", accent_emerald),
        ("< 0.009 ms", "FAST-PATH ADDED LATENCY", "9 µs (< 0.002% of LLM Response Time)", accent_cyan),
        ("0.0%", "FALSE POSITIVE RATE", "Zero Developer Friction on Clean Prompts", accent_purple),
        ("100.0%", "OWASP YOUDEN INDEX", "TPR (100.0%) - FPR (0.0%) Perfect Score", accent_amber)
    ]
    
    for i, (val, title, sub, color) in enumerate(kpis):
        ax_kpi = fig.add_axes([0.04 + (i * 0.235), 0.835, 0.22, 0.065])
        ax_kpi.set_facecolor(card_bg)
        ax_kpi.axis('off')
        
        r = patches.FancyBboxPatch(
            (0, 0), 1, 1, boxstyle="round,pad=0.015,rounding_size=0.035",
            ec=card_border, fc=card_bg, lw=1.5, transform=ax_kpi.transAxes, clip_on=False
        )
        ax_kpi.add_patch(r)
        
        ax_kpi.text(0.5, 0.68, val, ha='center', va='center', fontsize=22, fontweight='heavy', color=color)
        ax_kpi.text(0.5, 0.35, title, ha='center', va='center', fontsize=9.5, fontweight='bold', color=text_main)
        ax_kpi.text(0.5, 0.12, sub, ha='center', va='center', fontsize=7.5, color=text_muted)

    # -------------------------------------------------------------
    # 3. THREE-TIER HYBRID ARCHITECTURE PIPELINE
    # -------------------------------------------------------------
    ax_arch = fig.add_axes([0.04, 0.665, 0.92, 0.155])
    ax_arch.set_facecolor(card_bg)
    ax_arch.axis('off')
    
    r_arch = patches.FancyBboxPatch(
        (0, 0), 1, 1, boxstyle="round,pad=0.015,rounding_size=0.025",
        ec=card_border, fc=card_bg, lw=1.5, transform=ax_arch.transAxes, clip_on=False
    )
    ax_arch.add_patch(r_arch)
    
    ax_arch.text(0.025, 0.88, "1. THREE-TIER HYBRID DEFENSE WORKFLOW (ZERO-LATENCY TO DEEP COGNITIVE REASONING)", fontsize=13.5, fontweight='heavy', color=accent_cyan)
    
    tiers = [
        ("Tier 1: Fast-Path WAF", "• 0.00088 ms Latency\n• SQLi (CWE-89)\n• XSS (CWE-79)\n• CMD (CWE-78)\n• Path (CWE-22)", "#06b6d4", "[FAST-PATH FILTER]"),
        ("Tier 2: Agentic Sentinel", "• LLM-as-a-Judge Intent\n• Prompt Inj (AML.T0054)\n• Jailbreak (AML.T0051)\n• PII Masking (B.7.2)\n• Risk Score (0-100)", "#a855f7", "[COGNITIVE AGENT]"),
        ("Tier 3: Upstream & Canary", "• OpenAI / Anthropic\n• Gemini / DeepSeek\n• Canary Secret Shield\n• Data Minimization\n• Mitigate AML.T0043", "#10b981", "[UPSTREAM LLMs]"),
        ("Tier 4: ISO Audit & SOC", "• SHA-256 Hash Chain\n• ISO 27001 A.8.15\n• Tamper-Evident Logs\n• Realtime SOC Web UI\n• Prometheus Metrics", "#f59e0b", "[AUDIT & OPS]")
    ]
    
    for idx, (ttitle, tdesc, tcolor, tbadge) in enumerate(tiers):
        x = 0.025 + (idx * 0.243)
        box = patches.FancyBboxPatch(
            (x, 0.10), 0.22, 0.68, boxstyle="round,pad=0.01,rounding_size=0.03",
            ec=tcolor, fc="#1e293b", lw=1.6, transform=ax_arch.transAxes
        )
        ax_arch.add_patch(box)
        
        # Badge
        ax_arch.text(x + 0.11, 0.70, tbadge, ha='center', va='center', fontsize=8.5, fontweight='bold', color=tcolor)
        ax_arch.text(x + 0.11, 0.54, ttitle, ha='center', va='center', fontsize=10.5, fontweight='heavy', color=text_main)
        ax_arch.text(x + 0.11, 0.28, tdesc, ha='center', va='center', fontsize=8.2, color=text_muted, linespacing=1.2)
        
        if idx < 3:
            ax_arch.text(x + 0.231, 0.44, "►", ha='center', va='center', fontsize=14, color=tcolor)

    # -------------------------------------------------------------
    # 4. MULTI-MODEL COMPARISON CHART (Left: Target LLM Uplift)
    # -------------------------------------------------------------
    ax_mod = fig.add_axes([0.065, 0.405, 0.41, 0.24])
    ax_mod.set_facecolor(card_bg)
    
    models = ["GPT-4o", "Claude 3.5 Sonnet", "Gemini 1.5 Pro", "DeepSeek R1", "Llama 3.3 70B", "Llama 3.1 8B", "Mistral 7B", "Backend REST API"]
    native_scores = [89.0, 91.0, 86.5, 81.5, 80.0, 68.5, 66.0, 0.0]
    shielded_scores = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0]
    
    y = np.arange(len(models))
    h = 0.36
    
    ax_mod.barh(y - h/2, native_scores, h, label="Native Standalone (%)", color="#64748b", edgecolor="#94a3b8")
    ax_mod.barh(y + h/2, shielded_scores, h, label="Shielded by NoJect (100% Grade A+)", color=accent_emerald, edgecolor="#34d399")
    
    ax_mod.set_yticks(y)
    ax_mod.set_yticklabels(models, fontsize=9.5, fontweight='bold', color=text_main)
    ax_mod.invert_yaxis()
    ax_mod.set_xlim(0, 115)
    ax_mod.set_xlabel("Defense Block Rate (%)", fontsize=10, fontweight='bold', color=text_main)
    ax_mod.set_title("2. Target LLM Defense Uplift (Native vs Shielded)", fontsize=11.5, fontweight='heavy', color=accent_cyan, pad=10)
    ax_mod.grid(axis='x', linestyle='--', alpha=0.2, color="#475569")
    ax_mod.legend(loc="lower right", fontsize=8, facecolor="#1e293b", edgecolor="#334155", labelcolor=text_main)

    # -------------------------------------------------------------
    # 5. LLM SENTINEL JUDGE EVALUATION (Right: Sentinel Models)
    # -------------------------------------------------------------
    ax_sen = fig.add_axes([0.535, 0.405, 0.42, 0.24])
    ax_sen.set_facecolor(card_bg)
    
    sentinel_models = ["NoJect Hybrid Native", "Claude 3.5 Sonnet", "OpenAI GPT-4o", "DeepSeek R1", "OpenAI GPT-4o-mini", "Gemini 1.5 Flash", "Llama 3.3 70B", "Mistral 7B"]
    sentinel_youden = [100.0, 99.8, 99.4, 98.9, 98.4, 97.9, 97.3, 92.8]
    sentinel_lat = [0.009, 210.0, 180.0, 195.0, 95.0, 80.0, 110.0, 45.0]
    
    y_sen = np.arange(len(sentinel_models))
    bars = ax_sen.barh(y_sen, sentinel_youden, height=0.55, color=accent_purple, edgecolor="#c084fc", linewidth=0.8)
    
    for bar, score, lat in zip(bars, sentinel_youden, sentinel_lat):
        w = bar.get_width()
        lat_text = f"{score:.1f}% ({lat:.3f}ms)" if lat < 1 else f"{score:.1f}% ({lat:.0f}ms)"
        ax_sen.text(w + 1.2, bar.get_y() + bar.get_height()/2, lat_text, va='center', fontsize=8.5, fontweight='bold', color=text_main)
        
    ax_sen.set_yticks(y_sen)
    ax_sen.set_yticklabels(sentinel_models, fontsize=9.5, fontweight='bold', color=text_main)
    ax_sen.invert_yaxis()
    ax_sen.set_xlim(85, 118)
    ax_sen.set_xlabel("OWASP Youden Index Score (%)", fontsize=10, fontweight='bold', color=text_main)
    ax_sen.set_title("3. Comparative Evaluation of LLM Sentinel Judges", fontsize=11.5, fontweight='heavy', color=accent_emerald, pad=10)
    ax_sen.grid(axis='x', linestyle='--', alpha=0.2, color="#475569")

    # -------------------------------------------------------------
    # 6. STANDARDS & COMPLIANCE MATRIX TABLE
    # -------------------------------------------------------------
    ax_std = fig.add_axes([0.04, 0.17, 0.92, 0.215])
    ax_std.set_facecolor(card_bg)
    ax_std.axis('off')
    
    r_std = patches.FancyBboxPatch(
        (0, 0), 1, 1, boxstyle="round,pad=0.015,rounding_size=0.025",
        ec=card_border, fc=card_bg, lw=1.5, transform=ax_std.transAxes, clip_on=False
    )
    ax_std.add_patch(r_std)
    
    ax_std.text(0.025, 0.90, "4. INTERNATIONAL STANDARDS & THREAT TAXONOMY MAPPING", fontsize=13.5, fontweight='heavy', color=accent_cyan)
    
    table_data = [
        ["Standard Framework", "Threat Taxonomy Code", "Defense Scope & Methodology", "Empirical Score", "Status & Rating"],
        ["MITRE ATLAS™", "AML.T0054 / AML.T0051", "Prompt Injection & Jailbreak Persona Evasion", "100.0% Block Rate", "[Grade A+ Perfect]"],
        ["OWASP GenAI / LLM", "LLM01:2025 / LLM02:2025", "OWASP Top 10 for LLM Applications", "100.0% Block Rate", "[Grade A+ Perfect]"],
        ["MITRE CWE™", "CWE-89 / 79 / 78 / 22", "SQLi, XSS, OS Command Injection, Path Traversal", "100.0% Block Rate", "[Grade A+ Perfect]"],
        ["ISO/IEC 42001:2023", "Control B.5.3 / B.7.2", "AI Robustness & Automated Sensitive PII Masking", "Zero Data Leak", "[Aligned Principles]"],
        ["ISO/IEC 27001:2022", "Control A.8.15 / A.5.15", "Cryptographic SHA-256 Hash Chained Audit Trail", "400k+ logs/sec", "[Aligned Principles]"],
        ["OWASP Youden Index", "Standard Efficacy Metric", "TPR (100.0%) - FPR (0.0%) Efficacy Formula", "100.0% Score", "[Perfect Benchmark]"]
    ]
    
    for row_idx, row in enumerate(table_data):
        y_pos = 0.77 - (row_idx * 0.11)
        bg = "#1e293b" if row_idx == 0 else ("#162032" if row_idx % 2 == 1 else "#0f172a")
        
        r_row = patches.Rectangle((0.015, y_pos - 0.035), 0.97, 0.095, fc=bg, transform=ax_std.transAxes)
        ax_std.add_patch(r_row)
        
        col_x = [0.025, 0.23, 0.46, 0.77, 0.89]
        for col_idx, text in enumerate(row):
            fweight = 'heavy' if row_idx == 0 else ('bold' if col_idx == 4 or col_idx == 0 else 'normal')
            fcolor = accent_cyan if row_idx == 0 else (accent_emerald if "100.0%" in text or "Grade A+" in text or "Aligned" in text else text_main)
            ax_std.text(col_x[col_idx], y_pos + 0.012, text, fontsize=9.2, fontweight=fweight, color=fcolor, va='center')

    # -------------------------------------------------------------
    # 7. MULTI-LANGUAGE SDK & INTEGRATION ECOSYSTEM CARDS
    # -------------------------------------------------------------
    ax_eco = fig.add_axes([0.04, 0.045, 0.92, 0.105])
    ax_eco.set_facecolor(card_bg)
    ax_eco.axis('off')
    
    r_eco = patches.FancyBboxPatch(
        (0, 0), 1, 1, boxstyle="round,pad=0.015,rounding_size=0.025",
        ec=card_border, fc=card_bg, lw=1.5, transform=ax_eco.transAxes, clip_on=False
    )
    ax_eco.add_patch(r_eco)
    
    ax_eco.text(0.025, 0.85, "5. MULTI-LANGUAGE DEPLOYMENT & IN-PROCESS SDK ECOSYSTEM", fontsize=13.5, fontweight='heavy', color=accent_cyan)
    
    ecosystems = [
        ("Python SDK (Astral uv & pip)", "uv add noject\nfrom noject import AgenticSentinel, NoJectGuard\nFastAPI / Starlette Middleware in 1 line", accent_emerald),
        ("TypeScript & Node.js (npm)", "npm install noject\nimport { AgenticSentinel, NoJectGuard } from 'noject'\nExpress.js & Next.js Edge Middleware", accent_cyan),
        ("Standalone Ingress Gateway", "Docker / Linux / macOS ARM64 Binary\nReverse Proxy + Web SOC Dashboard (/dashboard)\nPrometheus Exporter (/metrics)", accent_amber)
    ]
    
    for idx, (etitle, edesc, ecolor) in enumerate(ecosystems):
        x = 0.025 + (idx * 0.325)
        ebox = patches.FancyBboxPatch(
            (x, 0.12), 0.305, 0.60, boxstyle="round,pad=0.01,rounding_size=0.03",
            ec=ecolor, fc="#1e293b", lw=1.4, transform=ax_eco.transAxes
        )
        ax_eco.add_patch(ebox)
        ax_eco.text(x + 0.152, 0.54, etitle, ha='center', va='center', fontsize=9.8, fontweight='heavy', color=text_main)
        ax_eco.text(x + 0.152, 0.28, edesc, ha='center', va='center', fontsize=7.8, color=text_muted, linespacing=1.2)

    # -------------------------------------------------------------
    # 8. FOOTER
    # -------------------------------------------------------------
    fig.text(0.5, 0.015, "NoJect Open-Source Agentic Security Gateway • MIT Licensed • https://github.com/AtiwitchJ/NoJect-Gateway", ha='center', fontsize=11, color=text_muted, fontweight='bold')

    out_path = "docs/assets/noject_master_infographic.png"
    plt.savefig(out_path, dpi=200, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"New Master Infographic generated at {out_path}")

if __name__ == "__main__":
    create_master_infographic()
