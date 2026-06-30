import pandas as pd
from datetime import datetime
import os


def generate_excel_report(results, output_dir="output"):
    """
    Generate Excel report for AuthRecon results.
    """

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(output_dir, f"AuthRecon_Report_{timestamp}.xlsx")

    # Normalize results
    rows = []

    for r in results:
        rows.append({
            "URL": r.get("url"),
            "Status": r.get("status_code"),
            "Auth Provider": r.get("provider"),
            "Protocol": r.get("protocol"),
            "Confidence": r.get("confidence"),
            "Redirects": " | ".join(r.get("redirect_chain", [])),
            "Title": r.get("title", ""),
        })

    df = pd.DataFrame(rows)

    # Create Excel writer
    with pd.ExcelWriter(file_path, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="AuthRecon Results", index=False)

        # Summary sheet
        summary = pd.DataFrame([
            {
                "Total URLs": len(df),
                "Unique Providers": df["Auth Provider"].nunique(),
                "High Confidence (>80)": len(df[df["Confidence"] > 80])
            }
        ])

        summary.to_excel(writer, sheet_name="Summary", index=False)

    print(f"[+] Excel report generated: {file_path}")

    return file_path