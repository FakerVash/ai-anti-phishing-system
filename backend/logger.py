import os
import json
import datetime

def ensure_log_dir():
    """Ensures that the logs directory exists."""
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    return log_dir

def log_analysis(data):
    """
    Logs the analysis result to a daily JSONL file.
    Updates existing entries for the same URL and saves only essential info.
    """
    try:
        log_dir = ensure_log_dir()
        today = datetime.date.today().isoformat()
        log_file = os.path.join(log_dir, f"analysis_{today}.jsonl")
        
        # 1. Simplify data
        simple_entry = {
            "url": data.get("url"),
            "status": data.get("status"),
            "reason": data.get("reason"),
            "ai_risk": data.get("ai_risk_level", "Unknown"),
            "timestamp": data.get("timestamp") or datetime.datetime.now().isoformat()
        }
        
        # 2. Read existing logs
        entries = []
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        
        # 3. Update or Append
        url_found = False
        for i, entry in enumerate(entries):
            if entry.get("url") == simple_entry["url"]:
                entries[i] = simple_entry  # Update existing
                url_found = True
                break
        
        if not url_found:
            entries.append(simple_entry)
            
        # 4. Rewrite file
        with open(log_file, "w", encoding="utf-8") as f:
            for entry in entries:
                json.dump(entry, f, ensure_ascii=False)
                f.write("\n")
            
        print(f"📝 Analysis logged/updated in {log_file}")
        return True
    except Exception as e:
        print(f"❌ Error logging analysis: {e}")
        return False
