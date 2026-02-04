import pandas as pd

def load_phishing_data(csv_path):
    data = pd.read_csv(csv_path)

    data = data[["url", "target", "phish_detail_url"]]
    data["url"] = data["url"].str.lower().str.strip()

    phishing_urls = set(data["url"].dropna())

    return data, phishing_urls
