import requests

def fetch_feed(url):
    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            return response.text.splitlines()

        else:
            print(f"Failed to fetch feed: {response.status_code}")
            return []

    except Exception as e:
        print(f"Error fetching feed: {e}")
        return []