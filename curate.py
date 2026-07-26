import json
import subprocess
import re

def get_metadata(url):
    try:
        result = subprocess.run(
            ["yt-dlp", "--dump-json", url],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error fetching metadata for {url}: {e}")
        return None

def extract_video_id(url):
    match = re.search(r'v=([a-zA-Z0-9_-]+)', url)
    return match.group(1) if match else url

def filter_and_sort_videos(task):
    urls = task["source_urls"]
    min_dur = task["min_duration_seconds"]
    max_dur = task["max_duration_seconds"]
    req_words = [w.lower() for w in task["required_words"]]
    forb_words = [w.lower() for w in task["forbidden_words"]]
    limit = task["limit"]

    valid_videos = []

    print("Fetching metadata for all videos...")
    for url in urls:
        data = get_metadata(url)
        if not data:
            continue

        duration = data.get("duration", 0) or 0
        title = data.get("title", "") or ""
        description = data.get("description", "") or ""
        upload_date = data.get("upload_date", "") or ""
        video_id = data.get("id") or extract_video_id(url)
        webpage_url = data.get("webpage_url") or url

        # Duration filter
        if not (min_dur <= duration <= max_dur):
            continue

        text_combined = (title + " " + description).lower()

        # Inclusion filter: must contain ALL required words
        if not all(w in text_combined for w in req_words):
            continue

        # Exclusion filter: must NOT contain ANY forbidden word
        if any(w in text_combined for w in forb_words):
            continue

        valid_videos.append({
            "url": webpage_url,
            "upload_date": upload_date,
            "id": video_id
        })

    # Sorting: upload_date DESC, then video_id ASC
    valid_videos.sort(key=lambda x: (-int(x["upload_date"] if x["upload_date"] else 0), x["id"]))

    # Limit results
    final_urls = [v["url"] for v in valid_videos[:limit]]

    return final_urls

if __name__ == "__main__":
    with open("task.json", "r") as f:
        task_data = json.load(f)

    result_urls = filter_and_sort_videos(task_data)
    
    print("\n--- CURATED PLAYLIST (JSON) ---")
    print(json.dumps(result_urls, indent=2))