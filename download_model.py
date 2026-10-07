from huggingface_hub import snapshot_download

model_id = "darshan8950/phishing_url_detection_BERT"
local_dir = "./phishing_model"

snapshot_download(
    repo_id=model_id,
    local_dir=local_dir
)

print("Model downloaded successfully!")
print(f"Model location: {local_dir}")