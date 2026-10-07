---
language: en
license: mit
tags:
- phishing
- url-classification
- bert
datasets:
- darshan8950/phishing_url_detection_BERT
metrics:
- accuracy
- auc
base_model:
- google-bert/bert-base-uncased
library_name: transformers
---


# BERT Phishing URL Detector

This model is a fine-tuned version of `bert-base-uncased` on a phishing URL classification dataset. It can be used to detect potentially malicious URLs.

## Model description

The model is based on BERT (Bidirectional Encoder Representations from Transformers) and has been fine-tuned for binary classification of URLs as safe or potentially phishing.

## Intended uses & limitations

This model is intended for use in detecting potentially malicious URLs. However, it should not be used as the sole method of protection against phishing attacks. Always use multiple layers of security and exercise caution when dealing with suspicious URLs.

## Training data

The model was trained on a custom dataset of URLs labeled as safe or unsafe. The dataset is available at `darshan8950/phishing_url_classification` on the Hugging Face Hub.

## Training procedure

The model was fine-tuned using the Hugging Face Transformers library. Only the pooling layers were fine-tuned while the base BERT layers were frozen.