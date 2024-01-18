# Standard library imports
import os
import warnings

# Third-party library imports
import numpy as np
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging

# External module imports
from pydantic import BaseModel
from url_feature_extractor import UrlFeatureExtractor


warnings.filterwarnings("ignore", category=UserWarning)

app = FastAPI()

model = joblib.load("./model/modelv3.joblib")


class RequestUrl(BaseModel):
    url: str
    threshold: float


class PhishingResponse(BaseModel):
    url: str
    prediction: str
    threshold: float


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)


async def get_extc_url_features(url):
    url_feat_extractor = UrlFeatureExtractor()
    url_feat_extractor.set_url(url)

    features = url_feat_extractor.get_url_features()
    return features


@app.post("/predict")
async def predict(request_url: RequestUrl, response_model=PhishingResponse):
    raw_url = request_url.url
    threshold = request_url.threshold

    try:
        url_features = await get_extc_url_features(raw_url)

        features = np.array(url_features).reshape(1, -1)
        prediction = model.predict(features)

        binary_prediction = ((prediction > threshold).astype(int)).tolist()
        prediction = "legitimate" if 0 in binary_prediction else "phishing"

        response = PhishingResponse(
            url=raw_url, prediction=prediction, threshold=threshold
        )

        return response

    except Exception as e:
        logging.error(f"An exception occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
