# Phishing Site Detector API

This API detects whether a URL is a legitimate or phishing attempt, based on the given threshold. It is built using FastAPI and powered by a machine learning model that I specifically trained for this purpose.

## Table of Contents

- [Phishing Site Detector API](#phishing-site-detector-api)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Machine Learning Model](#machine-learning-model)
  - [Dataset](#dataset)
  - [Model](#model)
  - [Training and Testing](#training-and-testing)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Running the API](#running-the-api)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Chrome Extension](#chrome-extension)
- [Note](#note)

## Features

- Accepts a URL and threshold in JSON format.
- Uses machine learning model to predict if the given URL is legitimate or phishing site.
- Returns URL, the prediction, and the threshold used.

## Technologies Used

This API is built using the following tools and technologies:

- **Python**
- **Google Colab**: Platform used for developing and training the machine learning model.
- **FastAPI**: Web framework for building APIs with Python.
- **Postman**: Tool used for testing and documenting the API endpoints.

## Machine Learning Model

The prediction engine behind this API is a machine learning model trained to classify URLs as either "legitimate" or "phishing." Below are details about the dataset and the model:

### Dataset

- **Source**: The dataset was originally sourced from [Mendeley](https://data.mendeley.com/datasets/72ptz43s9v/1) and [Kaggle](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning), but I have manually added more rows to expand the dataset.
- **Features**: The dataset includes various features extracted from URLs, such as:
  - Domain length
  - Presence of special characters
  - URL entropy
  - Whether it uses `https`
- **Size**: The expanded dataset now contains approximately 122,192 entries, with both 61,096 phishing and legitimate URLs.

### Model

- **Algorithm**: The model was built using Random Forest Algorithm.
- **Performance Metrics**:

  - Accuracy: 94.75
  - Precision: 93.8
  - Recall: 95.85
  - F1 Score: 94.82

### Training and Testing

- The dataset was split into training and testing sets using an 80/20 ratio.
- Hyperparameter tuning was performed using RandomizesSearchCV.

## Getting Started

Follow these steps to set up and run the API locally.

### Prerequisites

- Python 3.11.5
- `pip` (Python Package Installer)

### Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/campomanesreyc/phishing-site-detector-api.git
   ```

2. **Navigate to the project directory**

   ```bash
   cd phishing-site-detector-api
   ```

3. **Create a virtual environment**

   ```bash
   python -m venv .venv
   ```

4. **Activate the virtual environment**

   - On Windows

   ```bash
   .venv\Scripts\Activate
   ```

   - On macOS/Linux

   ```bash
   source .venv/bin/activate
   ```

5. **Install the dependencies**

   ```bash
   pip install -r requirements.txt
   ```

## Running the API

To start the API server locally, use the following command:

```bash
uvicorn main:app --reload
```

This will start the API at [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Usage

You can send a POST request to the API endpoint which is [http://127.0.0.1:8000/predict](http://127.0.0.1:8000/predict) with a JSON payload in the following format:

```json
{
  "url": "[the-url-here]",
  "threshold": "[threshold-string-here]"
}
```

The API will return a JSON response like this:

```json
{
  "url": "[the-url-here]",
  "prediction": "legitimate/phishing",
  "threshold": threshold-num-here
}
```

## How It Works

The API utilizes a machine learning model that has been trained to identify phishing sites based on various features extracted from the URL. The prediction is made by comparing the likelihood of the URL being a phishing site with the specified threshold.

## Chrome Extension

This API is also integrated into a Chrome extension that warns the users when they are browsing a phishing site. You can find the Chrome extension repository [here](https://github.com/campomanesreyc/phishing-site-detector-extension)

## Note

This API was previously deployed at [Render](https://render.com/), but due to associated costs, the deployment has been discontinued. This project was developed as part of my Capstone Project during my college studies.
