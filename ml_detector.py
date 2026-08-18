from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# Training examples
TRAINING_TEXTS = [
    # Scam / phishing messages
    "Your account has been suspended verify immediately",
    "Urgent click this link and enter your password",
    "Congratulations you won a prize claim now",
    "Send your OTP to verify your bank account",
    "Your payment failed login to confirm your details",
    "Your bank account will be closed act now",
    "Verify your account immediately to avoid suspension",
    "Enter your card number to receive your refund",

    # Normal messages
    "Hey, are we still meeting tomorrow?",
    "Please send me the project report",
    "The meeting is scheduled for 10 AM",
    "I changed my password yesterday",
    "Can you call me when you are free?",
    "The payment for the order was completed",
    "Please send the document when you have time",
    "Our team meeting is scheduled for Monday"
]


# 1 = suspicious
# 0 = normal
TRAINING_LABELS = [
    1, 1, 1, 1,
    1, 1, 1, 1,

    0, 0, 0, 0,
    0, 0, 0, 0
]


# Convert text into numerical features
vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(TRAINING_TEXTS)


# Create machine-learning model
model = LogisticRegression(
    max_iter=1000
)


# Train the model
model.fit(X, TRAINING_LABELS)


def analyze_with_ai(text):

    if not isinstance(text, str) or not text.strip():
        return {
            "ai_score": 0,
            "ai_risk": "UNKNOWN",
            "confidence": 0
        }

    # Convert the message into TF-IDF features
    text_vector = vectorizer.transform([text])

    # Probability that the message is suspicious
    probability = model.predict_proba(text_vector)[0][1]

    ai_score = round(probability * 100)

    # Determine AI risk
    if ai_score >= 70:
        ai_risk = "HIGH"

    elif ai_score >= 40:
        ai_risk = "MEDIUM"

    else:
        ai_risk = "LOW"

    # Calculate confidence
    confidence = round(
        max(probability, 1 - probability) * 100
    )

    return {
        "ai_score": ai_score,
        "ai_risk": ai_risk,
        "confidence": confidence
    }


# Test the AI when this file is run directly
if __name__ == "__main__":

    test_message = (
        "URGENT! Your bank account is suspended. "
        "Enter your OTP immediately."
    )

    result = analyze_with_ai(test_message)

    print("TrustGuard AI Test")
    print("------------------")
    print("AI Score:", result["ai_score"])
    print("AI Risk:", result["ai_risk"])
    print("Confidence:", result["confidence"])
