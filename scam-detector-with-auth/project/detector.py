import pickle
import re

with open("model.pkl", "rb") as f:
    model = pickle.load(f)
with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

RED_FLAGS = {
    "urgency": r"\b(urgent|immediately|within \d+ hours?|today only|expire[sd]?|block(ed)?|turant|abhi|jaldi)\b",
    "credential_request": r"\b(otp|pin|cvv|password|aadhaar|share your|bhejiye|share karein|batayein)\b",
    "suspicious_link": r"\b(click here|click this link|click the link|verify now|link par click)\b",
    "money_lure": r"\b(won|winner|lottery|prize|congratulations|free recharge|guaranteed|jeet gaye|inaam)\b",
    "payment_pressure": r"\b(pay now|pay rs|registration fee|custom duty|penalty|payment karein)\b",
}

def rule_based_flags(text):
    text_lower = text.lower()
    matched = []
    for flag_name, pattern in RED_FLAGS.items():
        if re.search(pattern, text_lower):
            matched.append(flag_name)
    return matched

def get_matched_words(text):
    """Actual words/phrases that triggered a flag, for highlighting in the UI."""
    words = []
    for pattern in RED_FLAGS.values():
        for m in re.finditer(pattern, text, re.IGNORECASE):
            words.append(m.group())
    return words

def analyze_message(text):
    vec = vectorizer.transform([text])
    ml_pred = model.predict(vec)[0]
    ml_proba = model.predict_proba(vec)[0]
    spam_confidence = ml_proba[list(model.classes_).index("spam")]

    flags = rule_based_flags(text)
    is_risky = (ml_pred == "spam") or (len(flags) >= 2)

    if ml_pred == "spam" and len(flags) >= 1:
        risk_level = "High Risk"
    elif is_risky:
        risk_level = "Suspicious"
    else:
        risk_level = "Likely Safe"

    return risk_level, flags, spam_confidence

if __name__ == "__main__":
    test_message = "Aapka account block ho jayega, turant OTP share karein"
    risk, flags, conf = analyze_message(test_message)
    print(f"Message: {test_message}")
    print(f"Risk Level: {risk} | Confidence: {conf:.2f}")
    print(f"Red flags found: {flags}")
    print(f"Matched words: {get_matched_words(test_message)}")