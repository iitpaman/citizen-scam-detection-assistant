import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# Load and combine both datasets (jo tumne explore_data.py mein kiya tha, wahi yahan bhi)
df = pd.read_csv("sms_spam.tsv", sep="\t", header=None, names=["label", "text"])
df2 = pd.read_csv("spam_ham_india.csv")
df2 = df2.rename(columns={"Msg": "text", "Label": "label"})
combined_df = pd.concat([df, df2], ignore_index=True)
print(f"Total messages: {len(combined_df)}")

combined_df = combined_df.dropna(subset=["text"])
print(f"Total messages after removing empty ones: {len(combined_df)}")

# TODO 1: Data ko train aur test mein baato
X_train, X_test, y_train, y_test = train_test_split(
    combined_df["text"], combined_df["label"], test_size=0.2, random_state=42
)

# TODO 2: TF-IDF vectorizer banao aur text ko numbers mein convert karo
vectorizer = TfidfVectorizer(stop_words="english")
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# TODO 3: Logistic Regression model banao aur train karo
model = LogisticRegression(class_weight="balanced")
model.fit(X_train_vec, y_train)

# TODO 4: Model ko test karo aur accuracy dekho
y_pred = model.predict(X_test_vec)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(classification_report(y_test, y_pred))

import pickle

with open("model.pkl", "wb") as f:
    pickle.dump(model, f)
with open("vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("Model saved!")