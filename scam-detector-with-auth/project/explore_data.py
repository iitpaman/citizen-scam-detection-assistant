import pandas as pd

# Load the first dataset (SMS Spam Collection - TSV)
df = pd.read_csv("sms_spam.tsv", sep="\t", header=None, names=["label", "text"])
print(f"Total messages: {len(df)}")
print(df["label"].value_counts())
print(df.head(5))

# Load the Kaggle Indian SMS dataset
df2 = pd.read_csv("spam_ham_india.csv")
print(df2.columns)
print(df2["Label"].value_counts())
print(df2.head(5))

# Rename Kaggle columns to match the first dataset
df2 = df2.rename(columns={"Msg": "text", "Label": "label"})

# Combine both datasets
combined_df = pd.concat([df, df2], ignore_index=True)
print(f"Total combined messages: {len(combined_df)}")
print(combined_df["label"].value_counts())