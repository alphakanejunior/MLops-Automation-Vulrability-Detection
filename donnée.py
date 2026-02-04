import pandas as pd
import great_expectations as ge

df = ge.from_pandas(pd.read_csv("SMSSpamCollection.txt"))

df.expect_column_values_to_not_be_null("label")
df.expect_column_values_to_be_between("age", 0, 120)

results = df.validate()
