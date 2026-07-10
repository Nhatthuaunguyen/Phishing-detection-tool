import pandas as pd
import os

dataset_path = os.path.join(os.path.dirname(__file__), '..', '..', 'colab_notebooks', 'phishing_dataset', 'dataset_phishing.csv')
output_path = os.path.join(os.path.dirname(__file__), 'sampled_dataset_500.csv')

df = pd.read_csv(dataset_path)
df_phishing = df[df['status'] == 'phishing'].sample(250, random_state=42)
df_legitimate = df[df['status'] == 'legitimate'].sample(250, random_state=42)

df_sampled = pd.concat([df_phishing, df_legitimate]).sample(frac=1, random_state=42).reset_index(drop=True)
df_sampled[['url', 'status']].to_csv(output_path, index=False)
print(f"Saved 500 sampled URLs to {output_path}")
