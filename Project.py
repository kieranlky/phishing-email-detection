import pandas as pd 
import re
df = pd.read_excel('c:\Python project\emails_clean_350_updated2.xlsx')
df.head()
df.tail()
df.shape
df.info()
df.describe()
df.columns
df['safe_domain'] = df['from_domain'].str.endswith('.org')
df.count()
print(df['safe_domain'].value_counts())
df['domain_status'] = df['safe_domain'].apply(lambda x: 'SAFE' if x else 'PHISHING')
# Classify URLs with IP addresses in 'url_domains' as phishing

def has_ip_address(domain):
    # Matches IPv4 addresses
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(domain).strip()))

df['ip_in_url'] = df['url_domains'].apply(has_ip_address)
df['domain_status'] = df.apply(
    lambda row: 'phishing' if row['ip_in_url'] else row['domain_status'],
    axis=1
)

# Check if phishing classification matches 'Phishing?' column
matches = (df['domain_status'] == df['Phishing?'])
print("Classification matches 'Phishing?' column:", matches.value_counts())