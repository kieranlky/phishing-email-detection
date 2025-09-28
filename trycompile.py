
# --- Imports (only once) ---
import pandas as pd
import re
import ast
from Levenshtein import distance as levenshtein_distance



# --- Load all dataframes at the top and reuse ---
EXCEL_FILE = 'emails_clean_350_updated2.xlsx'
SAFE_DOMAINS_FILE = 'safe_domains.xlsx'

df = pd.read_excel(EXCEL_FILE)
safe_domains_df = pd.read_excel(SAFE_DOMAINS_FILE)
safe_domains = safe_domains_df.iloc[:, 0].tolist()

# Function to check if an email domain is in the whitelist
def whitelist_check(domain, safe_domains):
    return 0 if domain in safe_domains else 1

# Function to apply whitelist check
def apply_whitelist_check(row, safe_domains):
    sender_domain = row['from_domain']  # Extract the 'from_domain' column from the dataset
    return whitelist_check(sender_domain, safe_domains)


# Apply the whitelist check to the DataFrame
df['whitelist_risk_score'] = df.apply(apply_whitelist_check, axis=1, safe_domains=safe_domains)

# Show the results with the sender domain and the new whitelist risk score
print(df[['from_domain', 'whitelist_risk_score']].head())

print("\nAvailable columns in the dataset:")
print(df.columns)

import re #tool to help us spot words using patterns
import pandas as pd #tool to help us read and handle tables

CSV_PATH = "emails_clean_350_updated2.xlsx" #name of file we want to read
keywords = {"urgent","verify","password", "confirm", "account", "suspend", "update"} #words to look for in the email subject/body

subject_weight = 0.60 #how much weight to give to subject line
body_weight = 0.40 #how much weight to give to body of email
early_window = 35.0 #how big the "early" part of the body is (smaller means earlier matters more)
threshold = 0.55 #if the total score is this number of bigger, we call it "keyword_flagged"

_word_re = re.compile(r"[A-Za-z0-9']+") #pattern to spot words

def tokens(text: str):
    return _word_re.findall((text or "").lower()) #find all words in the text, make them lowercase

def earliest_position(body_tokens, keywords):
    keywds = set(k.lower() for k in keywords) #make keywords lowercase
    for i, t in enumerate(body_tokens): #look at each word in the body
        if t in keywds: #if it's a keyword
            return i #return its position
        
def score_email(subject_text: str, body_text:str): #this will work to give the mail a score from 0-1, bigger means "more suspicious by keywords"
    s_tokens = tokens(subject_text) #get words in subject
    b_tokens = tokens(body_text) #get words in body 

    subject_hit = any(t in keywords for t in s_tokens) #see if any subject words are keywords, True(1) if subject has keyword
    pos = earliest_position(b_tokens, keywords) #get position of earliest keyword in body

    body_signal = 0.0 if pos is None else max(0.0, 1.0  - (pos/early_window)) #calculate body signal based on position of earliest keyword
    score = subject_weight * float(subject_hit) + body_weight * body_signal
    return min(1.0, max(0.0, score)), subject_hit, (pos if pos is not None else -1) #combine subject and body signals into a final score, make sure it's between 0 and 1

df = pd.read_excel(CSV_PATH) #read the table of emails from the xlsx file

subj_col = "subject_clean" if "subject_clean" in df.columns else "subject"
body_col = "body_clean" if "body_clean" in df.columns else "body"

df[subj_col] = df[subj_col].fillna("") #make sure there are no missing subjects, so code does not break
df[body_col] = df[body_col].fillna("") #make sure there are no missing bodies, so code does not break

scores, subject_hits, body_first_pos = [], [], [] #lists to hold results
for s, b in zip(df[subj_col], df[body_col]):
    sc, s_hit, pos = score_email(s,b)
    scores.append(sc) #remember the score
    subject_hits.append(int(s_hit)) #remember if subject had key word
    body_first_pos.append(pos) #remember where key word was positioned

df["keyword_score"] = scores
df["keyword_flag"] = (df["keyword_score"]>=threshold).astype(int) #1 if score is high enough
df["kw_subject_hit"] = subject_hits #1 if subject had a magic word
df["kw_body_firstpos"] = body_first_pos #where the first magic word in the body appears


print("Examples of flagged emails (top 10 by score):")
cols = [subj_col,"keyword_score", "kw_subject_hit", "kw_body_firstpos"]

counts = df["keyword_flag"].value_counts().sort_index() # how many were flagged and how many not
top10 = df[df["keyword_flag"]==1][cols].sort_values("keyword_score", ascending=False).head(10).to_string(index=False)

crosstab = None
if "y" in df.columns:
    crosstab = pd.crosstab(df["y"], df["keyword_flag"], 
                           rownames=["y"], colnames=["Keyword Flag"])


output = f"""
Counts by keyword_flag (1 = suspicious by keywords):
{counts}

Examples of flagged emails (top 10 by score):
{top10}
"""
if crosstab is not None:
    output += f"\nCross-tab with ground truth (y):\n{crosstab}"

print(output)

import pandas as pd
from Levenshtein import distance as levenshtein_distance
import re

def clean_domain(domain):
    """
    Cleans the domain string to ensure a fair comparison.
    - Removes common prefixes like 'www.'
    - Removes top-level domains like '.com', '.net', '.org', etc. for a more focused comparison on the brand name.
    - Removes special characters and converts to lowercase.
    """
    domain = str(domain).lower().strip()
    domain = re.sub(r'^(www\.|l1\.|lt08\.|mx03\.|now5\.|totalise\.|reply2\.|egwn\.|insurancemail\.|witty\.|bigfoot\.|frugaljoe\.|asiamagic\.|flashmail\.|verizonmail\.|superdada\.|virtual-mail\.|planetinternet\.|emailaccount\.|comprosys\.|abptrade\.|close2you\.|meishi\.|insurancemail\.|insurancemail\.|email\.is\.|insurancemail\.|insurancemail\.|insiq\.|insiq\.|insiq\.|insiq\.|hotmail\.)', '', domain, flags=re.IGNORECASE)
    domain = re.sub(r'\.\w{2,4}$', '', domain)  # Remove TLD
    domain = re.sub(r'[\W_]+', '', domain)  # Remove special characters
    return domain

def check_spoofing_with_edit_distance(dataset_path, legitimate_domains, threshold=2):
    """
    Analyzes a dataset of emails to detect potential domain spoofing using edit distance.

    Args:
        dataset_path (str): The path to the CSV file containing email data.
        legitimate_domains (list): A list of known, trusted domain names (brand names) to compare against.
        threshold (int): The maximum allowed edit distance for a domain to be flagged as a potential spoof.
                         A lower number is more sensitive to small changes.
    """
    try:
        # Load the dataset
        df = pd.read_excel(dataset_path)

        # Filter for phishing emails only to focus the analysis
        phishing_emails = df[df['y'] == 1].copy()

        # Create new columns for the analysis results
        phishing_emails['spoof_flag'] = False
        phishing_emails['closest_legit_domain'] = None
        phishing_emails['min_edit_distance'] = float('inf')

        # Clean legitimate domains once
        cleaned_legit_domains = [clean_domain(d) for d in legitimate_domains]
        cleaned_legit_domains = [d for d in cleaned_legit_domains if d] # Remove empty strings

        # Iterate over each phishing email to perform the check
        for index, row in phishing_emails.iterrows():
            sender_domain = row['from_domain']
            url_domains = row['url_domains']
            
            # Use sender domain from the "from_domain" column
            if pd.notna(sender_domain):
                cleaned_sender = clean_domain(sender_domain)
                
                # Compare the sender's domain with each legitimate domain
                for legit_domain in cleaned_legit_domains:
                    if not cleaned_sender or not legit_domain:
                        continue
                    
                    dist = levenshtein_distance(cleaned_sender, legit_domain)
                    
                    # Update if this is the closest match found so far
                    if dist < phishing_emails.loc[index, 'min_edit_distance']:
                        phishing_emails.loc[index, 'min_edit_distance'] = dist
                        phishing_emails.loc[index, 'closest_legit_domain'] = legit_domain
                        
                        # Flag as spoof if the distance is within the threshold
                        if 0 < dist <= threshold:
                            phishing_emails.loc[index, 'spoof_flag'] = True
                
            # Perform a similar check for URL domains if available
            if pd.notna(url_domains):
                # The URL list is a string representation of a Python list, so we need to parse it
                try:
                    # Safely evaluate the string to a list
                    url_domain_list = eval(url_domains)
                    
                    if url_domain_list and isinstance(url_domain_list, list):
                        for url_domain in url_domain_list:
                            cleaned_url_domain = clean_domain(url_domain)
                            
                            for legit_domain in cleaned_legit_domains:
                                if not cleaned_url_domain or not legit_domain:
                                    continue
                                
                                dist = levenshtein_distance(cleaned_url_domain, legit_domain)
                                
                                if dist < phishing_emails.loc[index, 'min_edit_distance']:
                                    phishing_emails.loc[index, 'min_edit_distance'] = dist
                                    phishing_emails.loc[index, 'closest_legit_domain'] = legit_domain
                                    
                                    if 0 < dist <= threshold:
                                        phishing_emails.loc[index, 'spoof_flag'] = True
                except (SyntaxError, TypeError):
                    print(f"Could not parse URL domain list for index {index}. Skipping.")
                    
        # Filter for only the flagged potential spoofs
        spoofed_emails = phishing_emails[phishing_emails['spoof_flag']]
        
        if not spoofed_emails.empty:
            print(f"Potential spoofing emails detected (edit distance threshold <= {threshold}):")
            print("-" * 80)
            
            # Print the relevant details for the detected spoofs
            for _, row in spoofed_emails.iterrows():
                print(f"Subject: {row['subject_clean']}")
                print(f"Original Domain: {row['from_domain']} / URL Domain: {row['url_domains']}")
                print(f"Potential Brand Spoof: {row['closest_legit_domain']} (Edit Distance: {int(row['min_edit_distance'])})")
                print("-" * 80)
        else:
            print("No potential spoofing emails detected with the current settings.")
            
    except FileNotFoundError:
        print(f"Error: The file at '{dataset_path}' was not found. Please check the file name and path.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example Usage:
if __name__ == "__main__":
    
    # Define a list of known legitimate domains to compare against.
    # Note: These should be brand names or core domain parts.
    legitimate_domains = [
        'aol', 'msn', 'yahoo', 'google', 'hotmail', 'amazon',
        'paypal', 'ebay', 'microsoft', 'apple', 'norton', 'hp', 'netflix',
        'wikipedia', 'youtube', 'facebook', 'twitter', 'linkedin',
        'cnet', 'zdnet', 'hertz', 'ryanair', 'intel'
    ]

    # Set the path to your Excel file
    excel_file_path = 'emails_clean_350_updated2.xlsx'
    
    # Run the detection function
    check_spoofing_with_edit_distance(excel_file_path, legitimate_domains, threshold=2)

import pandas as pd 
import re
df = pd.read_excel('emails_clean_350_updated2.xlsx')
def is_ip_url(url):
    # Regex to match URLs with IP addresses
    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)'
    return bool(re.search(ip_pattern, url))

df['phishing'] = df['url_list'].apply(lambda x: 'PHISHING' if is_ip_url(str(x)) else 'SAFE')
df['columns_match'] = df['phishing'] == df['Phishing?']
print(df['columns_match'].value_counts())
def has_encoded_or_hidden_link(text):
    # Check for percent-encoded URLs (e.g., %2F, %3A)
    encoded_pattern = r'%[0-9A-Fa-f]{2}'
    # Check for HTML anchor tags with href
    hidden_link_pattern = r'<a\s+href=["\'].*?["\'].*?>.*?</a>'
    return bool(re.search(encoded_pattern, str(text))) or bool(re.search(hidden_link_pattern, str(text)))

df['encoded_or_hidden_url'] = df.apply(
    lambda row: has_encoded_or_hidden_link(row['url_list']) or has_encoded_or_hidden_link(row['body_clean']),
    axis=1
)

# Classify as phishing if IP URL or encoded/hidden link is found
df['phishing'] = df.apply(
    lambda row: 'PHISHING' if (is_ip_url(str(row['url_list'])) or row['encoded_or_hidden_url']) else 'SAFE',
    axis=1
)

df['columns_match'] = df['phishing'] == df['Phishing?']
print(df['columns_match'].value_counts())
# Check for hidden or encoded links in 'body_clean' and 'url_list' columns
df['body_has_encoded_or_hidden'] = df['body_clean'].apply(has_encoded_or_hidden_link)
df['url_has_encoded_or_hidden'] = df['url_list'].apply(has_encoded_or_hidden_link)

print("Rows with encoded or hidden links in body_clean:", df['body_has_encoded_or_hidden'].sum())
print("Rows with encoded or hidden links in url_list:", df['url_has_encoded_or_hidden'].sum())
def anchor_text_mismatch(text):
    # Find all anchor tags with href
    anchor_pattern = r'<a\s+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>'
    mismatches = []
    for match in re.finditer(anchor_pattern, str(text), re.IGNORECASE | re.DOTALL):
        url = match.group(1)
        anchor_text = match.group(2)
        # Extract domain from URL
        domain_match = re.search(r'https?://([^/]+)', url)
        domain = domain_match.group(1) if domain_match else ''
        # Check if anchor text looks like a domain and doesn't match destination domain
        anchor_domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', anchor_text)
        anchor_domain = anchor_domain_match.group(1) if anchor_domain_match else ''
        if anchor_domain and anchor_domain.lower() != domain.lower():
            mismatches.append((anchor_text, domain))
    return len(mismatches) > 0

df['body_anchor_mismatch'] = df['body_clean'].apply(anchor_text_mismatch)
print("Rows with mismatched anchor text/domain in body_clean:", df['body_anchor_mismatch'].sum())


# ===================== RULE-BASED SCORING ADD-ON =====================
# If you don't have it yet, install once:  py -m pip install pyyaml
import re
import ast

RULE_THRESHOLD = 4.5   # >= 4.0 => NOT SAFE (rule_flag = 1)

# --- pick subject/body columns safely (matches your earlier code) ---
SUBJ = "subject_clean" if "subject_clean" in df.columns else "subject"
BODY = "body_clean"    if "body_clean"    in df.columns else "body"

# Make sure text columns are strings (prevents 'float has no attribute' errors)
df[SUBJ] = df[SUBJ].fillna("").astype(str)
df[BODY] = df[BODY].fillna("").astype(str)

# --- tiny helpers (kept simple) ---
_word_re = re.compile(r"[A-Za-z0-9']+")

def tokens(text):
    """Split text into lowercase 'word' pieces (simple & safe)."""
    return _word_re.findall(str(text).lower())

def earliest_pos_in_text(text, keyword_list):
    """Return first index of any keyword in text, or None if not found."""
    tks = tokens(text)
    kws = {k.lower() for k in keyword_list}
    for i, w in enumerate(tks):
        if w in kws:
            return i
    return None

def parse_list_cell(val):
    """
    url_list / url_domains may be stored like "['a','b']".
    This converts it back to a real Python list.
    """
    if isinstance(val, list):
        return val
    if isinstance(val, str):
            # Use literal_eval for safety; if it fails, return []
        try:
            return ast.literal_eval(val)
        except Exception:
            return []
    return []

# --- load rules config (use defaults if file missing) ---
RULES = [
    {
        "name": "subject_has_any",
        "weight": 3.0,
        "when": {
            "subject_has_any": ["urgent","verify","password","confirm","suspend","update","account"]
        }
    },
    {
        "name": "early_keyword_in_body",
        "weight": 2.0,
        "when": {
            "earliest_body_pos_at_most": {
                "keywords": ["urgent","verify","password","confirm","suspend","update","account"],
                "max_pos": 10
            }
        }
    },
    {
        "name": "raw_ip_in_any_url",
        "weight": 2.5,
        "when": { "col_equals": {"col": "raw_ip_flag", "value": 1} }
    },
    {
        "name": "anchor_text_mismatch",
        "weight": 1.5,
        "when": { "col_equals": {"col": "anchor_mismatch_flag", "value": 1} }
    },
    {
        "name": "lookalike_sender_or_url",
        "weight": 3.0,
        "when": { "any_true_cols": ["sender_looks_like_brand", "url_looks_like_brand"] }
    },
    {
        "name": "sender_not_whitelisted",
        "weight": 1.0,
        "when": {
            "from_domain_not_in": ["enron.com","dbs.com.sg","posb.com.sg","paypal.com","google.com","microsoft.com"]
        }
    }
]

def rule_matches_and_why(row, rule_when):
    """
    Check if a rule condition is true for this row.
    Return (matched: bool, reason: str).
    Supported 'when' keys:
      - subject_has_any: [..]
      - body_has_any: [..]
      - earliest_body_pos_at_most: {keywords:[..], max_pos:N}
      - col_equals: {col: name, value: X}
      - any_true_cols: [colA, colB, ...]
      - from_domain_not_in: [..]     (empty sender is treated as NOT whitelisted)
      - url_domain_in: [domain1, ...]
      - regex_any_in_body: [regex1, ...]
    """
    subj = row.get(SUBJ, "")
    body = row.get(BODY, "")
    from_domain = str(row.get("from_domain", "") or "")
    url_domains = parse_list_cell(row.get("url_domains", []))

    # 1) subject_has_any
    if "subject_has_any" in rule_when:
        kws = {w.lower() for w in rule_when["subject_has_any"]}
        found = sorted(set(tokens(subj)) & kws)
        if not found:
            return False, ""
        return True, f"subject has keyword(s): {', '.join(found)}"

    # 2) body_has_any
    if "body_has_any" in rule_when:
        kws = {w.lower() for w in rule_when["body_has_any"]}
        found = sorted(set(tokens(body)) & kws)
        if not found:
            return False, ""
        return True, f"body has keyword(s): {', '.join(found)}"

    # 3) earliest_body_pos_at_most
    if "earliest_body_pos_at_most" in rule_when:
        cfg = rule_when["earliest_body_pos_at_most"]
        kws = cfg.get("keywords", [])
        max_pos = int(cfg.get("max_pos", 10))
        pos = earliest_pos_in_text(body, kws)
        if pos is None or pos > max_pos:
            return False, ""
        return True, f"body keyword appears early (pos {pos} ≤ {max_pos})"

    # 4) col_equals
    if "col_equals" in rule_when:
        c = rule_when["col_equals"]
        col, val = c.get("col"), c.get("value")
        if str(row.get(col)) == str(val):
            return True, f"{col} == {val}"
        return False, ""

    # 5) any_true_cols
    if "any_true_cols" in rule_when:
        cols = rule_when["any_true_cols"]
        trues = [c for c in cols if bool(row.get(c, 0))]
        if trues:
            return True, f"one or more flags are true: {', '.join(trues)}"
        return False, ""

    # 6) from_domain_not_in  (empty sender counts as NOT whitelisted)
    if "from_domain_not_in" in rule_when:
        wl = {d.lower() for d in rule_when["from_domain_not_in"]}
        if from_domain == "" or from_domain.lower() not in wl:
            return True, f"sender domain '{from_domain or '(empty)'}' not in whitelist"
        return False, ""

    # 7) url_domain_in
    if "url_domain_in" in rule_when:
        targets = {d.lower() for d in rule_when["url_domain_in"]}
        hits = [d for d in url_domains if str(d).lower() in targets]
        if hits:
            return True, f"url domain hits whitelist: {', '.join(map(str, hits))}"
        return False, ""

    # 8) regex_any_in_body
    if "regex_any_in_body" in rule_when:
        pats = rule_when["regex_any_in_body"]
        for p in pats:
            if re.search(p, body, re.IGNORECASE):
                return True, f"body matches regex: {p}"
        return False, ""

    # If rule has no known condition, treat as not matched
    return False, ""

# --- apply rules to every row ---
rule_totals = []
rule_names  = []
rule_reasons_all = []   # store detailed reasons per row (for printing later)

for idx, row in df.iterrows():
    total = 0.0
    matched_names = []
    matched_reasons = []
    for rule in RULES:
        name   = rule.get("name", "unnamed_rule")
        weight = float(rule.get("weight", 0))
        cond   = rule.get("when", {})
        ok, why = rule_matches_and_why(row, cond)
        if ok:
            total += weight
            matched_names.append(name)
            matched_reasons.append(f"{name}: {why}")

    rule_totals.append(total)
    rule_names.append(", ".join(matched_names))
    rule_reasons_all.append("; ".join(matched_reasons))

df["rule_score_total"] = rule_totals
df["rule_matched"]     = rule_names
df["rule_flag"]        = (df["rule_score_total"] >= RULE_THRESHOLD).astype(int)  # 1 = NOT SAFE (by rules)
df["rule_why"]         = rule_reasons_all

# --- prints: counts, ALL flagged + WHY, and one detailed example ---

print("\nRule-based scoring summary (SAFE vs NOT SAFE):")
print(df["rule_flag"].value_counts().rename({0:"SAFE", 1:"NOT SAFE"}))

# Show rule scores and which rules matched for first 10 rows
print("\nFirst 10 rows: rule_score_total and matched rules:")
print(df[[SUBJ, "rule_score_total", "rule_matched"]].head(10).to_string(index=False))

# Show rows where any rule matched (even if not flagged as NOT SAFE)
any_matched = df[df["rule_matched"] != ""]
print(f"\nRows where at least one rule matched: {len(any_matched)}")
if len(any_matched) > 0:
    print(any_matched[[SUBJ, "rule_score_total", "rule_matched"]].head(10).to_string(index=False))

def show_all_rule_flagged():
    """Print ALL rule-flagged emails + why they were flagged."""
    flagged = df[df["rule_flag"] == 1].copy()
    print(f"\nTotal NOT SAFE (by rules): {len(flagged)}")
    if len(flagged) == 0:
        return
    view = flagged[[SUBJ, "rule_score_total", "rule_why"]].sort_values("rule_score_total", ascending=False)
    for idx, r in view.iterrows():
        print(f"[row {idx}] rule_score={r['rule_score_total']:.2f}")
        print(f"  Subject : {r[SUBJ]}")
        print(f"  Why     : {r['rule_why']}")
        print("-" * 60)

def show_rule_email(i, body_chars=300):
    """Show one email’s rule view (score, reasons, subject, short body)."""
    i = int(i)
    row = df.iloc[i]
    body_text = str(row[BODY] or "")
    preview = body_text if body_chars is None else body_text[:body_chars] + ("…" if len(body_text) > body_chars else "")
    print(f"\n--- Rule view: row {i} ---")
    print(f"rule_flag        : {row['rule_flag']}  (1=NOT SAFE, 0=SAFE)")
    print(f"rule_score_total : {row['rule_score_total']:.2f}")
    print(f"matched_rules    : {row['rule_matched']}")
    print(f"why (details)    : {row['rule_why']}")
    print(f"Subject          : {row[SUBJ]}")
    print(f"Body (preview)   : {preview}")

# Show everything
show_all_rule_flagged()
CHECK_ROW = 21
# If you want to inspect a specific row, set CHECK_ROW = some number earlier
try:
    CHECK_ROW  # do we have this variable from earlier code?
except NameError:
    CHECK_ROW = None

if CHECK_ROW is not None:
    show_rule_email(CHECK_ROW)
else:
    # If none specified, show first rule-flagged email (if any)
    idxs = df.index[df["rule_flag"] == 1]
    if len(idxs) > 0:
        show_rule_email(int(idxs[0]))