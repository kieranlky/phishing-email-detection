import re #tool to help us spot words using patterns
import pandas as pd #tool to help us read and handle tables

CSV_PATH = "emails_clean_350_updated2.xlsx" #name of file we want to read
keywords = {"urgent","verify","password", "confirm", "account", "suspend", "update"} #words to look for in the email subject/body

subject_weight = 0.60 #how much weight to give to subject line
body_weight = 0.40 #how much weight to give to body of email
early_window = 35.0 #how big the "early" part of the body is (smaller means earlier matters more)
threshold = 0.55 #if the total score is this number of bigger, we call it "keyword_flagged"

check_row = None #set to a number to check a specific row, or None to check all rows
_word_re = re.compile(r"[A-Za-z0-9']+") #pattern to spot words

def tokens(text: str):
    return _word_re.findall((text or "").lower()) #find all words in the text, make them lowercase

def earliest_position(body_tokens, keywords):
    keywds = set(k.lower() for k in keywords) #make keywords lowercase
    for i, t in enumerate(body_tokens): #look at each word in the body
        if t in keywds: #if it's a keyword
            return i #return its position
    return None #if no keywords found, return None
        
def score_email(subject_text: str, body_text:str): #this will work to give the mail a score from 0-1, bigger means "more suspicious by keywords"
    s_tokens = tokens(subject_text) #get words in subject
    b_tokens = tokens(body_text) #get words in body 

    subject_hit = 1.0 if any(t in keywords for t in s_tokens) else 0.0 

    pos = earliest_position(b_tokens, keywords) #get position of earliest keyword in body
    if pos is None:
        body_signal = 0.0  
    else:
         body_signal = max(0.0, 1.0 - (pos / early_window)) #calculate body signal based on position of earliest keyword
    score = subject_weight * subject_hit + body_weight * body_signal #combine subject and body signals into a final score
    score = min(1.0, max(0.0, score)) #make sure score is between 0 and 1
    return score, int(subject_hit==1.0), (pos if pos is not None else -1) #return score, whether subject had keyword, and position of first keyword in body

df = pd.read_excel(CSV_PATH) #read the table of emails from the xlsx file

SUBJ = "subject_clean" if "subject_clean" in df.columns else "subject"
BODY = "body_clean" if "body_clean" in df.columns else "body"

df[SUBJ] = df[SUBJ].fillna("") #make sure there are no missing subjects, so code does not break
df[BODY] = df[BODY].fillna("") #make sure there are no missing bodies, so code does not break

scores, subj_hits, body_pos = [], [], [] #lists to hold results
for s, b in zip(df[SUBJ], df[BODY]):
    sc, sh, bp = score_email(s,b)
    scores.append(sc) #remember the score
    subj_hits.append(int(sh)) #remember if subject had key word
    body_pos.append(bp) #remember where key word was positioned

df["keyword_score"] = scores
df["keyword_flag"] = (df["keyword_score"]>=threshold).astype(int) #1 if score is high enough
df["kw_subject_hit"] = subj_hits #1 if subject had a magic word
df["kw_body_firstpos"] = body_pos #where the first magic word in the body appears

def matched_keywords(text: str):
    toks = set(tokens(text))
    return ",".join(sorted(k for k in keywords if k in toks))

df["kw_subject_matches"] = df[SUBJ].apply(matched_keywords)
df["kw_body_matches"] = df[BODY].apply(matched_keywords)

def show_email(i: int, body_chars: int = 300):
    row = df.iloc[i]
    print(f"\n--- Email at row {i} ---")
    print(f"keyword_flag      : {row['keyword_flag']}  (1=suspicious, 0=not)")
    print(f"keyword_score     : {row['keyword_score']:.3f}")
    print(f"kw_subject_hit    : {row['kw_subject_hit']}  (1 if subject had a keyword)")
    print(f"kw_body_firstpos  : {row['kw_body_firstpos']}  (-1 means no keyword in body)")
    print(f"kw_subject_matches: {row['kw_subject_matches']}")
    print(f"kw_body_matches   : {row['kw_body_matches']}")
    print(f"Subject           : {row[SUBJ]}")
    body = str(row[BODY]) or ""
    preview = (body[:body_chars] + "…") if len(body) > body_chars else body
    print(f"Body (preview)    : {preview}")

def show_all_flagged():
    #print all flagged emails (row index, score, subject)
    flagged = df[df["keyword_flag"]==1]
    print(f"\nTotal flagged emails: {len(flagged)}")
    if len(flagged) == 0:
        return
    view = flagged[[SUBJ, "keyword_score"]].sort_values("keyword_score", ascending=False)
    for idx, r in view.iterrows():
        print(f"[row{idx}] score={r['keyword_score']:.3f} subject={r[SUBJ]}")

#display results next
counts = df["keyword_flag"].value_counts().sort_index()
print("\nCounts by keyword_flag (1=suspicious by keywords):")
print(counts)

#all flagged emails
show_all_flagged()

#show specific email if requested
if check_row is not None:
    show_email(check_row)
else:
    #or if no specific email requested, show first flagged email
    flagged_idx = df.index[df["keyword_flag"]==1]
    if len(flagged_idx) > 0:
        show_email(int(flagged_idx[0]))

