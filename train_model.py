import urllib.request
import re
import json
import os
import math
from collections import Counter

# Set target paths
TARGET_DIR = r"d:\Techmaghi Internship\TECHMAGHI\Spam Detection Project"
WEIGHTS_PATH = os.path.join(TARGET_DIR, "model_weights.json")

# Stopwords list
STOPWORDS = {
    "i", "me", "my", "myself", "we", "our", "ours", "ourselves", "you", "your", "yours", 
    "yourself", "yourselves", "he", "him", "his", "himself", "she", "her", "hers", "herself", 
    "it", "its", "itself", "they", "them", "their", "theirs", "themselves", "what", "which", 
    "who", "whom", "this", "that", "these", "those", "am", "is", "are", "was", "were", "be", 
    "been", "being", "have", "has", "had", "having", "do", "does", "did", "doing", "a", "an", 
    "the", "and", "but", "if", "or", "because", "as", "until", "while", "of", "at", "by", "for", 
    "with", "about", "against", "between", "into", "through", "during", "before", "after", "above", 
    "below", "to", "from", "up", "down", "in", "out", "on", "off", "over", "under", "again", 
    "further", "then", "once", "here", "there", "when", "where", "why", "how", "all", "any", 
    "both", "each", "few", "more", "most", "other", "some", "such", "no", "nor", "not", "only", 
    "own", "same", "so", "than", "too", "very", "s", "t", "can", "will", "just", "don", "should", "now"
}

def clean_text(text):
    # Lowercase
    text = text.lower()
    # Replace non-alphanumeric characters with space
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    # Split by whitespace
    tokens = text.split()
    # Filter stopwords and short tokens (keep tokens with length >= 2 or numbers)
    cleaned = [t for t in tokens if t not in STOPWORDS and (len(t) >= 2 or t.isdigit())]
    return cleaned

def download_dataset():
    url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
    print(f"Downloading SMS Spam dataset from {url}...")
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode('utf-8')
        
        lines = data.strip().split('\n')
        dataset = []
        for line in lines:
            parts = line.split('\t')
            if len(parts) >= 2:
                label = parts[0].strip().lower()
                text = parts[1].strip()
                if label in ('ham', 'spam'):
                    dataset.append((label, text))
        print(f"Successfully downloaded {len(dataset)} messages.")
        return dataset
    except Exception as e:
        print(f"Warning: Download failed ({e}). Using built-in fallback dataset.")
        return get_fallback_dataset()

def get_fallback_dataset():
    # Simple hardcoded dataset containing representative patterns of spam and ham
    raw_data = [
        ("ham", "Hey, are you coming for dinner tonight? Let me know."),
        ("ham", "I'll call you back when I get home. Busy right now."),
        ("ham", "Can you send me the lecture notes for today's math class? Thanks!"),
        ("ham", "Just finished my homework. What are you doing?"),
        ("ham", "Do you want to study together this weekend at the library?"),
        ("ham", "I'm running a bit late, see you in ten minutes."),
        ("ham", "Did you receive the email from the professor about the assignment?"),
        ("ham", "Sorry I missed your call, was sleeping. What's up?"),
        ("ham", "Yes, that sounds perfect. Let's do that tomorrow."),
        ("ham", "Can we reschedule our meeting to Friday instead of Thursday?"),
        ("ham", "Hey, just checking in. Hope you're having a great week!"),
        ("ham", "Thanks for the birthday wishes! Appreciate it."),
        ("ham", "Are you free to chat on Discord later tonight?"),
        ("ham", "No problem, take your time. No rush at all."),
        ("ham", "I'll be there soon. Just waiting for the bus."),
        ("spam", "WINNER! You have been selected for a cash prize of £1000! Call 09061701461 now to claim your reward!"),
        ("spam", "URGENT! Your mobile number has won a free gift card. Text CLAIM to 81010 within 24 hours to secure it."),
        ("spam", "Get FREE ringtones now! Reply YES to 55555. Standard rates apply. 16+ only."),
        ("spam", "Double your income working from home. No experience needed. Click http://earn-cash-easy.com now!"),
        ("spam", "Congratulations! You have been awarded a free 3-day cruise to the Bahamas. Call 1-800-CRUISE to claim."),
        ("spam", "Your bank account has been locked due to suspicious activity. Verify your identity at http://secure-login-bank.com"),
        ("spam", "Get cheap medication online. No prescription required. Click here for 80% off Viagra and Cialis."),
        ("spam", "Earn cash fast! Direct bank transfer of $5000 is waiting for your approval. Visit cash-fast.club to verify."),
        ("spam", "Guaranteed credit card approval for students! No credit check required. Apply online at http://credit-now.net"),
        ("spam", "Congratulations! You've won a free iPhone 14. Text WIN to 99288 to receive your prize details."),
        ("spam", "Make $500 a day easily by using this secret trading software. Register now at trader-secret.net"),
        ("spam", "Final warning! Your tax return is overdue. Avoid penalties by filing at http://irs-tax-refund.org immediately."),
        ("spam", "Get rich quick with bitcoin. Invest $100 and get $1000 daily! Join now at bitcoin-wealth.co"),
        ("spam", "Dating site invitation: Hot local singles are waiting for you in your area. Chat free at http://date-now.com"),
        ("spam", "LOSE WEIGHT FAST! Burn fat while you sleep. Special offer ends tonight. Buy online at http://slim-quick.com"),
        ("spam", "Dear customer, you have received 10,000 rs. Claim it by sending your atm card pin now!"),
        ("spam", "URGENT: Your ATM card has been blocked. Reply with your PIN to verify your identity and unblock."),
        ("spam", "We need to verify your bank account details. Please send your ATM pin and OTP immediately to avoid suspension."),
        ("spam", "You won a cash prize of 50,000 rs! Send your ATM card number and PIN to process the transfer.")
    ]
    # We duplicate the fallback dataset a few times to simulate slightly higher word frequencies and stability
    return raw_data * 5

def train_naive_bayes(dataset):
    print("Training Naive Bayes classifier...")
    
    num_messages = len(dataset)
    num_spam = sum(1 for label, _ in dataset if label == "spam")
    num_ham = num_messages - num_spam
    
    prior_spam = num_spam / num_messages
    prior_ham = num_ham / num_messages
    
    spam_words = []
    ham_words = []
    
    for label, text in dataset:
        tokens = clean_text(text)
        if label == "spam":
            spam_words.extend(tokens)
        else:
            ham_words.extend(tokens)
            
    spam_word_counts = Counter(spam_words)
    ham_word_counts = Counter(ham_words)
    
    # Vocabulary is the set of all unique words across both classes
    vocabulary = set(spam_word_counts.keys()).union(set(ham_word_counts.keys()))
    vocab_size = len(vocabulary)
    
    spam_total_words = sum(spam_word_counts.values())
    ham_total_words = sum(ham_word_counts.values())
    
    # Laplace smoothing parameter
    alpha = 1.0
    
    spam_word_probs = {}
    ham_word_probs = {}
    
    for word in vocabulary:
        # P(word|Spam) = (count + 1) / (spam_total_words + vocab_size)
        spam_word_probs[word] = (spam_word_counts[word] + alpha) / (spam_total_words + alpha * vocab_size)
        # P(word|Ham) = (count + 1) / (ham_total_words + vocab_size)
        ham_word_probs[word] = (ham_word_counts[word] + alpha) / (ham_total_words + alpha * vocab_size)
        
    model_data = {
        "prior_spam": prior_spam,
        "prior_ham": prior_ham,
        "vocab_size": vocab_size,
        "spam_total_words": spam_total_words,
        "ham_total_words": ham_total_words,
        "spam_word_probs": spam_word_probs,
        "ham_word_probs": ham_word_probs,
        "stopwords": list(STOPWORDS)
    }
    
    return model_data

def main():
    dataset = download_dataset()
    # Always append our custom rules to enforce high probability on specific terms
    dataset.extend(get_fallback_dataset())
    model_data = train_naive_bayes(dataset)
    
    print(f"Saving model weights to {WEIGHTS_PATH}...")
    with open(WEIGHTS_PATH, "w", encoding="utf-8") as f:
        json.dump(model_data, f, indent=2, ensure_ascii=False)
        
    print("Success! Model training complete.")
    
if __name__ == "__main__":
    main()
