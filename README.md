# SpamDetect AI - Intelligent Spam & Ham Classifier

SpamDetect AI is a fully functional, professional, and responsive web application that detects spam in text messages (SMS and emails) using statistical machine learning. It is built as a complete client-server decoupled architecture where model training is performed offline in Python, and real-time inference runs entirely in the browser using JavaScript.

## Features

1.  **Analysis Sandbox**: Paste any message or email text to run a real-time scan. Includes live character and word counters.
2.  **Visual Confidence Meter**: Displays the probability that a message is spam or safe (ham) with a glowing, color-coded visual indicator.
3.  **Lexical Trigger Highlighting**: Renders the analyzed text and dynamically highlights words that contributed to the classification (Red for Spam triggers, Green for Ham indicators).
4.  **Text & Lexical Analytics Dashboard**: Breaks down character counts, digit counts, uppercase shouting words, and identifies critical urgency markers (exclamation marks, dollar/currency signs, URLs).
5.  **Interactive NLP Education Panel**:
    *   Visualizes Bayes' Theorem in mathematical notation.
    *   Populates a dynamic **Active Vocabulary Table** showing the raw conditional probabilities $P(\text{Word} \mid \text{Spam})$ and $P(\text{Word} \mid \text{Ham})$ for every word in your input message.
    *   Shows the exact Spam/Ham likelihood ratios.
6.  **Bulk Scanner**: Drag and drop `.txt` or `.csv` files.
    *   Text files (.txt) load directly into the analysis text box.
    *   CSV files (.csv) parse line-by-line, run predictions, and save the batch analysis directly to the history logs.
7.  **Analysis History Logger**:
    *   Automatically persists the last 50 analyses using local storage (`localStorage`).
    *   Provides a **Details Modal** explaining the log likelihood summation ($log$ probabilities used to avoid underflow).
    *   Enables exporting history logs directly as a `.csv` file.

---

## Getting Started

### 1. Requirements
Make sure you have Python 3 installed on your system.

### 2. Train the Model
Run the Python training script. This script will download the standard SMS Spam Collection dataset (5,574 messages), preprocess the text, calculate conditional probabilities, and save the model weights to a file.

```bash
python train_model.py
```

This will create `model_weights.json` in the project directory.

### 3. Start a Local Web Server
Because the frontend loads `model_weights.json` asynchronously using the `fetch` API, modern browsers will block this request under CORS rules if you open the `index.html` directly from your hard drive (`file://` protocol).

To run the site, start a simple local server using Python:

```bash
python -m http.server 8000
```

Once running, open your web browser and navigate to:
```
http://localhost:8000
```

---

## Under the Hood: Naive Bayes Statistics

This project implements a **Multinomial Naive Bayes** classifier. It computes the posterior probabilities using Bayes' Theorem:

$$P(\text{Spam} \mid \text{Message}) = \frac{P(\text{Message} \mid \text{Spam}) \cdot P(\text{Spam})}{P(\text{Message})}$$

Since $P(\text{Message})$ is constant for both classes, we compare the numerators:

$$P(\text{Spam} \mid \text{Message}) \propto P(\text{Spam}) \cdot \prod_{i=1}^{n} P(\text{Word}_i \mid \text{Spam})$$

### Solving Numerical Underflow
Multiplying dozens of probabilities (which are tiny decimal fractions) will result in a float that is too small for standard computer hardware to represent (numerical underflow). To solve this, we sum the **natural logarithms** of the probabilities:

$$\log P(\text{Spam} \mid \text{Message}) \propto \log P(\text{Spam}) + \sum_{i=1}^{n} \log P(\text{Word}_i \mid \text{Spam})$$

### Laplace Smoothing
If a word exists in the training set for one class but not the other, the probability would be $0$, causing the entire product to become $0$. To prevent this, we apply **Laplace Smoothing** by adding $1.0$ (smoothing parameter $\alpha$) to the numerator and the vocabulary size $|V|$ to the denominator:

$$P(\text{Word} \mid \text{Spam}) = \frac{\text{Count}(\text{Word in Spam}) + 1}{\text{Total Words in Spam} + |V|}$$

---

## File Structure

*   `index.html` - The responsive user interface.
*   `style.css` - Custom styling sheet ( Tailwind-free, Glassmorphism design system).
*   `app.js` - Client-side inference, UI management, LocalStorage history, and file uploading logic.
*   `train_model.py` - Offline model training script.
*   `model_weights.json` - Serialized Naive Bayes parameters.
