
import math
from collections import Counter

ENGLISH_BIGRAM_FREQ = {"th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199, "on": 0.0176, "en": 0.0145, "at": 0.014, "es": 0.0132, "ed": 0.0131, "or": 0.0128, "ti": 0.0127, "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107, "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095, "se": 0.0093, "ha": 0.0093, "ou": 0.0087, "io": 0.0083, "le": 0.0083, "nd": 0.0082, "re": 0.0081, "ea": 0.0069, "de": 0.0069, "co": 0.0068, "te": 0.0067, "of": 0.0067, "ra": 0.0062, "ri": 0.0062, "ne": 0.0058, "me": 0.0057, "sa": 0.0056, "li": 0.0054, "la": 0.0054, "el": 0.0053, "ve": 0.0052, "ta": 0.0051, "ce": 0.0049, "si": 0.0048, "ic": 0.0045, "no": 0.0044, "ma": 0.0044, "di": 0.0043, "ro": 0.0043, "as": 0.0042}
VOWELS = set('aeiou')
STAT_FEATURE_NAMES = ["Shannon Entropy", "Bigram Score", "Subdomain Count", "Consonant Ratio", "Domain Length", "Digit Ratio", "Max Label Length"]


def compute_statistical_features(domain):
    """Compute 7 statistical features for a domain. Returns list of floats."""
    domain_lower = domain.lower().strip()
    parts = domain_lower.split('.')
    analysis_str = '.'.join(parts[:-2]) if len(parts) > 2 else parts[0]
    
    # Entropy
    if len(analysis_str) == 0:
        entropy = 0.0
    else:
        freq = Counter(analysis_str)
        total = len(analysis_str)
        entropy = -sum((c/total) * math.log2(c/total) for c in freq.values())
    
    # Bigram score
    bigrams = [analysis_str[i:i+2] for i in range(len(analysis_str)-1)]
    if bigrams:
        bg_scores = [ENGLISH_BIGRAM_FREQ.get(bg, 0.0001) for bg in bigrams]
        bigram_score = sum(math.log(s) for s in bg_scores) / len(bg_scores)
        bigram_score = max(0.0, min(1.0, (bigram_score + 9.0) / 6.0))
    else:
        bigram_score = 0.0
    
    subdomain_count = len(parts) - 2 if len(parts) > 2 else 0
    subdomain_count_norm = min(subdomain_count / 6.0, 1.0)
    
    alpha_chars = [c for c in analysis_str if c.isalpha()]
    consonant_ratio = sum(1 for c in alpha_chars if c not in VOWELS) / len(alpha_chars) if alpha_chars else 0.0
    
    domain_length_norm = min(len(domain_lower) / 253.0, 1.0)
    digit_ratio = sum(1 for c in analysis_str if c.isdigit()) / len(analysis_str) if analysis_str else 0.0
    
    label_lengths = [len(p) for p in parts[:-2]] if len(parts) > 2 else [len(parts[0])]
    max_label_norm = min(max(label_lengths) / 63.0, 1.0) if label_lengths else 0.0
    
    return [entropy/5.0, bigram_score, subdomain_count_norm, consonant_ratio,
            domain_length_norm, digit_ratio, max_label_norm]
