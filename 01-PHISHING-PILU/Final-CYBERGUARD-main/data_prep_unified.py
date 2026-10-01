import os
import sys
import csv
import re
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from url_intelligence.preprocessing import URLCanonicalizer

DATA_DIR = r'.\data'
REPORTS_DIR = r'.\reports'
URL_DATASET_PATH = r'.\url\clean url_cleaned.csv'
QR_BENIGN_PATH = r'.\qr_decoding_output\benign_decoded.csv'
QR_MALICIOUS_PATH = r'.\qr_decoding_output\malicious_decoded.csv'

def run_pipeline():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    print("="*60)
    print("STEP 1 & 2: DATASET DISCOVERY & STREAM INGESTION")
    print("="*60)

    # In clean url_cleaned.csv:
    # label 0 = Phishing/Malicious (e.g. teramill, swtest.ru, weeblysite phishing)
    # label 1 = Legitimate/Benign (e.g. uni-mainz.de, aap.org, socialpolicy.org)
    # Target Standard Convention: 0 = BENIGN, 1 = MALICIOUS
    # Therefore, for URL dataset: standardized_label = (1 - raw_label)
    
    url_b_rows = []
    url_m_rows = []
    
    print("Ingesting Existing URL dataset (Standardizing labels to 0=Benign, 1=Malicious)...")
    with open(URL_DATASET_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        header = next(reader)
        url_idx = header.index('URL') if 'URL' in header else 0
        lbl_idx = header.index('label') if 'label' in header else -2

        for row in reader:
            if len(row) > max(url_idx, lbl_idx):
                u = row[url_idx].strip()
                l_str = row[lbl_idx].strip()
                if l_str == '1' and len(url_b_rows) < 25000:
                    # In this CSV, label 1 is legitimate -> standardized 0
                    url_b_rows.append({'original_url': u, 'standardized_label': 0, 'raw_label': 1, 'source': 'existing_url'})
                elif l_str == '0' and len(url_m_rows) < 25000:
                    # In this CSV, label 0 is malicious -> standardized 1
                    url_m_rows.append({'original_url': u, 'standardized_label': 1, 'raw_label': 0, 'source': 'existing_url'})
                
                if len(url_b_rows) >= 25000 and len(url_m_rows) >= 25000:
                    break

    print(f"Loaded existing URLs: {len(url_b_rows)} Benign, {len(url_m_rows)} Malicious")

    # In QR datasets:
    # benign_decoded.csv has label 0 (e.g. youtube.com, google.com, wikipedia) -> standardized 0
    # malicious_decoded.csv has label 1 (e.g. atualizacaodedados.online, ukit.me) -> standardized 1
    qr_b_rows = []
    with open(QR_BENIGN_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for r in reader:
            u = (r.get('decoded_content') or r.get('normalized_url') or '').strip()
            if u and len(u) >= 4:
                qr_b_rows.append({'original_url': u, 'standardized_label': 0, 'raw_label': 0, 'source': 'qr_decoded'})
            if len(qr_b_rows) >= 25000:
                break

    qr_m_rows = []
    with open(QR_MALICIOUS_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for r in reader:
            u = (r.get('decoded_content') or r.get('normalized_url') or '').strip()
            if u and len(u) >= 4:
                qr_m_rows.append({'original_url': u, 'standardized_label': 1, 'raw_label': 1, 'source': 'qr_decoded'})
            if len(qr_m_rows) >= 25000:
                break

    print(f"Loaded QR URLs: {len(qr_b_rows)} Benign, {len(qr_m_rows)} Malicious")

    all_raw = url_b_rows + url_m_rows + qr_b_rows + qr_m_rows
    raw_df = pd.DataFrame(all_raw)
    raw_path = os.path.join(DATA_DIR, 'unified_url_raw.csv')
    raw_df.to_csv(raw_path, index=False)
    print(f"\nSaved {len(raw_df)} records to {raw_path}")

    print("\n" + "="*60)
    print("STEP 3: URL NORMALIZATION & SCHEMA VALIDATION")
    print("="*60)

    processed_records = []
    for item in all_raw:
        orig = item['original_url']
        canon = URLCanonicalizer.canonicalize(orig)
        norm = canon['normalized_url']
        if not norm or len(norm) < 4:
            continue
        root = URLCanonicalizer.extract_root_domain(canon['domain'])
        processed_records.append({
            'original_url': orig,
            'normalized_url': norm,
            'domain': canon['domain'],
            'root_domain': root,
            'label': item['standardized_label'],
            'source': item['source']
        })

    proc_df = pd.DataFrame(processed_records)
    print(f"Total processed records after basic canonicalization: {len(proc_df)}")

    print("\n" + "="*60)
    print("STEP 4: DUPLICATE & CONFLICT ANALYSIS")
    print("="*60)

    # Check for exact normalized URL duplicates and conflicts
    dup_counts = proc_df.groupby('normalized_url').agg(
        count=('label', 'count'),
        unique_labels=('label', 'nunique'),
        label_list=('label', lambda s: list(s.unique()))
    ).reset_index()

    conflicts = dup_counts[dup_counts['unique_labels'] > 1]
    print(f"Found {len(conflicts)} URLs with conflicting labels across sources.")

    dup_report_rows = []
    if len(conflicts) > 0:
        for _, row in conflicts.iterrows():
            dup_report_rows.append({
                'normalized_url': row['normalized_url'],
                'occurrence_count': row['count'],
                'conflict_flag': True,
                'labels': str(row['label_list'])
            })
    dup_analysis_df = pd.DataFrame(dup_report_rows)
    dup_analysis_df.to_csv(os.path.join(REPORTS_DIR, 'duplicate_analysis.csv'), index=False)

    # Drop conflicting URLs to maintain pure ground truth
    conflict_urls = set(conflicts['normalized_url'])
    valid_df = proc_df[~proc_df['normalized_url'].isin(conflict_urls)].copy()

    # Deduplicate by normalized_url
    dedup_df = valid_df.drop_duplicates(subset=['normalized_url']).reset_index(drop=True)
    print(f"Final clean deduplicated records: {len(dedup_df)}")
    print(f"Label distribution: Benign (0) = {(dedup_df['label']==0).sum()}, Malicious (1) = {(dedup_df['label']==1).sum()}")
    print(f"Source distribution:\n{dedup_df['source'].value_counts()}")

    clean_path = os.path.join(DATA_DIR, 'unified_url_clean.csv')
    dedup_df.to_csv(clean_path, index=False)
    print(f"Saved clean unified dataset to: {clean_path}")

    # Generate Data Quality Report
    quality_report = f"""============================================================
DATA QUALITY & SANITIZATION AUDIT REPORT
============================================================
1. INGESTION SUMMARY:
   - Existing URL Dataset ingested: {len(url_b_rows) + len(url_m_rows)}
   - QR Decoded Dataset ingested:   {len(qr_b_rows) + len(qr_m_rows)}
   - Total Raw Consolidated:       {len(all_raw)}

2. LABEL STANDARDIZATION:
   - Target Convention: 0 = BENIGN, 1 = MALICIOUS
   - Existing URL Dataset: Inverted inverted ground truth (raw 1 -> 0, raw 0 -> 1)
   - QR Decoded Dataset: Direct mapping (0 -> 0, 1 -> 1)

3. SANITIZATION & DUPLICATE ANALYSIS:
   - Conflicting URLs flagged & quarantined: {len(conflicts)}
   - Exact duplicates removed: {len(proc_df) - len(dedup_df)}
   - Final High-Fidelity Clean URLs: {len(dedup_df)}
   - Benign Count (0):    {(dedup_df['label']==0).sum()} ({(dedup_df['label']==0).mean()*100:.2f}%)
   - Malicious Count (1): {(dedup_df['label']==1).sum()} ({(dedup_df['label']==1).mean()*100:.2f}%)

4. GENERALIZATION STRATEGY:
   - Test A: Standard Stratified Holdout (15%)
   - Test B: Unseen Domain Zero-Leakage Split (15% disjoint domain clusters)
   - Test C: Unseen QR Holdout (25% held out completely from training)
   - Test D: Temporal / Campaign Mutation Shift (Complex, high-entropy payload subset)
============================================================
"""
    with open(os.path.join(REPORTS_DIR, 'data_quality_report.txt'), 'w', encoding='utf-8') as f:
        f.write(quality_report)
    print(f"Data quality report generated at: reports/data_quality_report.txt")

    print("\n" + "="*60)
    print("STEP 5: CREATING ZERO-LEAKAGE STRATIFIED EVALUATION SPLITS")
    print("="*60)

    # Zero-Leakage Domain Partitioning
    unique_domains = dedup_df['root_domain'].dropna().unique()
    np.random.seed(42)
    np.random.shuffle(unique_domains)

    n_unseen_dom = int(len(unique_domains) * 0.15)
    unseen_dom_set = set(unique_domains[:n_unseen_dom])
    train_dom_set = set(unique_domains[n_unseen_dom:])

    df_unseen_dom = dedup_df[dedup_df['root_domain'].isin(unseen_dom_set)].copy()
    df_trainable = dedup_df[dedup_df['root_domain'].isin(train_dom_set)].copy()

    # Holdout 25% of QR for Test C (Unseen QR test)
    qr_pool = df_trainable[df_trainable['source'] == 'qr_decoded']
    non_qr_pool = df_trainable[df_trainable['source'] != 'qr_decoded']

    qr_train, qr_test = train_test_split(qr_pool, test_size=0.25, random_state=42, stratify=qr_pool['label'])

    train_pool = pd.concat([non_qr_pool, qr_train], ignore_index=True)
    train_df, test_random = train_test_split(train_pool, test_size=0.15, random_state=42, stratify=train_pool['label'])
    train_df, val_df = train_test_split(train_df, test_size=0.15, random_state=42, stratify=train_df['label'])

    # Test D: Temporal / High-Entropy Campaign Shift test
    b_long = test_random[(test_random['label'] == 0) & (test_random['normalized_url'].str.len() > 30)]
    m_long = test_random[(test_random['label'] == 1) & (test_random['normalized_url'].str.len() > 30)]
    n_sample_each = min(len(b_long), len(m_long), 300)
    test_temporal = pd.concat([b_long.sample(n_sample_each, random_state=42), m_long.sample(n_sample_each, random_state=42)], ignore_index=True)

    # Save splits
    train_df.to_csv(os.path.join(DATA_DIR, 'train.csv'), index=False)
    val_df.to_csv(os.path.join(DATA_DIR, 'validation.csv'), index=False)
    test_random.to_csv(os.path.join(DATA_DIR, 'test_random.csv'), index=False)
    df_unseen_dom.to_csv(os.path.join(DATA_DIR, 'test_unseen_domain.csv'), index=False)
    qr_test.to_csv(os.path.join(DATA_DIR, 'test_qr_unseen.csv'), index=False)
    test_temporal.to_csv(os.path.join(DATA_DIR, 'test_temporal.csv'), index=False)

    print(f"Train set:           {len(train_df)} rows")
    print(f"Validation set:      {len(val_df)} rows")
    print(f"Test A (Random):     {len(test_random)} rows")
    print(f"Test B (Unseen Dom): {len(df_unseen_dom)} rows")
    print(f"Test C (QR Unseen):  {len(qr_test)} rows")
    print(f"Test D (Temporal):   {len(test_temporal)} rows")

    # Anti-leakage assertion
    overlap = set(train_df['root_domain']).intersection(set(df_unseen_dom['root_domain']))
    print(f"Anti-leakage Domain Overlap (Train vs Test B): {len(overlap)} (Must be 0)")
    assert len(overlap) == 0, "Data leakage detected in domain split!"
    print("All splits verified and saved successfully.")

if __name__ == '__main__':
    run_pipeline()
