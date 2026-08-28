#!/usr/bin/env python3
"""
Progress Monitor for PhishGuard Crawler
Run this anytime to check your crawler's progress
"""

import pandas as pd
import os
from datetime import datetime

def check_crawler_progress():
    print("="*60)
    print("PhishGuard Crawler - Progress Report")
    print("="*60)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Check if dataset exists
    dataset_path = "data/dataset.csv"
    if not os.path.exists(dataset_path):
        print("❌ No dataset found yet. Crawler may still be starting...")
        return
    
    try:
        # Load dataset
        df = pd.read_csv(dataset_path)
        
        if len(df) == 0:
            print("📊 Dataset file exists but is empty")
            return
        
        # Calculate statistics
        total_rows = len(df)
        phishing_count = len(df[df['is_phishing'] == 1])
        legit_count = len(df[df['is_phishing'] == 0])
        
        target_phishing = 5000
        target_legit = 5000
        target_total = target_phishing + target_legit
        
        # Progress percentages
        phishing_progress = (phishing_count / target_phishing) * 100
        legit_progress = (legit_count / target_legit) * 100
        total_progress = (total_rows / target_total) * 100
        
        print("📊 CURRENT STATISTICS:")
        print(f"   Total entries: {total_rows:,}")
        print(f"   Phishing sites: {phishing_count:,} / {target_phishing:,} ({phishing_progress:.1f}%)")
        print(f"   Legitimate sites: {legit_count:,} / {target_legit:,} ({legit_progress:.1f}%)")
        print(f"   Overall progress: {total_progress:.1f}%")
        print()
        
        # Progress bars
        def create_progress_bar(percentage, width=30):
            filled = int((percentage / 100) * width)
            bar = "█" * filled + "░" * (width - filled)
            return f"[{bar}] {percentage:.1f}%"
        
        print("📈 PROGRESS BARS:")
        print(f"   Phishing:   {create_progress_bar(phishing_progress)}")
        print(f"   Legitimate: {create_progress_bar(legit_progress)}")
        print(f"   Total:      {create_progress_bar(total_progress)}")
        print()
        
        # Sample data quality check
        print("🔍 DATA QUALITY CHECK:")
        if total_rows > 0:
            # Check for missing values
            missing_data = df.isnull().sum()
            critical_columns = ['domain_age_days', 'ssl_issuer', 'url_length']
            
            quality_issues = 0
            for col in critical_columns:
                if col in df.columns:
                    missing_count = missing_data.get(col, 0)
                    unknown_count = len(df[df[col] == 'Unknown']) if col in df.columns else 0
                    if missing_count > 0 or unknown_count > 0:
                        quality_issues += 1
                        print(f"   ⚠️  {col}: {missing_count} missing, {unknown_count} unknown values")
            
            if quality_issues == 0:
                print("   ✅ No major data quality issues detected")
        
        print()
        
        # Show sample entries
        print("📋 SAMPLE ENTRIES:")
        if total_rows > 0:
            sample_size = min(3, total_rows)
            sample_df = df.head(sample_size)
            
            for idx, row in sample_df.iterrows():
                site_type = "🎣 PHISHING" if row['is_phishing'] == 1 else "✅ LEGITIMATE"
                print(f"   {site_type}: {row['url']}")
                if 'domain_age_days' in row:
                    print(f"      Domain age: {row['domain_age_days']} days")
                if 'ssl_issuer' in row:
                    print(f"      SSL issuer: {row['ssl_issuer']}")
                print()
        
        # Time estimation
        if total_rows > 10:  # Need some data for estimation
            print("⏱️  TIME ESTIMATION:")
            
            # Check file modification time for rate calculation
            file_mod_time = os.path.getmtime(dataset_path)
            current_time = datetime.now().timestamp()
            hours_elapsed = (current_time - file_mod_time) / 3600
            
            if hours_elapsed > 0:
                entries_per_hour = total_rows / hours_elapsed
                remaining_entries = target_total - total_rows
                
                if entries_per_hour > 0:
                    hours_remaining = remaining_entries / entries_per_hour
                    print(f"   Current rate: {entries_per_hour:.1f} entries/hour")
                    print(f"   Estimated time remaining: {hours_remaining:.1f} hours")
                    
                    if hours_remaining > 24:
                        days_remaining = hours_remaining / 24
                        print(f"   That's approximately {days_remaining:.1f} days")
        
    except Exception as e:
        print(f"❌ Error reading dataset: {e}")
    
    print("="*60)

if __name__ == "__main__":
    check_crawler_progress()