# patchthisapp.py
# Modernized: pathlib, type hints, argparse, modularization, logging, __main__ guard, file checks

from pathlib import Path
import argparse
import json
import logging
import pandas as pd
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_csv(path: Path, **kwargs) -> pd.DataFrame:
    if not path.exists():
        logging.error(f"Missing file: {path}")
        return pd.DataFrame()
    return pd.read_csv(path, **kwargs)

def load_metasploit_nuclei(metasploit_path: Path, nuclei_path: Path) -> pd.DataFrame:
    columns = ['CVE']
    metasploit_df = load_csv(metasploit_path, header=None, names=columns)
    nuclei_df = load_csv(nuclei_path, header=None, names=columns)
    if metasploit_df.empty and nuclei_df.empty:
        logging.error("No Metasploit or Nuclei data loaded.")
        return pd.DataFrame()
    metasploit_df.drop_duplicates(keep='first', inplace=True)
    nuclei_df.drop_duplicates(keep='first', inplace=True)
    metasploit_df['Source'] = 'Metasploit'
    nuclei_df['Source'] = 'Nuclei'
    return pd.concat([
        metasploit_df[['CVE', 'Source']],
        nuclei_df[['CVE', 'Source']]
    ], ignore_index=True, sort=False)

def load_cisa(cisa_path: Path) -> pd.DataFrame:
    df = load_csv(cisa_path)
    if df.empty:
        return df
    df = df.rename(columns={"cveID": "CVE"})
    df['Source'] = 'CISA'
    return df[['CVE', 'Source']]

def load_epss(epss_path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    df = load_csv(epss_path, skiprows=1)
    if df.empty:
        return df, df
    df = df.rename(columns={"cve": "CVE"})
    df_all = df.copy()
    df = df[df.epss > .95].copy()
    df['Source'] = 'EPSS'
    return df[['CVE', 'Source']], df_all

def load_nvd_data(filename: Path) -> List[Dict[str, str]]:
    if not filename.exists():
        logging.error(f"Missing NVD file: {filename}")
        return []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from file {filename}: {e}")
        return []

def extract_entry_data(entry: Dict[str, str]) -> Dict[str, str]:
    fields = {
        'assigner': 'Missing_Data',
        'published_date': 'Missing_Data',
        'attack_vector': 'Missing_Data',
        'attack_complexity': 'Missing_Data',
        'privileges_required': 'Missing_Data',
        'user_interaction': 'Missing_Data',
        'scope': 'Missing_Data',
        'confidentiality_impact': 'Missing_Data',
        'integrity_impact': 'Missing_Data',
        'availability_impact': 'Missing_Data',
        'base_score': '0.0',
        'base_severity': 'Missing_Data',
        'exploitability_score': 'Missing_Data',
        'impact_score': 'Missing_Data',
        'cwe': 'Missing_Data',
        'description': ''
    }
    fields['cve'] = entry['cve']['id']
    fields['assigner'] = entry['cve'].get('sourceIdentifier', fields['assigner'])
    fields['published_date'] = entry['cve'].get('published', fields['published_date'])
    metrics = entry['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
    fields.update({
        'attack_vector': metrics.get('attackVector', fields['attack_vector']),
        'attack_complexity': metrics.get('attackComplexity', fields['attack_complexity']),
        'privileges_required': metrics.get('privilegesRequired', fields['privileges_required']),
        'user_interaction': metrics.get('userInteraction', fields['user_interaction']),
        'scope': metrics.get('scope', fields['scope']),
        'confidentiality_impact': metrics.get('confidentialityImpact', fields['confidentiality_impact']),
        'integrity_impact': metrics.get('integrityImpact', fields['integrity_impact']),
        'availability_impact': metrics.get('availabilityImpact', fields['availability_impact']),
        'base_score': metrics.get('baseScore', fields['base_score']),
        'base_severity': metrics.get('baseSeverity', fields['base_severity']),
        'exploitability_score': metrics.get('exploitabilityScore', fields['exploitability_score']),
        'impact_score': metrics.get('impactScore', fields['impact_score']),
    })
    weaknesses = entry['cve'].get('weaknesses', [{}])[0].get('description', [{}])
    if weaknesses:
        fields['cwe'] = weaknesses[0].get('value', fields['cwe'])
    descriptions = entry['cve'].get('descriptions', [{}])
    if descriptions:
        fields['description'] = descriptions[0].get('value', fields['description'])
    return fields

def process_nvd_files(nvd_path: Path) -> pd.DataFrame:
    row_accumulator = []
    if not nvd_path.exists():
        logging.error(f"NVD file not found: {nvd_path}")
        return pd.DataFrame()
    nvd_data = load_nvd_data(nvd_path)
    for entry in nvd_data:
        entry_data = extract_entry_data(entry)
        if not entry_data['description'].startswith('** REJECT **'):
            row_accumulator.append(entry_data)
    nvd = pd.DataFrame(row_accumulator)
    if nvd.empty:
        return nvd
    nvd = nvd.rename(columns={'published_date': 'Published'})
    nvd['Published'] = pd.to_datetime(nvd['Published'], errors='coerce')
    nvd = nvd.sort_values(by=['Published'])
    nvd = nvd.reset_index(drop=True)
    return nvd

def main():
    parser = argparse.ArgumentParser(description="PatchThisApp Data Aggregator")
    parser.add_argument('--metasploit', type=Path, default=Path('metasploit.txt'))
    parser.add_argument('--nuclei', type=Path, default=Path('nuclei.txt'))
    parser.add_argument('--cisa', type=Path, default=Path('known_exploited_vulnerabilities.csv'))
    parser.add_argument('--epss', type=Path, default=Path('epss_scores-current.csv'))
    parser.add_argument('--nvd', type=Path, default=Path('nvd.jsonl'))
    parser.add_argument('--output', type=Path, default=Path('data/data.csv'))
    args = parser.parse_args()

    logging.info("Loading Metasploit and Nuclei data...")
    cve_sources = load_metasploit_nuclei(args.metasploit, args.nuclei)
    logging.info("Loading CISA data...")
    cisa_df = load_cisa(args.cisa)
    logging.info("Loading EPSS data...")
    epss_df, epss_df_all = load_epss(args.epss)
    if cve_sources.empty and cisa_df.empty and epss_df.empty:
        logging.error("No CVE source data loaded. Exiting.")
        return
    cve_list = pd.concat([cve_sources, epss_df, cisa_df], ignore_index=True, sort=False)
    cve_list = cve_list.groupby('CVE', as_index=False).agg({'CVE': 'first', 'Source': '/'.join})

    logging.info("Processing NVD data...")
    nvd = process_nvd_files(args.nvd)
    if nvd.empty:
        logging.error("No NVD data loaded. Exiting.")
        return
    nvd = nvd.rename(columns={'cve': 'CVE', 'description': 'Description', 'base_score': 'CVSS Score'})

    logging.info("Merging data and writing output...")
    patchthisapp_df = pd.merge(cve_list, nvd, how='inner', left_on='CVE', right_on='CVE')
    if not epss_df_all.empty:
        patchthisapp_df = pd.merge(patchthisapp_df, epss_df_all, how='inner', left_on='CVE', right_on='CVE')
        patchthisapp_df = patchthisapp_df[['CVE', 'CVSS Score', 'epss', 'Description', 'Published', 'Source']]
        patchthisapp_df = patchthisapp_df.rename(columns={"epss": "EPSS"})
    else:
        patchthisapp_df = patchthisapp_df[['CVE', 'CVSS Score', 'Description', 'Published', 'Source']]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    patchthisapp_df.to_csv(args.output, index=False)
    logging.info(f"Wrote output to {args.output}")

if __name__ == "__main__":
    main()
