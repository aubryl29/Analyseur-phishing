import argparse
import os
import re
import email
from email import policy
import base64
import json
import time
import urllib.request
import urllib.error
import urllib.parse

def extract_ip_from_received(received_headers):
    """
    Extrait l'adresse IP d'origine à partir des en-têtes Received.
    Les en-têtes sont généralement ajoutés du plus récent (en haut) au plus ancien (en bas).
    On cherche donc la première IP dans le dernier en-tête Received.
    """
    if not received_headers:
        return None
        
    received_ips = []
    # Parcourt tous les en-têtes Received pour en extraire les adresses IPv4
    for header in received_headers:
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(header))
        received_ips.extend(ips)
        
    if received_ips:
        # L'IP d'origine est généralement la dernière IP listée dans le thread de réception
        return received_ips[-1]
    return None

def parse_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f, policy=policy.default)
        
    sender = msg.get('From', 'Non trouvé')
    date = msg.get('Date', 'Non trouvée')
    
    # Extract IPs
    originating_ip = msg.get('X-Originating-IP')
    if not originating_ip:
        originating_ip = extract_ip_from_received(msg.get_all('Received'))
                
    if not originating_ip:
        originating_ip = "Non trouvée"
        
    # Extract URLs from body
    urls = set()
    # Regex simple pour capturer les URLs http(s)
    url_pattern = re.compile(r'https?://[^\s<>"\'\]\[\)]+')
    
    # Process text or html parts
    parts_to_process = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ('text/plain', 'text/html'):
                parts_to_process.append(part)
    else:
        parts_to_process.append(msg)

    all_text = ""
    for part in parts_to_process:
        try:
            payload = part.get_payload(decode=True)
            if payload:
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or 'utf-8'
                    text = payload.decode(charset, errors='ignore')
                else:
                    text = str(payload)
                all_text += text + " "
                urls.update(re.findall(url_pattern, text))
        except Exception:
            pass

    print("=" * 60)
    print(f"Analyse de l'email : {os.path.basename(file_path)}")
    print("=" * 60)
    print(f"[+] Expéditeur : {sender}")
    print(f"[+] Date       : {date}")
    print(f"[+] IP Origine : {originating_ip}")
    print()
    print(f"[+] URLs trouvées ({len(urls)}) :")
    for url in sorted(urls):
        print(f"    - {url}")
    print("=" * 60)
    return sender, urls, all_text

def analyze_urls_virustotal(urls, api_key):
    print("\n" + "=" * 60)
    print("Analyse des URLs sur VirusTotal")
    print("=" * 60)
    
    vt_results = {}
    sorted_urls = sorted(urls)
    for i, url in enumerate(sorted_urls):
        print(f"[*] Analyse de {url}...")
        # L'API v3 attend l'URL encodée en base64url sans padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        req = urllib.request.Request(endpoint, headers={"x-apikey": api_key})
        
        try:
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    harmless = stats.get('harmless', 0)
                    undetected = stats.get('undetected', 0)
                    
                    vt_results[url] = stats
                    
                    print(f"    -> Malveillant : {malicious}")
                    print(f"    -> Suspect     : {suspicious}")
                    print(f"    -> Inoffensif  : {harmless}")
                    print(f"    -> Non détecté : {undetected}")
                    if malicious > 0:
                        print("    [!] ATTENTION : Cette URL a été signalée comme malveillante !")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print("    -> URL non trouvée dans la base de données de VirusTotal.")
            elif e.code == 401:
                print("    -> Erreur : Clé API invalide.")
                break
            elif e.code == 429:
                print("    -> Limite de requêtes atteinte (Quotas API publique).")
                break
            else:
                print(f"    -> Erreur lors de l'analyse (Code : {e.code}).")
        except Exception as e:
            print(f"    -> Erreur de connexion : {e}")
            
        if i < len(sorted_urls) - 1:
            print("    -> Pause de 15s pour respecter le quota de l'API gratuite...")
            time.sleep(15)
            
    return vt_results

from typing import cast, Dict, Any, Set, Tuple, Optional

def evaluate_phishing_score(sender: str, text_content: str, urls: Set[str], vt_results: Optional[Dict[str, Any]] = None) -> Tuple[int, list[str], Dict[str, int]]:
    score = 0
    details = []
    
    # 1. Analyse des mots-clés d'urgence
    urgency_keywords = [
        r'\burgent[e]?\b', r'\bimmédiat[e]?\b', r'\battention\b', r'\balerte\b',
        r'\bcompte suspendu\b', r'\bbloqué\b', r'\bsécurité\b', r'\bfacture\b',
        r'\bpaiement\b', r'\bvalidation\b', r'\baction requise\b',
        r'\bverify\b', r'\bsuspended\b', r'\bpassword\b', r'\bmot de passe\b',
        r'\bconfidentiel\b', r'\bimportant[e]?\b', r'\bconnexion\b'
    ]
    
    found_keywords: Dict[str, int] = {}
    text_lower = text_content.lower()
    for kw in urgency_keywords:
        # Nettoyage de l'expression régulière pour l'affichage
        kw_clean = kw.replace(r'\b', '').replace('[e]?', '')
        matches = re.findall(kw, text_lower)
        if matches:
            found_keywords[kw_clean] = len(matches)
            
    if found_keywords:
        kw_score = min(30, len(found_keywords) * 10)
        score += kw_score
        details.append(f"[+] Mots-clés d'urgence trouvés ({len(found_keywords)}) : {', '.join(found_keywords.keys())} (+{kw_score} pts)")
    else:
        details.append("[+] Aucun mot-clé d'urgence détecté (0 pt)")
        
    # 2. Analyse des URLs
    if urls:
        base_url_score = 10
        score += base_url_score
        
        url_pattern = re.compile(r'https?://[^\s<>"\'\]\[\)]+')
        all_urls_in_text = re.findall(url_pattern, text_content)
        total_links = len(all_urls_in_text)
        if total_links == 0:
            total_links = len(urls)
            
        http_count = 0
        unknown_domain_count = 0
        
        known_domains = {
            'google.com', 'youtube.com', 'facebook.com', 'x.com', 'twitter.com', 'instagram.com', 
            'linkedin.com', 'apple.com', 'microsoft.com', 'github.com', 'amazon.com', 
            'wikipedia.org', 'paypal.com', 'netflix.com', 'yahoo.com', 'bing.com',
            'office.com', 'live.com', 'outlook.com', 'adobe.com', 'zoom.us',
            'wordpress.org', 'wordpress.com', 'cloudflare.com',
            'gmail.com', 'yahoo.fr', 'orange.fr', 'free.fr', 'sfr.fr', 'wanadoo.fr',
            'laposte.net', 'bouyguestelecom.fr', 'gouv.fr', 'service-public.fr'
        }
        
        for url in urls:
            if url.startswith('http://'):
                http_count += 1
                
            try:
                parsed_url = urllib.parse.urlparse(url)
                netloc = parsed_url.netloc.lower()
                if netloc.startswith('www.'):
                    netloc = netloc[4:]
                    
                is_known = False
                for kd in known_domains:
                    if netloc == kd or netloc.endswith('.' + kd):
                        is_known = True
                        break
                        
                if not is_known:
                    unknown_domain_count += 1
            except:
                unknown_domain_count += 1
                
        bad_link_factors = 0
        if total_links > 2:
            bad_link_factors += (total_links - 2) * 0.5
        bad_link_factors += http_count * 1.5
        bad_link_factors += unknown_domain_count * 1.0
        
        exponential_score = 0
        if bad_link_factors > 0:
            exponential_score = int(min(80, 2 ** bad_link_factors))
            
        details.append(f"[+] Présence de liens uniques ({len(urls)}) (+{base_url_score} pts)")
        if exponential_score > 0:
            score += exponential_score
            details.append(f"[!] Risque exponentiel sur les liens (Total: {total_links}, HTTP: {http_count}, Domaines inconnus: {unknown_domain_count}) (+{exponential_score} pts)")
            
        malicious_count: int = 0
        suspicious_count: int = 0
        
        if vt_results:
            for url, stats in vt_results.items():
                if isinstance(stats, dict):
                    if isinstance(stats.get('malicious'), int) and stats.get('malicious', 0) > 0:
                        malicious_count += 1
                    elif isinstance(stats.get('suspicious'), int) and stats.get('suspicious', 0) > 0:
                        suspicious_count += 1
                    
        if malicious_count > 0:
            vt_score = 50
            score += vt_score
            details.append(f"[!] VirusTotal a détecté {malicious_count} lien(s) malveillant(s) ! (+{vt_score} pts)")
        elif suspicious_count > 0:
            vt_score = 20
            score += vt_score
            details.append(f"[!] VirusTotal a détecté {suspicious_count} lien(s) suspect(s). (+{vt_score} pts)")
    else:
        details.append("[+] Aucun lien trouvé (0 pt)")
        
    # 3. Analyse de l'expéditeur (nom vs domaine, domaines suspects)
    sender_str: str = str(sender) if sender else "Non trouvé"
    sender_lower: str = sender_str.lower()
    suspicious_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.ru', 'yandex.ru']
    official_brands = ['paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'google', 'facebook', 'instagram', 'twitter', 'dhl', 'ups', 'chronopost', 'laposte']
    
    domain_match = re.search(r'@([\w.-]+)', sender_lower)
    domain: str = str(domain_match.group(1)).strip('>') if domain_match else ""
    
    sender_score: int = 0
    brand_spoofed: bool = False
    for brand in official_brands:
        if isinstance(brand, str) and isinstance(sender_lower, str) and isinstance(domain, str):
            if brand in sender_lower and brand not in domain:
                brand_spoofed = True
                break
            
    if brand_spoofed:
        sender_score += 40
        details.append(f"[!] Usurpation possible : le nom d'une marque est présent mais le domaine ({domain}) ne correspond pas (+40 pts)")
    elif domain in suspicious_domains and any(brand in sender_lower for brand in official_brands):
        sender_score += 30
        details.append(f"[!] Expéditeur suspect : utilise un domaine gratuit ({domain}) pour une marque officielle (+30 pts)")
    elif domain in suspicious_domains:
        sender_score += 10
        details.append(f"[+] Expéditeur utilise un domaine gratuit courant ({domain}) (+10 pts)")
    else:
        details.append(f"[+] Domaine de l'expéditeur ({domain}) ne présente pas d'anomalie évidente (0 pt)")
        
    score += sender_score
    
    # Cap le score à 100
    score = min(100, score)
    return score, details, found_keywords

def generate_report(score, details):
    print("\n" + "=" * 60)
    print("RAPPORT DE SYNTHÈSE - ÉVALUATION PHISHING")
    print("=" * 60)
    
    print(f"Score de risque : {score}/100\n")
    
    for detail in details:
        print(detail)
        
    print("\nCONCLUSION :")
    if score >= 70:
        print("[!!!] TRÈS PROBABLEMENT UN PHISHING. Ne cliquez sur aucun lien et supprimez ce mail.")
    elif score >= 40:
        print("[!] SUSPECT. Soyez prudent, ce mail présente plusieurs caractéristiques de phishing.")
    else:
        print("[OK] FAIBLE RISQUE. Ce mail semble légitime, mais restez vigilant.")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent d'analyse de phishing par email")
    parser.add_argument("file", help="Chemin vers le fichier .eml à analyser", nargs='?', default=r"d:\Antigravity_projects\Analyseur_phishing\aubrylloic.eml")
    args = parser.parse_args()
    
    api_key = input("Veuillez entrer votre clé API VirusTotal (ou appuyez sur Entrée pour ignorer) : ").strip()
    
    if os.path.exists(args.file):
        sender, urls_trouvees, all_text = parse_email(args.file)
        
        vt_results = None
        if api_key and urls_trouvees:
            vt_results = analyze_urls_virustotal(urls_trouvees, api_key)
            
        score, details, kws = evaluate_phishing_score(sender, all_text, urls_trouvees, vt_results)
        generate_report(score, details)
    else:
        print(f"Erreur : Le fichier {args.file} est introuvable.")
