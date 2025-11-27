import ssl
import socket
import datetime
from typing import Dict, List, Tuple
import certifi

class SSLAnalyzer:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.weak_ciphers = ['RC4', 'DES', 'MD5', '3DES', 'NULL', 'EXPORT', 'anon']
        self.secure_protocols = ['TLSv1.2', 'TLSv1.3']
        
    def analyze_website(self, hostname: str, port: int = 443) -> Dict:
        """Main function to analyze SSL certificate of a website"""
        try:
            # Remove protocol if present
            hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]
            
            # Create SSL context
            context = ssl.create_default_context(cafile=certifi.where())
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
            # Parse certificate details
            result = self._parse_certificate(cert, cipher, protocol, hostname)
            result['status'] = 'success'
            result['error'] = None
            
            return result
            
        except ssl.SSLError as e:
            return {
                'status': 'error',
                'error': f'SSL Error: {str(e)}',
                'hostname': hostname,
                'security_score': 0
            }
        except socket.timeout:
            return {
                'status': 'error',
                'error': 'Connection timeout',
                'hostname': hostname,
                'security_score': 0
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Error: {str(e)}',
                'hostname': hostname,
                'security_score': 0
            }
    
    def _parse_certificate(self, cert: Dict, cipher: Tuple, protocol: str, hostname: str) -> Dict:
        """Parse certificate and extract relevant information"""
        
        # Extract basic info
        subject = dict(x[0] for x in cert.get('subject', ()))
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        
        # Parse dates
        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.utcnow()
        
        # Calculate days until expiry
        days_remaining = (not_after - now).days
        
        # Check if self-signed
        is_self_signed = subject.get('commonName') == issuer.get('commonName')
        
        # Analyze cipher
        cipher_name = cipher[0] if cipher else 'Unknown'
        cipher_protocol = cipher[2] if len(cipher) > 2 else 'Unknown'
        is_weak_cipher = any(weak in cipher_name.upper() for weak in self.weak_ciphers)
        
        # Calculate security score
        security_score = self._calculate_security_score(
            days_remaining, is_self_signed, is_weak_cipher, protocol, cipher_name
        )
        
        # Determine certificate status
        if days_remaining < 0:
            cert_status = 'Expired'
        elif days_remaining <= 10:
            cert_status = 'Expiring Soon'
        elif days_remaining <= 30:
            cert_status = 'Warning'
        else:
            cert_status = 'Valid'
        
        # Get SANs (Subject Alternative Names)
        san_list = []
        if 'subjectAltName' in cert:
            san_list = [item[1] for item in cert['subjectAltName'] if item[0] == 'DNS']
        
        return {
            'hostname': hostname,
            'common_name': subject.get('commonName', 'N/A'),
            'organization': subject.get('organizationName', 'N/A'),
            'issuer_name': issuer.get('commonName', 'N/A'),
            'issuer_org': issuer.get('organizationName', 'N/A'),
            'valid_from': not_before.strftime('%Y-%m-%d %H:%M:%S'),
            'valid_until': not_after.strftime('%Y-%m-%d %H:%M:%S'),
            'days_remaining': days_remaining,
            'is_expired': days_remaining < 0,
            'is_self_signed': is_self_signed,
            'cipher_suite': cipher_name,
            'protocol_version': protocol,
            'is_weak_cipher': is_weak_cipher,
            'certificate_status': cert_status,
            'security_score': security_score,
            'san_list': san_list,
            'serial_number': cert.get('serialNumber', 'N/A')
        }
    
    def _calculate_security_score(self, days_remaining: int, is_self_signed: bool, 
                                   is_weak_cipher: bool, protocol: str, cipher: str) -> int:
        """Calculate security score out of 100"""
        score = 100
        
        # Expiry penalties
        if days_remaining < 0:
            score -= 40
        elif days_remaining <= 10:
            score -= 30
        elif days_remaining <= 30:
            score -= 15
        
        # Self-signed penalty
        if is_self_signed:
            score -= 25
        
        # Weak cipher penalty
        if is_weak_cipher:
            score -= 20
        
        # Protocol penalties
        if protocol not in self.secure_protocols:
            score -= 15
        
        # Bonus for strong configuration
        if 'AES' in cipher and 'GCM' in cipher:
            score += 5
        
        return max(0, min(100, score))
    
    def batch_analyze(self, hostnames: List[str]) -> List[Dict]:
        """Analyze multiple websites"""
        results = []
        for hostname in hostnames:
            result = self.analyze_website(hostname.strip())
            results.append(result)
        return results
    
    def get_security_grade(self, score: int) -> str:
        """Convert security score to letter grade"""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'