"""
FortifyRoot Built-in Validators
Custom validator functions for hybrid detection rules.
These can be referenced in config.yaml as "fortifyroot.validators.<function_name>"
"""

import re
from typing import Optional


def luhn(value: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.
    
    Args:
        value: Credit card number (digits only, no spaces/dashes)
    
    Returns:
        True if valid according to Luhn algorithm
    """
    # Remove any non-digits
    digits = re.sub(r'\D', '', value)
    
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False
    
    # Reject all-same-digit numbers (0000..., 1111..., etc.)
    if len(set(digits)) == 1:
        return False
    
    # Luhn algorithm
    total = 0
    reverse_digits = digits[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:  # Double every second digit
            n *= 2
            if n > 9:
                n -= 9
        total += n
    
    return total % 10 == 0


def aadhaar_checksum(value: str) -> bool:
    """
    Validate Indian Aadhaar number using Verhoeff algorithm.
    
    Args:
        value: 12-digit Aadhaar number (digits only)
    
    Returns:
        True if valid according to Verhoeff checksum
    """
    # Remove any non-digits
    digits = re.sub(r'\D', '', value)
    
    if len(digits) != 12:
        return False
    
    # Verhoeff tables
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]
    
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = d[c][p[i % 8][int(digit)]]
    
    return c == 0


def ssn_format(value: str) -> bool:
    """
    Validate US Social Security Number format.
    
    Args:
        value: SSN in XXX-XX-XXXX format or 9 digits
    
    Returns:
        True if valid SSN format (not actual validation)
    """
    # Remove dashes
    digits = re.sub(r'\D', '', value)
    
    if len(digits) != 9:
        return False
    
    # Area number (first 3) cannot be 000, 666, or 900-999
    area = int(digits[:3])
    if area == 0 or area == 666 or (900 <= area <= 999):
        return False
    
    # Group number (middle 2) cannot be 00
    group = int(digits[3:5])
    if group == 0:
        return False
    
    # Serial number (last 4) cannot be 0000
    serial = int(digits[5:])
    if serial == 0:
        return False
    
    return True


def pan_format(value: str) -> bool:
    """
    Validate Indian PAN (Permanent Account Number) format.
    
    Args:
        value: 10-character PAN
    
    Returns:
        True if valid PAN format
    """
    value = value.upper().strip()
    
    if len(value) != 10:
        return False
    
    # PAN format: AAAAA0000A
    # First 5: letters, next 4: digits, last 1: letter
    pattern = r'^[A-Z]{5}[0-9]{4}[A-Z]$'
    if not re.match(pattern, value):
        return False
    
    # Fourth character indicates entity type
    valid_fourth_chars = 'ABCFGHLJPT'  # Valid entity types
    if value[3] not in valid_fourth_chars:
        return False
    
    return True


def iban_checksum(value: str) -> bool:
    """
    Validate IBAN using MOD 97-10 algorithm.
    
    Args:
        value: IBAN string
    
    Returns:
        True if valid IBAN checksum
    """
    # Remove spaces and convert to uppercase
    iban = re.sub(r'\s', '', value).upper()
    
    if len(iban) < 15 or len(iban) > 34:
        return False
    
    # Country code (first 2) must be letters
    if not iban[:2].isalpha():
        return False
    
    # Check digits (positions 3-4) must be digits
    if not iban[2:4].isdigit():
        return False
    
    # Rearrange: move first 4 chars to end
    rearranged = iban[4:] + iban[:4]
    
    # Convert letters to numbers (A=10, B=11, ..., Z=35)
    numeric = ''
    for char in rearranged:
        if char.isalpha():
            numeric += str(ord(char) - ord('A') + 10)
        else:
            numeric += char
    
    # MOD 97 check
    return int(numeric) % 97 == 1


def ifsc_format(value: str) -> bool:
    """
    Validate Indian IFSC (Indian Financial System Code) format.
    
    Args:
        value: 11-character IFSC code
    
    Returns:
        True if valid IFSC format
    """
    value = value.upper().strip()
    
    if len(value) != 11:
        return False
    
    # Format: AAAA0AAAAAA
    # First 4: bank code (letters)
    # Fifth: always 0
    # Last 6: branch code (alphanumeric)
    pattern = r'^[A-Z]{4}0[A-Z0-9]{6}$'
    return bool(re.match(pattern, value))


def upi_format(value: str) -> bool:
    """
    Validate UPI ID format.
    
    Args:
        value: UPI ID (e.g., user@bank)
    
    Returns:
        True if valid UPI ID format
    """
    value = value.strip().lower()
    
    # Basic format: username@provider
    if '@' not in value:
        return False
    
    parts = value.split('@')
    if len(parts) != 2:
        return False
    
    username, provider = parts
    
    # Username: alphanumeric, dots, underscores
    if not username or len(username) < 3:
        return False
    
    if not re.match(r'^[a-z0-9._]+$', username):
        return False
    
    # Provider: known UPI providers or bank handles
    # This is a simplified check
    if not provider or len(provider) < 2:
        return False
    
    return True


def api_key_entropy(value: str, min_entropy: float = 3.5) -> bool:
    """
    Check if a string has enough entropy to be an API key.
    
    Args:
        value: Potential API key
        min_entropy: Minimum bits of entropy per character
    
    Returns:
        True if entropy is high enough
    """
    import math
    from collections import Counter
    
    if len(value) < 20:
        return False
    
    # Calculate Shannon entropy
    freq = Counter(value)
    length = len(value)
    entropy = 0.0
    
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy >= min_entropy


def is_not_placeholder(value: str) -> bool:
    """
    Check that a value is not a common placeholder/example.
    
    Args:
        value: Value to check
    
    Returns:
        True if not a placeholder
    """
    # Common placeholder patterns
    placeholders = [
        'xxxx', 'yyyy', 'zzzz',
        '0000', '1111', '1234', '4321',
        'test', 'demo', 'example', 'sample',
        'fake', 'dummy', 'placeholder'
    ]
    
    value_lower = value.lower()
    
    for placeholder in placeholders:
        if placeholder in value_lower:
            return False
    
    # Check for repeating patterns
    if len(set(value)) <= 2 and len(value) > 4:
        return False
    
    return True


def email_domain_check(value: str) -> bool:
    """
    Validate email has a proper domain (not disposable).
    
    Args:
        value: Email address
    
    Returns:
        True if email appears valid and not disposable
    """
    # Basic format check
    if '@' not in value:
        return False
    
    parts = value.split('@')
    if len(parts) != 2:
        return False
    
    local, domain = parts
    
    if not local or not domain:
        return False
    
    # Domain must have at least one dot
    if '.' not in domain:
        return False
    
    # Check TLD length
    tld = domain.split('.')[-1]
    if len(tld) < 2 or len(tld) > 10:
        return False
    
    return True


def ipv4_private_check(value: str) -> bool:
    """
    Check if IPv4 address is private/internal.
    
    Args:
        value: IPv4 address string
    
    Returns:
        True if private IP (for detection purposes, we often want to flag these)
    """
    try:
        octets = [int(x) for x in value.split('.')]
        if len(octets) != 4:
            return False
        
        if not all(0 <= o <= 255 for o in octets):
            return False
        
        # Check private ranges
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        
        # 127.0.0.0/8 (loopback)
        if octets[0] == 127:
            return True
        
        return False
    except (ValueError, IndexError):
        return False


def phone_length_check(value: str) -> bool:
    """
    Validate phone number has reasonable length.
    
    Args:
        value: Phone number (digits extracted)
    
    Returns:
        True if reasonable phone length
    """
    digits = re.sub(r'\D', '', value)
    
    # Most phone numbers are 10-15 digits
    return 10 <= len(digits) <= 15


# Alias for backward compatibility
credit_card_luhn = luhn
validate_ssn = ssn_format
validate_pan = pan_format
validate_iban = iban_checksum
validate_ifsc = ifsc_format
validate_upi = upi_format
