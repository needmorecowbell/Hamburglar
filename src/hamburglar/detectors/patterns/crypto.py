"""Cryptocurrency detection patterns.

This module contains patterns for detecting cryptocurrency addresses, private keys,
wallet identifiers, and seed phrases across various blockchain networks.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# Bitcoin Address Patterns
BITCOIN_ADDRESS_P2PKH = Pattern(
    name="bitcoin_address_p2pkh",
    regex=r"\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin P2PKH Address - Legacy address starting with 1",
    confidence=Confidence.MEDIUM,
)

BITCOIN_ADDRESS_P2SH = Pattern(
    name="bitcoin_address_p2sh",
    regex=r"\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin P2SH Address - Pay-to-Script-Hash address starting with 3",
    confidence=Confidence.MEDIUM,
)

BITCOIN_ADDRESS_BECH32 = Pattern(
    name="bitcoin_address_bech32",
    regex=r"\bbc1[a-z0-9]{39,59}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin Bech32 Address - Native SegWit address starting with bc1",
    confidence=Confidence.HIGH,
)

BITCOIN_ADDRESS_BECH32M = Pattern(
    name="bitcoin_address_bech32m",
    regex=r"\bbc1p[a-z0-9]{58}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin Bech32m Address - Taproot address starting with bc1p",
    confidence=Confidence.HIGH,
)

# Bitcoin Private Key Patterns (WIF Format)
BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED = Pattern(
    name="bitcoin_private_key_wif_uncompressed",
    regex=r"\b5[HJK][a-km-zA-HJ-NP-Z1-9]{49}\b",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Bitcoin WIF Private Key (Uncompressed) - Wallet Import Format starting with 5",
    confidence=Confidence.HIGH,
)

BITCOIN_PRIVATE_KEY_WIF_COMPRESSED = Pattern(
    name="bitcoin_private_key_wif_compressed",
    regex=r"\b[KL][a-km-zA-HJ-NP-Z1-9]{51}\b",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Bitcoin WIF Private Key (Compressed) - Wallet Import Format starting with K or L",
    confidence=Confidence.HIGH,
)

# Ethereum Patterns
ETHEREUM_ADDRESS = Pattern(
    name="ethereum_address",
    regex=r"\b0x[a-fA-F0-9]{40}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Ethereum Address - 40 hex characters prefixed with 0x",
    confidence=Confidence.HIGH,
)

ETHEREUM_PRIVATE_KEY = Pattern(
    name="ethereum_private_key",
    regex=r"(?i)(?:eth|ethereum|private)[_-]?(?:private)?[_-]?key['\"]?\s*[:=]\s*['\"]?(0x)?[a-fA-F0-9]{64}['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Ethereum Private Key - 64 hex character private key with context",
    confidence=Confidence.HIGH,
)

ETHEREUM_PRIVATE_KEY_RAW = Pattern(
    name="ethereum_private_key_raw",
    regex=r"\b0x[a-fA-F0-9]{64}\b",
    severity=Severity.HIGH,
    category=PatternCategory.CRYPTO,
    description="Ethereum Private Key (Raw) - 64 hex characters prefixed with 0x (may be hash)",
    confidence=Confidence.LOW,
)

# Monero Patterns
MONERO_ADDRESS_STANDARD = Pattern(
    name="monero_address_standard",
    regex=r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Monero Standard Address - 95 character address starting with 4",
    confidence=Confidence.HIGH,
)

MONERO_ADDRESS_INTEGRATED = Pattern(
    name="monero_address_integrated",
    regex=r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{104}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Monero Integrated Address - 106 character address with payment ID",
    confidence=Confidence.HIGH,
)

MONERO_ADDRESS_SUBADDRESS = Pattern(
    name="monero_address_subaddress",
    regex=r"\b8[0-9A-Za-z]{94}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Monero Subaddress - 95 character address starting with 8",
    confidence=Confidence.HIGH,
)

# Litecoin Patterns
LITECOIN_ADDRESS_LEGACY = Pattern(
    name="litecoin_address_legacy",
    regex=r"\bL[a-km-zA-HJ-NP-Z1-9]{26,33}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Litecoin Legacy Address - P2PKH address starting with L",
    confidence=Confidence.MEDIUM,
)

LITECOIN_ADDRESS_P2SH = Pattern(
    name="litecoin_address_p2sh",
    regex=r"\bM[a-km-zA-HJ-NP-Z1-9]{26,33}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Litecoin P2SH Address - Pay-to-Script-Hash address starting with M",
    confidence=Confidence.MEDIUM,
)

LITECOIN_ADDRESS_BECH32 = Pattern(
    name="litecoin_address_bech32",
    regex=r"\bltc1[a-z0-9]{39,59}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Litecoin Bech32 Address - Native SegWit address starting with ltc1",
    confidence=Confidence.HIGH,
)

# Bitcoin Extended Public Key (HD wallet)
BITCOIN_XPUB_KEY = Pattern(
    name="bitcoin_xpub_key",
    regex=r"\b(xpub[a-km-zA-HJ-NP-Z1-9]{100,108})(\?c=\d*&h=bip\d{2,3})?\b",
    severity=Severity.HIGH,
    category=PatternCategory.CRYPTO,
    description="Bitcoin xpub Key - Extended public key for HD wallets",
    confidence=Confidence.HIGH,
)

# Bitcoin URI Pattern
BITCOIN_URI = Pattern(
    name="bitcoin_uri",
    regex=r"bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin URI - bitcoin: protocol URI with address",
    confidence=Confidence.HIGH,
)

# Bitcoin Cash Address (legacy format)
BITCOIN_CASH_ADDRESS = Pattern(
    name="bitcoin_cash_address",
    regex=r"\b[13][a-km-zA-HJ-NP-Z1-9]{33}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin Cash Address - BCH legacy address format (33 chars)",
    confidence=Confidence.MEDIUM,
)

# Dash Cryptocurrency Address
DASH_ADDRESS = Pattern(
    name="dash_address",
    regex=r"\bX[1-9A-HJ-NP-Za-km-z]{33}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Dash Address - Dash cryptocurrency address starting with X",
    confidence=Confidence.HIGH,
)

# NEO Cryptocurrency Address
NEO_ADDRESS = Pattern(
    name="neo_address",
    regex=r"\bA[0-9a-zA-Z]{33}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="NEO Address - NEO blockchain address starting with A",
    confidence=Confidence.MEDIUM,
)

# Dogecoin Patterns
DOGECOIN_ADDRESS = Pattern(
    name="dogecoin_address",
    regex=r"\bD[5-9A-HJ-NP-U][a-km-zA-HJ-NP-Z1-9]{32}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Dogecoin Address - P2PKH address starting with D",
    confidence=Confidence.MEDIUM,
)

DOGECOIN_ADDRESS_P2SH = Pattern(
    name="dogecoin_address_p2sh",
    regex=r"\b9[a-km-zA-HJ-NP-Z1-9]{33}\b",
    severity=Severity.LOW,
    category=PatternCategory.CRYPTO,
    description="Dogecoin P2SH Address - Multi-sig address starting with 9",
    confidence=Confidence.LOW,
)

# Ripple (XRP) Patterns
RIPPLE_ADDRESS = Pattern(
    name="ripple_address",
    regex=r"\br[0-9a-zA-Z]{24,34}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Ripple (XRP) Address - Classic address starting with r",
    confidence=Confidence.MEDIUM,
)

RIPPLE_X_ADDRESS = Pattern(
    name="ripple_x_address",
    regex=r"\bX[a-km-zA-HJ-NP-Z1-9]{46}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Ripple X-Address - New format address starting with X",
    confidence=Confidence.HIGH,
)

# Cardano Patterns
CARDANO_ADDRESS_SHELLEY = Pattern(
    name="cardano_address_shelley",
    regex=r"\baddr1[a-z0-9]{53,98}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Cardano Shelley Address - Mainnet address starting with addr1",
    confidence=Confidence.HIGH,
)

# Solana Patterns
SOLANA_ADDRESS = Pattern(
    name="solana_address",
    regex=r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b",
    severity=Severity.LOW,
    category=PatternCategory.CRYPTO,
    description="Solana Address - Base58 encoded public key (32-44 chars)",
    confidence=Confidence.LOW,
)

# Cryptocurrency Seed Phrase Patterns
SEED_PHRASE_12_WORDS = Pattern(
    name="seed_phrase_12_words",
    regex=r"(?i)(?:seed|mnemonic|recovery|backup)[_\s-]?(?:phrase|words)?['\"]?\s*[:=]\s*['\"]?(?:[a-z]+\s+){11}[a-z]+['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="12-Word Seed Phrase - BIP39 mnemonic recovery phrase",
    confidence=Confidence.HIGH,
)

SEED_PHRASE_24_WORDS = Pattern(
    name="seed_phrase_24_words",
    regex=r"(?i)(?:seed|mnemonic|recovery|backup)[_\s-]?(?:phrase|words)?['\"]?\s*[:=]\s*['\"]?(?:[a-z]+\s+){23}[a-z]+['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="24-Word Seed Phrase - BIP39 mnemonic recovery phrase",
    confidence=Confidence.HIGH,
)

SEED_PHRASE_GENERIC = Pattern(
    name="seed_phrase_generic",
    regex=r"(?i)(?:seed|mnemonic|recovery|backup)[_\s-]?(?:phrase|words)?['\"]?\s*[:=]\s*['\"]?[a-z]+(?:\s+[a-z]+){11,23}['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Seed Phrase (Generic) - BIP39 mnemonic with 12-24 words",
    confidence=Confidence.MEDIUM,
)

# Hardware Wallet Patterns
TREZOR_PASSPHRASE = Pattern(
    name="trezor_passphrase",
    regex=r"(?i)trezor[_-]?passphrase['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Trezor Passphrase - Hardware wallet passphrase",
    confidence=Confidence.HIGH,
)

LEDGER_RECOVERY = Pattern(
    name="ledger_recovery",
    regex=r"(?i)ledger[_-]?(?:recovery|seed|mnemonic)[_-]?(?:phrase)?['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Ledger Recovery Phrase - Hardware wallet recovery data",
    confidence=Confidence.HIGH,
)

# Crypto Exchange API Keys
BINANCE_API_KEY = Pattern(
    name="binance_api_key",
    regex=r"(?i)binance[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{64})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Binance API Key - Cryptocurrency exchange API key",
    confidence=Confidence.HIGH,
)

BINANCE_SECRET_KEY = Pattern(
    name="binance_secret_key",
    regex=r"(?i)binance[_-]?(?:api)?[_-]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{64})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Binance Secret Key - Cryptocurrency exchange secret key",
    confidence=Confidence.HIGH,
)

COINBASE_API_KEY = Pattern(
    name="coinbase_api_key",
    regex=r"(?i)coinbase[_-]?(?:api)?[_-]?(?:key|secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9+/=]{40,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Coinbase API Key/Secret - Cryptocurrency exchange credentials",
    confidence=Confidence.HIGH,
)

KRAKEN_API_KEY = Pattern(
    name="kraken_api_key",
    regex=r"(?i)kraken[_-]?(?:api)?[_-]?(?:key|secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9+/=]{40,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CRYPTO,
    description="Kraken API Key/Secret - Cryptocurrency exchange credentials",
    confidence=Confidence.HIGH,
)

# Blockchain Explorer API Keys
ETHERSCAN_API_KEY = Pattern(
    name="etherscan_api_key",
    regex=r"[Ee][Tt][Hh][Ee][Rr][Ss][Cc][Aa][Nn][_-]?(?:[Aa][Pp][Ii])?[_-]?[Kk][Ee][Yy]['\"]?\s*[:=]\s*['\"]?([A-Z0-9]{34})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CRYPTO,
    description="Etherscan API Key - Ethereum blockchain explorer API key",
    confidence=Confidence.HIGH,
)

INFURA_PROJECT_ID = Pattern(
    name="infura_project_id",
    regex=r"(?i)infura[_-]?(?:project)?[_-]?(?:id|key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CRYPTO,
    description="Infura Project ID - Ethereum node access key",
    confidence=Confidence.HIGH,
)

ALCHEMY_API_KEY = Pattern(
    name="alchemy_api_key",
    regex=r"(?i)alchemy[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{32})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CRYPTO,
    description="Alchemy API Key - Blockchain development platform key",
    confidence=Confidence.HIGH,
)


# Collect all patterns for easy import
CRYPTO_PATTERNS: list[Pattern] = [
    # Bitcoin addresses
    BITCOIN_ADDRESS_P2PKH,
    BITCOIN_ADDRESS_P2SH,
    BITCOIN_ADDRESS_BECH32,
    BITCOIN_ADDRESS_BECH32M,
    # Bitcoin private keys
    BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED,
    BITCOIN_PRIVATE_KEY_WIF_COMPRESSED,
    # Bitcoin extended and URI
    BITCOIN_XPUB_KEY,
    BITCOIN_URI,
    BITCOIN_CASH_ADDRESS,
    # Ethereum
    ETHEREUM_ADDRESS,
    ETHEREUM_PRIVATE_KEY,
    ETHEREUM_PRIVATE_KEY_RAW,
    # Monero
    MONERO_ADDRESS_STANDARD,
    MONERO_ADDRESS_INTEGRATED,
    MONERO_ADDRESS_SUBADDRESS,
    # Litecoin
    LITECOIN_ADDRESS_LEGACY,
    LITECOIN_ADDRESS_P2SH,
    LITECOIN_ADDRESS_BECH32,
    # Other altcoins
    DASH_ADDRESS,
    NEO_ADDRESS,
    # Dogecoin
    DOGECOIN_ADDRESS,
    DOGECOIN_ADDRESS_P2SH,
    # Ripple
    RIPPLE_ADDRESS,
    RIPPLE_X_ADDRESS,
    # Cardano
    CARDANO_ADDRESS_SHELLEY,
    # Solana
    SOLANA_ADDRESS,
    # Seed phrases
    SEED_PHRASE_12_WORDS,
    SEED_PHRASE_24_WORDS,
    SEED_PHRASE_GENERIC,
    # Hardware wallets
    TREZOR_PASSPHRASE,
    LEDGER_RECOVERY,
    # Exchange API keys
    BINANCE_API_KEY,
    BINANCE_SECRET_KEY,
    COINBASE_API_KEY,
    KRAKEN_API_KEY,
    # Blockchain explorers
    ETHERSCAN_API_KEY,
    INFURA_PROJECT_ID,
    ALCHEMY_API_KEY,
]

__all__ = [
    "CRYPTO_PATTERNS",
    # Bitcoin addresses
    "BITCOIN_ADDRESS_P2PKH",
    "BITCOIN_ADDRESS_P2SH",
    "BITCOIN_ADDRESS_BECH32",
    "BITCOIN_ADDRESS_BECH32M",
    # Bitcoin private keys
    "BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED",
    "BITCOIN_PRIVATE_KEY_WIF_COMPRESSED",
    # Bitcoin extended and URI
    "BITCOIN_XPUB_KEY",
    "BITCOIN_URI",
    "BITCOIN_CASH_ADDRESS",
    # Ethereum
    "ETHEREUM_ADDRESS",
    "ETHEREUM_PRIVATE_KEY",
    "ETHEREUM_PRIVATE_KEY_RAW",
    # Monero
    "MONERO_ADDRESS_STANDARD",
    "MONERO_ADDRESS_INTEGRATED",
    "MONERO_ADDRESS_SUBADDRESS",
    # Litecoin
    "LITECOIN_ADDRESS_LEGACY",
    "LITECOIN_ADDRESS_P2SH",
    "LITECOIN_ADDRESS_BECH32",
    # Other altcoins
    "DASH_ADDRESS",
    "NEO_ADDRESS",
    # Dogecoin
    "DOGECOIN_ADDRESS",
    "DOGECOIN_ADDRESS_P2SH",
    # Ripple
    "RIPPLE_ADDRESS",
    "RIPPLE_X_ADDRESS",
    # Cardano
    "CARDANO_ADDRESS_SHELLEY",
    # Solana
    "SOLANA_ADDRESS",
    # Seed phrases
    "SEED_PHRASE_12_WORDS",
    "SEED_PHRASE_24_WORDS",
    "SEED_PHRASE_GENERIC",
    # Hardware wallets
    "TREZOR_PASSPHRASE",
    "LEDGER_RECOVERY",
    # Exchange API keys
    "BINANCE_API_KEY",
    "BINANCE_SECRET_KEY",
    "COINBASE_API_KEY",
    "KRAKEN_API_KEY",
    # Blockchain explorers
    "ETHERSCAN_API_KEY",
    "INFURA_PROJECT_ID",
    "ALCHEMY_API_KEY",
]
