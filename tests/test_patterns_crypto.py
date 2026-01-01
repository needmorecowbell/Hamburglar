"""Tests for cryptocurrency detection patterns.

This module contains comprehensive tests for all cryptocurrency patterns defined in
the crypto pattern module. Each pattern is tested with at least 2 positive
matches and 2 negative cases to ensure accuracy.

NOTE: Test patterns are intentionally constructed to be obviously fake and
avoid triggering secret scanning. Patterns use FAKE/TEST markers,
concatenation, and synthetic sequences where appropriate.
"""

from __future__ import annotations

import re

import pytest

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, PatternCategory
from hamburglar.detectors.patterns.crypto import (
    ALCHEMY_API_KEY,
    BINANCE_API_KEY,
    BINANCE_SECRET_KEY,
    BITCOIN_ADDRESS_BECH32,
    BITCOIN_ADDRESS_BECH32M,
    BITCOIN_ADDRESS_P2PKH,
    BITCOIN_ADDRESS_P2SH,
    BITCOIN_PRIVATE_KEY_WIF_COMPRESSED,
    BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED,
    CARDANO_ADDRESS_SHELLEY,
    COINBASE_API_KEY,
    CRYPTO_PATTERNS,
    DOGECOIN_ADDRESS,
    DOGECOIN_ADDRESS_P2SH,
    ETHEREUM_ADDRESS,
    ETHEREUM_PRIVATE_KEY,
    ETHEREUM_PRIVATE_KEY_RAW,
    ETHERSCAN_API_KEY,
    INFURA_PROJECT_ID,
    KRAKEN_API_KEY,
    LEDGER_RECOVERY,
    LITECOIN_ADDRESS_BECH32,
    LITECOIN_ADDRESS_LEGACY,
    LITECOIN_ADDRESS_P2SH,
    MONERO_ADDRESS_INTEGRATED,
    MONERO_ADDRESS_STANDARD,
    MONERO_ADDRESS_SUBADDRESS,
    RIPPLE_ADDRESS,
    RIPPLE_X_ADDRESS,
    SEED_PHRASE_12_WORDS,
    SEED_PHRASE_24_WORDS,
    SEED_PHRASE_GENERIC,
    SOLANA_ADDRESS,
    TREZOR_PASSPHRASE,
)


class TestBitcoinAddressPatterns:
    """Tests for Bitcoin address patterns."""

    def test_bitcoin_p2pkh_positive_1(self) -> None:
        """Test Bitcoin P2PKH address starting with 1."""
        pattern = re.compile(BITCOIN_ADDRESS_P2PKH.regex)
        # Fake address for testing
        result = pattern.search("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert result is not None

    def test_bitcoin_p2pkh_positive_2(self) -> None:
        """Test Bitcoin P2PKH address in context."""
        pattern = re.compile(BITCOIN_ADDRESS_P2PKH.regex)
        result = pattern.search("Send to address: 1FfmbHfnpaZjKFvyi1okTjJJusN455paPH")
        assert result is not None

    def test_bitcoin_p2pkh_negative_1(self) -> None:
        """Test invalid Bitcoin address (wrong prefix)."""
        pattern = re.compile(BITCOIN_ADDRESS_P2PKH.regex)
        result = pattern.search("0BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert result is None

    def test_bitcoin_p2pkh_negative_2(self) -> None:
        """Test address too short."""
        pattern = re.compile(BITCOIN_ADDRESS_P2PKH.regex)
        result = pattern.search("1BvBMSEYstWetqT")
        assert result is None

    def test_bitcoin_p2sh_positive_1(self) -> None:
        """Test Bitcoin P2SH address starting with 3."""
        pattern = re.compile(BITCOIN_ADDRESS_P2SH.regex)
        result = pattern.search("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        assert result is not None

    def test_bitcoin_p2sh_positive_2(self) -> None:
        """Test Bitcoin P2SH address in context."""
        pattern = re.compile(BITCOIN_ADDRESS_P2SH.regex)
        result = pattern.search("MultiSig: 3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r")
        assert result is not None

    def test_bitcoin_p2sh_negative_1(self) -> None:
        """Test wrong prefix for P2SH."""
        pattern = re.compile(BITCOIN_ADDRESS_P2SH.regex)
        result = pattern.search("1J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        assert result is None

    def test_bitcoin_p2sh_negative_2(self) -> None:
        """Test P2SH address too short."""
        pattern = re.compile(BITCOIN_ADDRESS_P2SH.regex)
        result = pattern.search("3J98t1WpEZ73")
        assert result is None

    def test_bitcoin_bech32_positive_1(self) -> None:
        """Test Bitcoin Bech32 address."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32.regex)
        result = pattern.search("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert result is not None

    def test_bitcoin_bech32_positive_2(self) -> None:
        """Test Bitcoin Bech32 address in context."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32.regex)
        result = pattern.search("SegWit: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assert result is not None

    def test_bitcoin_bech32_negative_1(self) -> None:
        """Test wrong prefix for Bech32."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32.regex)
        result = pattern.search("ltc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert result is None

    def test_bitcoin_bech32_negative_2(self) -> None:
        """Test Bech32 address too short."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32.regex)
        result = pattern.search("bc1qar0srrr7xfkvy5l643lydnw9")
        assert result is None

    def test_bitcoin_bech32m_positive_1(self) -> None:
        """Test Bitcoin Bech32m (Taproot) address."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32M.regex)
        result = pattern.search("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
        assert result is not None

    def test_bitcoin_bech32m_positive_2(self) -> None:
        """Test Bitcoin Bech32m address in context."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32M.regex)
        result = pattern.search(
            "Taproot: bc1pq2urtlmzp0ztk6efv9c7gh3lgpga6kchc9hgft9e2xdvcmwqpe2qrp83g3"
        )
        assert result is not None

    def test_bitcoin_bech32m_negative_1(self) -> None:
        """Test Bech32m without p prefix after bc1."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32M.regex)
        result = pattern.search("bc1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
        assert result is None

    def test_bitcoin_bech32m_negative_2(self) -> None:
        """Test Bech32m address too short."""
        pattern = re.compile(BITCOIN_ADDRESS_BECH32M.regex)
        result = pattern.search("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q")
        assert result is None

    def test_bitcoin_p2pkh_metadata(self) -> None:
        """Test Bitcoin P2PKH pattern metadata."""
        assert BITCOIN_ADDRESS_P2PKH.severity == Severity.MEDIUM
        assert BITCOIN_ADDRESS_P2PKH.category == PatternCategory.CRYPTO
        assert BITCOIN_ADDRESS_P2PKH.confidence == Confidence.MEDIUM


class TestBitcoinPrivateKeyPatterns:
    """Tests for Bitcoin private key patterns."""

    def test_wif_uncompressed_positive_1(self) -> None:
        """Test WIF uncompressed private key starting with 5H."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED.regex)
        # Fake key for testing - 51 chars starting with 5H/5J/5K
        result = pattern.search("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        assert result is not None

    def test_wif_uncompressed_positive_2(self) -> None:
        """Test WIF uncompressed private key starting with 5J."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED.regex)
        result = pattern.search("key: 5Jf2vbdzdCccKApCrjmwL5EFc4BGLRhLGNhjLpXkv3TqH6TmrqS")
        assert result is not None

    def test_wif_uncompressed_negative_1(self) -> None:
        """Test wrong prefix for WIF."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED.regex)
        result = pattern.search("5AueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        assert result is None

    def test_wif_uncompressed_negative_2(self) -> None:
        """Test WIF too short."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED.regex)
        result = pattern.search("5HueCGU8rMjxEXxiPuD5BDku")
        assert result is None

    def test_wif_compressed_positive_1(self) -> None:
        """Test WIF compressed private key starting with K."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_COMPRESSED.regex)
        result = pattern.search("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        assert result is not None

    def test_wif_compressed_positive_2(self) -> None:
        """Test WIF compressed private key starting with L."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_COMPRESSED.regex)
        result = pattern.search("privkey: L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC")
        assert result is not None

    def test_wif_compressed_negative_1(self) -> None:
        """Test wrong prefix for compressed WIF."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_COMPRESSED.regex)
        result = pattern.search("MwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        assert result is None

    def test_wif_compressed_negative_2(self) -> None:
        """Test WIF compressed too short."""
        pattern = re.compile(BITCOIN_PRIVATE_KEY_WIF_COMPRESSED.regex)
        result = pattern.search("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3")
        assert result is None

    def test_wif_uncompressed_metadata(self) -> None:
        """Test WIF pattern metadata."""
        assert BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED.severity == Severity.CRITICAL
        assert BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED.category == PatternCategory.CRYPTO


class TestEthereumPatterns:
    """Tests for Ethereum patterns."""

    def test_ethereum_address_positive_1(self) -> None:
        """Test Ethereum address."""
        pattern = re.compile(ETHEREUM_ADDRESS.regex)
        result = pattern.search("0x742d35Cc6634C0532925a3b844Bc9e7595f2b3e8")
        assert result is not None

    def test_ethereum_address_positive_2(self) -> None:
        """Test Ethereum address in context."""
        pattern = re.compile(ETHEREUM_ADDRESS.regex)
        result = pattern.search("Wallet: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")
        assert result is not None

    def test_ethereum_address_negative_1(self) -> None:
        """Test Ethereum address too short."""
        pattern = re.compile(ETHEREUM_ADDRESS.regex)
        result = pattern.search("0x742d35Cc6634C0532925a3b844Bc9")
        assert result is None

    def test_ethereum_address_negative_2(self) -> None:
        """Test invalid hex characters."""
        pattern = re.compile(ETHEREUM_ADDRESS.regex)
        result = pattern.search("0x742d35Cc6634C0532925a3b844Bc9eGGGG5f2b3e8")
        assert result is None

    def test_ethereum_private_key_positive_1(self) -> None:
        """Test Ethereum private key with context."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY.regex)
        result = pattern.search(
            "eth_private_key = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'"
        )
        assert result is not None

    def test_ethereum_private_key_positive_2(self) -> None:
        """Test Ethereum private key alternate context."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY.regex)
        result = pattern.search(
            'ETHEREUM_KEY: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"'
        )
        assert result is not None

    def test_ethereum_private_key_negative_1(self) -> None:
        """Test Ethereum private key without context."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY.regex)
        result = pattern.search("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        assert result is None

    def test_ethereum_private_key_negative_2(self) -> None:
        """Test non-Ethereum key context."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY.regex)
        result = pattern.search(
            "api_key = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'"
        )
        assert result is None

    def test_ethereum_private_key_raw_positive_1(self) -> None:
        """Test raw Ethereum private key."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY_RAW.regex)
        result = pattern.search(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        assert result is not None

    def test_ethereum_private_key_raw_positive_2(self) -> None:
        """Test raw Ethereum private key in context."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY_RAW.regex)
        result = pattern.search(
            "key: 0xabcdefABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234"
        )
        assert result is not None

    def test_ethereum_private_key_raw_negative_1(self) -> None:
        """Test raw key too short."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY_RAW.regex)
        result = pattern.search("0x1234567890abcdef1234567890abcdef")
        assert result is None

    def test_ethereum_private_key_raw_negative_2(self) -> None:
        """Test raw key without 0x prefix."""
        pattern = re.compile(ETHEREUM_PRIVATE_KEY_RAW.regex)
        result = pattern.search("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        assert result is None

    def test_ethereum_address_metadata(self) -> None:
        """Test Ethereum address pattern metadata."""
        assert ETHEREUM_ADDRESS.severity == Severity.MEDIUM
        assert ETHEREUM_ADDRESS.category == PatternCategory.CRYPTO
        assert ETHEREUM_ADDRESS.confidence == Confidence.HIGH


class TestMoneroPatterns:
    """Tests for Monero address patterns."""

    def test_monero_standard_positive_1(self) -> None:
        """Test Monero standard address (95 chars starting with 4)."""
        pattern = re.compile(MONERO_ADDRESS_STANDARD.regex)
        # Fake 95 char address for testing
        addr = "4" + "A" + "a" * 93
        result = pattern.search(addr)
        assert result is not None

    def test_monero_standard_positive_2(self) -> None:
        """Test Monero standard address in context."""
        pattern = re.compile(MONERO_ADDRESS_STANDARD.regex)
        addr = "4" + "B" + "b" * 93
        result = pattern.search(f"XMR address: {addr}")
        assert result is not None

    def test_monero_standard_negative_1(self) -> None:
        """Test wrong prefix for Monero."""
        pattern = re.compile(MONERO_ADDRESS_STANDARD.regex)
        addr = "5" + "A" + "a" * 93
        result = pattern.search(addr)
        assert result is None

    def test_monero_standard_negative_2(self) -> None:
        """Test Monero address too short."""
        pattern = re.compile(MONERO_ADDRESS_STANDARD.regex)
        addr = "4" + "A" + "a" * 50
        result = pattern.search(addr)
        assert result is None

    def test_monero_integrated_positive_1(self) -> None:
        """Test Monero integrated address (106 chars)."""
        pattern = re.compile(MONERO_ADDRESS_INTEGRATED.regex)
        addr = "4" + "A" + "a" * 104
        result = pattern.search(addr)
        assert result is not None

    def test_monero_integrated_positive_2(self) -> None:
        """Test Monero integrated address in context."""
        pattern = re.compile(MONERO_ADDRESS_INTEGRATED.regex)
        addr = "4" + "B" + "b" * 104
        result = pattern.search(f"Payment: {addr}")
        assert result is not None

    def test_monero_integrated_negative_1(self) -> None:
        """Test wrong length for integrated."""
        pattern = re.compile(MONERO_ADDRESS_INTEGRATED.regex)
        addr = "4" + "A" + "a" * 93  # Standard length, not integrated
        result = pattern.search(addr)
        assert result is None

    def test_monero_integrated_negative_2(self) -> None:
        """Test wrong prefix for integrated."""
        pattern = re.compile(MONERO_ADDRESS_INTEGRATED.regex)
        addr = "5" + "A" + "a" * 104
        result = pattern.search(addr)
        assert result is None

    def test_monero_subaddress_positive_1(self) -> None:
        """Test Monero subaddress (95 chars starting with 8)."""
        pattern = re.compile(MONERO_ADDRESS_SUBADDRESS.regex)
        addr = "8" + "a" * 94
        result = pattern.search(addr)
        assert result is not None

    def test_monero_subaddress_positive_2(self) -> None:
        """Test Monero subaddress in context."""
        pattern = re.compile(MONERO_ADDRESS_SUBADDRESS.regex)
        addr = "8" + "B" * 94
        result = pattern.search(f"Subaddress: {addr}")
        assert result is not None

    def test_monero_subaddress_negative_1(self) -> None:
        """Test wrong prefix for subaddress."""
        pattern = re.compile(MONERO_ADDRESS_SUBADDRESS.regex)
        addr = "4" + "a" * 94
        result = pattern.search(addr)
        assert result is None

    def test_monero_subaddress_negative_2(self) -> None:
        """Test subaddress too short."""
        pattern = re.compile(MONERO_ADDRESS_SUBADDRESS.regex)
        addr = "8" + "a" * 50
        result = pattern.search(addr)
        assert result is None


class TestLitecoinPatterns:
    """Tests for Litecoin address patterns."""

    def test_litecoin_legacy_positive_1(self) -> None:
        """Test Litecoin legacy address starting with L."""
        pattern = re.compile(LITECOIN_ADDRESS_LEGACY.regex)
        result = pattern.search("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
        assert result is not None

    def test_litecoin_legacy_positive_2(self) -> None:
        """Test Litecoin legacy address in context."""
        pattern = re.compile(LITECOIN_ADDRESS_LEGACY.regex)
        result = pattern.search("Send LTC to: LUdMPKhvxFE69dP9G6UmEJDvnEcjqLHSxk")
        assert result is not None

    def test_litecoin_legacy_negative_1(self) -> None:
        """Test wrong prefix for Litecoin."""
        pattern = re.compile(LITECOIN_ADDRESS_LEGACY.regex)
        result = pattern.search("KM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
        assert result is None

    def test_litecoin_legacy_negative_2(self) -> None:
        """Test Litecoin address too short."""
        pattern = re.compile(LITECOIN_ADDRESS_LEGACY.regex)
        result = pattern.search("LM2WMpR1Rp6j3Sa")
        assert result is None

    def test_litecoin_p2sh_positive_1(self) -> None:
        """Test Litecoin P2SH address starting with M."""
        pattern = re.compile(LITECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("MQZ5FpB2vXHM3z3a8k5qUmxBnHKvWfrWGn")
        assert result is not None

    def test_litecoin_p2sh_positive_2(self) -> None:
        """Test Litecoin P2SH address in context."""
        pattern = re.compile(LITECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("MultiSig: MV3L4BcCfUTWSe4K7x8YvnNDC2FrYPXEhp")
        assert result is not None

    def test_litecoin_p2sh_negative_1(self) -> None:
        """Test wrong prefix for Litecoin P2SH."""
        pattern = re.compile(LITECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("NQZ5FpB2vXHM3z3a8k5qUmxBnHKvWfrWGn")
        assert result is None

    def test_litecoin_p2sh_negative_2(self) -> None:
        """Test Litecoin P2SH too short."""
        pattern = re.compile(LITECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("MQZ5FpB2vXHM3z")
        assert result is None

    def test_litecoin_bech32_positive_1(self) -> None:
        """Test Litecoin Bech32 address."""
        pattern = re.compile(LITECOIN_ADDRESS_BECH32.regex)
        result = pattern.search("ltc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert result is not None

    def test_litecoin_bech32_positive_2(self) -> None:
        """Test Litecoin Bech32 address in context."""
        pattern = re.compile(LITECOIN_ADDRESS_BECH32.regex)
        result = pattern.search("SegWit: ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assert result is not None

    def test_litecoin_bech32_negative_1(self) -> None:
        """Test wrong prefix for Litecoin Bech32."""
        pattern = re.compile(LITECOIN_ADDRESS_BECH32.regex)
        result = pattern.search("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert result is None

    def test_litecoin_bech32_negative_2(self) -> None:
        """Test Litecoin Bech32 too short."""
        pattern = re.compile(LITECOIN_ADDRESS_BECH32.regex)
        result = pattern.search("ltc1qar0srrr7xfkvy5l643lydnw")
        assert result is None


class TestDogecoinPatterns:
    """Tests for Dogecoin address patterns."""

    def test_dogecoin_address_positive_1(self) -> None:
        """Test Dogecoin address starting with D."""
        pattern = re.compile(DOGECOIN_ADDRESS.regex)
        result = pattern.search("D7Y55qKPTnBQ9fWpD5P7mJhKw2jhvXxyjV")
        assert result is not None

    def test_dogecoin_address_positive_2(self) -> None:
        """Test Dogecoin address in context."""
        pattern = re.compile(DOGECOIN_ADDRESS.regex)
        result = pattern.search("DOGE tips: D9eQbvBmQZHnWzPKjNQXVvDfLfyLJpJm4h")
        assert result is not None

    def test_dogecoin_address_negative_1(self) -> None:
        """Test wrong prefix for Dogecoin."""
        pattern = re.compile(DOGECOIN_ADDRESS.regex)
        result = pattern.search("17Y55qKPTnBQ9fWpD5P7mJhKw2jhvXxyjV")
        assert result is None

    def test_dogecoin_address_negative_2(self) -> None:
        """Test Dogecoin address too short."""
        pattern = re.compile(DOGECOIN_ADDRESS.regex)
        result = pattern.search("D7Y55qKPTnBQ9fWpD5P7mJhKw")
        assert result is None

    def test_dogecoin_p2sh_positive_1(self) -> None:
        """Test Dogecoin P2SH address starting with 9."""
        pattern = re.compile(DOGECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("9wHPwX7n6Z6vXGxdZ9GYGgTBgJCuXSPc6w")
        assert result is not None

    def test_dogecoin_p2sh_positive_2(self) -> None:
        """Test Dogecoin P2SH in context."""
        pattern = re.compile(DOGECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("MultiSig: 9xJPwX7n6Z6vXGxdZ9GYGgTBgJCuXSPc6w")
        assert result is not None

    def test_dogecoin_p2sh_negative_1(self) -> None:
        """Test wrong prefix for Dogecoin P2SH."""
        pattern = re.compile(DOGECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("8wHPwX7n6Z6vXGxdZ9GYGgTBgJCuXSPc6w")
        assert result is None

    def test_dogecoin_p2sh_negative_2(self) -> None:
        """Test Dogecoin P2SH too short."""
        pattern = re.compile(DOGECOIN_ADDRESS_P2SH.regex)
        result = pattern.search("9wHPwX7n6Z6vXGxdZ9GYGg")
        assert result is None


class TestRipplePatterns:
    """Tests for Ripple (XRP) address patterns."""

    def test_ripple_address_positive_1(self) -> None:
        """Test Ripple classic address starting with r."""
        pattern = re.compile(RIPPLE_ADDRESS.regex)
        result = pattern.search("rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh")
        assert result is not None

    def test_ripple_address_positive_2(self) -> None:
        """Test Ripple address in context."""
        pattern = re.compile(RIPPLE_ADDRESS.regex)
        result = pattern.search("XRP: rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY")
        assert result is not None

    def test_ripple_address_negative_1(self) -> None:
        """Test wrong prefix for Ripple."""
        pattern = re.compile(RIPPLE_ADDRESS.regex)
        result = pattern.search("sEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh")
        assert result is None

    def test_ripple_address_negative_2(self) -> None:
        """Test Ripple address too short."""
        pattern = re.compile(RIPPLE_ADDRESS.regex)
        result = pattern.search("rEb8TK3gBgk5auZkwc6sH")
        assert result is None

    def test_ripple_x_address_positive_1(self) -> None:
        """Test Ripple X-address."""
        pattern = re.compile(RIPPLE_X_ADDRESS.regex)
        # X-address is 47 chars
        result = pattern.search("X7gPc1A8y5h6Ck5V9dH6x5mPZq8T4bBB3kZ7sL9qR2nWpXy")
        assert result is not None

    def test_ripple_x_address_positive_2(self) -> None:
        """Test Ripple X-address in context."""
        pattern = re.compile(RIPPLE_X_ADDRESS.regex)
        result = pattern.search("XRP X-addr: X8cD6MzP9k5n2Rq8T4hG7bXcV5sA3pE8f9Z2mL4nWqYhBj6")
        assert result is not None

    def test_ripple_x_address_negative_1(self) -> None:
        """Test wrong prefix for X-address."""
        pattern = re.compile(RIPPLE_X_ADDRESS.regex)
        result = pattern.search("Y7gPc1A8y5h6Ck5V9dH6x5mPZq8T4bBB3kZ7sL9qR2nWpXy")
        assert result is None

    def test_ripple_x_address_negative_2(self) -> None:
        """Test X-address too short."""
        pattern = re.compile(RIPPLE_X_ADDRESS.regex)
        result = pattern.search("X7gPc1A8y5h6Ck5V9dH6x5mPZq8T")
        assert result is None


class TestCardanoPatterns:
    """Tests for Cardano address patterns."""

    def test_cardano_shelley_positive_1(self) -> None:
        """Test Cardano Shelley address."""
        pattern = re.compile(CARDANO_ADDRESS_SHELLEY.regex)
        # Valid 58-char Cardano Shelley address (5 prefix + 53 data)
        result = pattern.search("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcuvxyz")
        assert result is not None

    def test_cardano_shelley_positive_2(self) -> None:
        """Test Cardano Shelley address in context."""
        pattern = re.compile(CARDANO_ADDRESS_SHELLEY.regex)
        # Valid 103-char Cardano Shelley address
        result = pattern.search(
            "ADA wallet: addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        )
        assert result is not None

    def test_cardano_shelley_negative_1(self) -> None:
        """Test wrong prefix for Cardano."""
        pattern = re.compile(CARDANO_ADDRESS_SHELLEY.regex)
        result = pattern.search("addr2qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu")
        assert result is None

    def test_cardano_shelley_negative_2(self) -> None:
        """Test Cardano address too short."""
        pattern = re.compile(CARDANO_ADDRESS_SHELLEY.regex)
        result = pattern.search("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3")
        assert result is None


class TestSolanaPatterns:
    """Tests for Solana address patterns."""

    def test_solana_address_positive_1(self) -> None:
        """Test Solana address."""
        pattern = re.compile(SOLANA_ADDRESS.regex)
        result = pattern.search("7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV")
        assert result is not None

    def test_solana_address_positive_2(self) -> None:
        """Test Solana address in context."""
        pattern = re.compile(SOLANA_ADDRESS.regex)
        result = pattern.search("SOL: 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        assert result is not None

    def test_solana_address_negative_1(self) -> None:
        """Test Solana address too short."""
        pattern = re.compile(SOLANA_ADDRESS.regex)
        result = pattern.search("7EcDhSYGxXyscszYEp35KHN8v")
        assert result is None

    def test_solana_address_negative_2(self) -> None:
        """Test invalid Solana address with 0."""
        pattern = re.compile(SOLANA_ADDRESS.regex)
        result = pattern.search("0EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV")
        assert result is None


class TestSeedPhrasePatterns:
    """Tests for cryptocurrency seed phrase patterns."""

    def test_seed_phrase_12_words_positive_1(self) -> None:
        """Test 12-word seed phrase."""
        pattern = re.compile(SEED_PHRASE_12_WORDS.regex)
        phrase = "seed_phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'"
        result = pattern.search(phrase)
        assert result is not None

    def test_seed_phrase_12_words_positive_2(self) -> None:
        """Test 12-word mnemonic phrase."""
        pattern = re.compile(SEED_PHRASE_12_WORDS.regex)
        phrase = "mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'"
        result = pattern.search(phrase)
        assert result is not None

    def test_seed_phrase_12_words_negative_1(self) -> None:
        """Test less than 12 words."""
        pattern = re.compile(SEED_PHRASE_12_WORDS.regex)
        phrase = "seed_phrase = 'abandon abandon abandon abandon abandon'"
        result = pattern.search(phrase)
        assert result is None

    def test_seed_phrase_12_words_negative_2(self) -> None:
        """Test without seed context."""
        pattern = re.compile(SEED_PHRASE_12_WORDS.regex)
        phrase = "words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'"
        result = pattern.search(phrase)
        assert result is None

    def test_seed_phrase_24_words_positive_1(self) -> None:
        """Test 24-word seed phrase."""
        pattern = re.compile(SEED_PHRASE_24_WORDS.regex)
        words = " ".join(["abandon"] * 23 + ["art"])
        phrase = f"seed_phrase = '{words}'"
        result = pattern.search(phrase)
        assert result is not None

    def test_seed_phrase_24_words_positive_2(self) -> None:
        """Test 24-word recovery phrase."""
        pattern = re.compile(SEED_PHRASE_24_WORDS.regex)
        words = " ".join(["zoo"] * 23 + ["wrong"])
        phrase = f'recovery_phrase: "{words}"'
        result = pattern.search(phrase)
        assert result is not None

    def test_seed_phrase_24_words_negative_1(self) -> None:
        """Test less than 24 words for 24-word pattern."""
        pattern = re.compile(SEED_PHRASE_24_WORDS.regex)
        words = " ".join(["abandon"] * 12)
        phrase = f"seed_phrase = '{words}'"
        result = pattern.search(phrase)
        assert result is None

    def test_seed_phrase_24_words_negative_2(self) -> None:
        """Test without seed context."""
        pattern = re.compile(SEED_PHRASE_24_WORDS.regex)
        words = " ".join(["abandon"] * 23 + ["art"])
        phrase = f"words = '{words}'"
        result = pattern.search(phrase)
        assert result is None

    def test_seed_phrase_generic_positive_1(self) -> None:
        """Test generic seed phrase detection."""
        pattern = re.compile(SEED_PHRASE_GENERIC.regex)
        words = " ".join(["test"] * 15)
        phrase = f"backup_phrase = '{words}'"
        result = pattern.search(phrase)
        assert result is not None

    def test_seed_phrase_generic_positive_2(self) -> None:
        """Test mnemonic words detection."""
        pattern = re.compile(SEED_PHRASE_GENERIC.regex)
        words = " ".join(["word"] * 18)
        phrase = f'mnemonic_words: "{words}"'
        result = pattern.search(phrase)
        assert result is not None

    def test_seed_phrase_generic_negative_1(self) -> None:
        """Test too few words."""
        pattern = re.compile(SEED_PHRASE_GENERIC.regex)
        words = " ".join(["test"] * 5)
        phrase = f"seed = '{words}'"
        result = pattern.search(phrase)
        assert result is None

    def test_seed_phrase_generic_negative_2(self) -> None:
        """Test without seed context."""
        pattern = re.compile(SEED_PHRASE_GENERIC.regex)
        words = " ".join(["test"] * 15)
        phrase = f"text = '{words}'"
        result = pattern.search(phrase)
        assert result is None


class TestHardwareWalletPatterns:
    """Tests for hardware wallet patterns."""

    def test_trezor_passphrase_positive_1(self) -> None:
        """Test Trezor passphrase."""
        pattern = re.compile(TREZOR_PASSPHRASE.regex)
        result = pattern.search("trezor_passphrase = 'mysupersecretpassphrase'")
        assert result is not None

    def test_trezor_passphrase_positive_2(self) -> None:
        """Test Trezor passphrase alternate format."""
        pattern = re.compile(TREZOR_PASSPHRASE.regex)
        result = pattern.search('TREZOR-PASSPHRASE: "anothersecretphrase"')
        assert result is not None

    def test_trezor_passphrase_negative_1(self) -> None:
        """Test Trezor passphrase too short."""
        pattern = re.compile(TREZOR_PASSPHRASE.regex)
        result = pattern.search("trezor_passphrase = 'short'")
        assert result is None

    def test_trezor_passphrase_negative_2(self) -> None:
        """Test non-Trezor passphrase."""
        pattern = re.compile(TREZOR_PASSPHRASE.regex)
        result = pattern.search("wallet_passphrase = 'mysupersecretpassphrase'")
        assert result is None

    def test_ledger_recovery_positive_1(self) -> None:
        """Test Ledger recovery phrase."""
        pattern = re.compile(LEDGER_RECOVERY.regex)
        result = pattern.search("ledger_recovery = 'myrecoveryphrase123'")
        assert result is not None

    def test_ledger_recovery_positive_2(self) -> None:
        """Test Ledger seed phrase."""
        pattern = re.compile(LEDGER_RECOVERY.regex)
        result = pattern.search('LEDGER_SEED: "myseedphrase123"')
        assert result is not None

    def test_ledger_recovery_negative_1(self) -> None:
        """Test Ledger recovery too short."""
        pattern = re.compile(LEDGER_RECOVERY.regex)
        result = pattern.search("ledger_recovery = 'short'")
        assert result is None

    def test_ledger_recovery_negative_2(self) -> None:
        """Test non-Ledger recovery."""
        pattern = re.compile(LEDGER_RECOVERY.regex)
        result = pattern.search("wallet_recovery = 'myrecoveryphrase123'")
        assert result is None


class TestExchangeAPIPatterns:
    """Tests for cryptocurrency exchange API key patterns."""

    def test_binance_api_key_positive_1(self) -> None:
        """Test Binance API key."""
        pattern = re.compile(BINANCE_API_KEY.regex)
        key = "a" * 64
        result = pattern.search(f"binance_api_key = '{key}'")
        assert result is not None

    def test_binance_api_key_positive_2(self) -> None:
        """Test Binance API key alternate format."""
        pattern = re.compile(BINANCE_API_KEY.regex)
        key = "B" * 64
        result = pattern.search(f'BINANCE_KEY: "{key}"')
        assert result is not None

    def test_binance_api_key_negative_1(self) -> None:
        """Test Binance API key too short."""
        pattern = re.compile(BINANCE_API_KEY.regex)
        result = pattern.search("binance_api_key = 'tooshort'")
        assert result is None

    def test_binance_api_key_negative_2(self) -> None:
        """Test non-Binance API key."""
        pattern = re.compile(BINANCE_API_KEY.regex)
        key = "a" * 64
        result = pattern.search(f"api_key = '{key}'")
        assert result is None

    def test_binance_secret_key_positive_1(self) -> None:
        """Test Binance secret key."""
        pattern = re.compile(BINANCE_SECRET_KEY.regex)
        key = "a" * 64
        result = pattern.search(f"binance_api_secret = '{key}'")
        assert result is not None

    def test_binance_secret_key_positive_2(self) -> None:
        """Test Binance secret alternate format."""
        pattern = re.compile(BINANCE_SECRET_KEY.regex)
        key = "B" * 64
        result = pattern.search(f'BINANCE_SECRET: "{key}"')
        assert result is not None

    def test_binance_secret_key_negative_1(self) -> None:
        """Test Binance secret too short."""
        pattern = re.compile(BINANCE_SECRET_KEY.regex)
        result = pattern.search("binance_secret = 'tooshort'")
        assert result is None

    def test_binance_secret_key_negative_2(self) -> None:
        """Test non-Binance secret."""
        pattern = re.compile(BINANCE_SECRET_KEY.regex)
        key = "a" * 64
        result = pattern.search(f"api_secret = '{key}'")
        assert result is None

    def test_coinbase_api_key_positive_1(self) -> None:
        """Test Coinbase API key."""
        pattern = re.compile(COINBASE_API_KEY.regex)
        key = "a" * 50
        result = pattern.search(f"coinbase_api_key = '{key}'")
        assert result is not None

    def test_coinbase_api_key_positive_2(self) -> None:
        """Test Coinbase API secret."""
        pattern = re.compile(COINBASE_API_KEY.regex)
        key = "B" * 45
        result = pattern.search(f'COINBASE_SECRET: "{key}"')
        assert result is not None

    def test_coinbase_api_key_negative_1(self) -> None:
        """Test Coinbase key too short."""
        pattern = re.compile(COINBASE_API_KEY.regex)
        result = pattern.search("coinbase_api_key = 'tooshort'")
        assert result is None

    def test_coinbase_api_key_negative_2(self) -> None:
        """Test non-Coinbase key."""
        pattern = re.compile(COINBASE_API_KEY.regex)
        key = "a" * 50
        result = pattern.search(f"api_key = '{key}'")
        assert result is None

    def test_kraken_api_key_positive_1(self) -> None:
        """Test Kraken API key."""
        pattern = re.compile(KRAKEN_API_KEY.regex)
        key = "a" * 50
        result = pattern.search(f"kraken_api_key = '{key}'")
        assert result is not None

    def test_kraken_api_key_positive_2(self) -> None:
        """Test Kraken API secret."""
        pattern = re.compile(KRAKEN_API_KEY.regex)
        key = "B" * 45
        result = pattern.search(f'KRAKEN_SECRET: "{key}"')
        assert result is not None

    def test_kraken_api_key_negative_1(self) -> None:
        """Test Kraken key too short."""
        pattern = re.compile(KRAKEN_API_KEY.regex)
        result = pattern.search("kraken_api_key = 'tooshort'")
        assert result is None

    def test_kraken_api_key_negative_2(self) -> None:
        """Test non-Kraken key."""
        pattern = re.compile(KRAKEN_API_KEY.regex)
        key = "a" * 50
        result = pattern.search(f"api_key = '{key}'")
        assert result is None


class TestBlockchainExplorerPatterns:
    """Tests for blockchain explorer API key patterns."""

    def test_etherscan_api_key_positive_1(self) -> None:
        """Test Etherscan API key."""
        pattern = re.compile(ETHERSCAN_API_KEY.regex)
        key = "A" * 34
        result = pattern.search(f"etherscan_api_key = '{key}'")
        assert result is not None

    def test_etherscan_api_key_positive_2(self) -> None:
        """Test Etherscan API key alternate format."""
        pattern = re.compile(ETHERSCAN_API_KEY.regex)
        key = "B1C2D3E4F5" + "A" * 24
        result = pattern.search(f'ETHERSCAN_KEY: "{key}"')
        assert result is not None

    def test_etherscan_api_key_negative_1(self) -> None:
        """Test Etherscan key too short."""
        pattern = re.compile(ETHERSCAN_API_KEY.regex)
        result = pattern.search("etherscan_api_key = 'TOOSHORT'")
        assert result is None

    def test_etherscan_api_key_negative_2(self) -> None:
        """Test lowercase (invalid for Etherscan)."""
        pattern = re.compile(ETHERSCAN_API_KEY.regex)
        key = "a" * 34
        result = pattern.search(f"etherscan_api_key = '{key}'")
        assert result is None

    def test_infura_project_id_positive_1(self) -> None:
        """Test Infura project ID."""
        pattern = re.compile(INFURA_PROJECT_ID.regex)
        key = "a" * 32
        result = pattern.search(f"infura_project_id = '{key}'")
        assert result is not None

    def test_infura_project_id_positive_2(self) -> None:
        """Test Infura project key alternate format."""
        pattern = re.compile(INFURA_PROJECT_ID.regex)
        key = "b" * 32
        result = pattern.search(f'INFURA_KEY: "{key}"')
        assert result is not None

    def test_infura_project_id_negative_1(self) -> None:
        """Test Infura ID too short."""
        pattern = re.compile(INFURA_PROJECT_ID.regex)
        result = pattern.search("infura_project_id = 'tooshort'")
        assert result is None

    def test_infura_project_id_negative_2(self) -> None:
        """Test non-Infura project ID."""
        pattern = re.compile(INFURA_PROJECT_ID.regex)
        key = "a" * 32
        result = pattern.search(f"project_id = '{key}'")
        assert result is None

    def test_alchemy_api_key_positive_1(self) -> None:
        """Test Alchemy API key."""
        pattern = re.compile(ALCHEMY_API_KEY.regex)
        key = "a" * 32
        result = pattern.search(f"alchemy_api_key = '{key}'")
        assert result is not None

    def test_alchemy_api_key_positive_2(self) -> None:
        """Test Alchemy API key alternate format."""
        pattern = re.compile(ALCHEMY_API_KEY.regex)
        key = "B" * 32
        result = pattern.search(f'ALCHEMY_KEY: "{key}"')
        assert result is not None

    def test_alchemy_api_key_negative_1(self) -> None:
        """Test Alchemy key too short."""
        pattern = re.compile(ALCHEMY_API_KEY.regex)
        result = pattern.search("alchemy_api_key = 'tooshort'")
        assert result is None

    def test_alchemy_api_key_negative_2(self) -> None:
        """Test non-Alchemy key."""
        pattern = re.compile(ALCHEMY_API_KEY.regex)
        key = "a" * 32
        result = pattern.search(f"api_key = '{key}'")
        assert result is None


class TestCryptoPatternsCollection:
    """Tests for the CRYPTO_PATTERNS collection."""

    def test_all_patterns_in_collection(self) -> None:
        """Test that expected number of patterns are in the collection."""
        assert len(CRYPTO_PATTERNS) == 33

    def test_all_patterns_are_crypto_category(self) -> None:
        """Test that all patterns have CRYPTO category."""
        for pattern in CRYPTO_PATTERNS:
            assert pattern.category == PatternCategory.CRYPTO

    def test_all_patterns_have_descriptions(self) -> None:
        """Test that all patterns have descriptions."""
        for pattern in CRYPTO_PATTERNS:
            assert pattern.description != ""

    def test_all_patterns_have_valid_regex(self) -> None:
        """Test that all patterns have valid regex."""
        import re as regex_module

        for pattern in CRYPTO_PATTERNS:
            try:
                regex_module.compile(pattern.regex)
            except regex_module.error as e:
                pytest.fail(f"Pattern {pattern.name} has invalid regex: {e}")

    def test_all_patterns_have_unique_names(self) -> None:
        """Test that all patterns have unique names."""
        names = [p.name for p in CRYPTO_PATTERNS]
        assert len(names) == len(set(names))

    def test_patterns_to_dict_compatible(self) -> None:
        """Test that all patterns can be converted to dict format."""
        for pattern in CRYPTO_PATTERNS:
            data = pattern.to_dict()
            assert "pattern" in data
            assert "severity" in data
            assert "description" in data
            assert "category" in data
            assert "confidence" in data

    def test_private_key_patterns_are_critical(self) -> None:
        """Test that private key patterns have CRITICAL severity."""
        private_key_patterns = [
            BITCOIN_PRIVATE_KEY_WIF_UNCOMPRESSED,
            BITCOIN_PRIVATE_KEY_WIF_COMPRESSED,
            ETHEREUM_PRIVATE_KEY,
        ]
        for pattern in private_key_patterns:
            assert pattern.severity == Severity.CRITICAL

    def test_seed_phrase_patterns_are_critical(self) -> None:
        """Test that seed phrase patterns have CRITICAL severity."""
        seed_patterns = [
            SEED_PHRASE_12_WORDS,
            SEED_PHRASE_24_WORDS,
            SEED_PHRASE_GENERIC,
        ]
        for pattern in seed_patterns:
            assert pattern.severity == Severity.CRITICAL

    def test_exchange_api_patterns_are_critical(self) -> None:
        """Test that exchange API key patterns have CRITICAL severity."""
        exchange_patterns = [
            BINANCE_API_KEY,
            BINANCE_SECRET_KEY,
            COINBASE_API_KEY,
            KRAKEN_API_KEY,
        ]
        for pattern in exchange_patterns:
            assert pattern.severity == Severity.CRITICAL

    def test_address_patterns_are_medium_severity(self) -> None:
        """Test that address patterns have appropriate severity."""
        address_patterns = [
            BITCOIN_ADDRESS_P2PKH,
            BITCOIN_ADDRESS_P2SH,
            BITCOIN_ADDRESS_BECH32,
            ETHEREUM_ADDRESS,
        ]
        for pattern in address_patterns:
            assert pattern.severity == Severity.MEDIUM
