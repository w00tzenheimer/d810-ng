"""Unit tests for d810.core.platform module."""

import pytest

from d810.core.platform import (
    ARCH_CONFIG_KEYS,
    FileFormat,
    Platform,
    get_format_config_keys,
    is_arch_specific_config,
    resolve_arch_config,
)


class TestArchConfigKeys:
    """Tests for ARCH_CONFIG_KEYS constant."""

    def test_contains_expected_keys(self):
        """Verify all expected architecture config keys are present."""
        expected = {"default", "macho", "elf", "pe", "darwin", "linux", "windows"}
        assert ARCH_CONFIG_KEYS == expected


class TestIsArchSpecificConfig:
    """Tests for is_arch_specific_config function."""

    def test_empty_config_not_arch_specific(self):
        """Empty config should not be considered arch-specific."""
        assert not is_arch_specific_config({})

    def test_plain_config_not_arch_specific(self):
        """Plain config with regular keys should not be arch-specific."""
        config = {"min_size": 4, "allow_executable_readonly": True}
        assert not is_arch_specific_config(config)

    def test_default_key_is_arch_specific(self):
        """Config with 'default' key should be arch-specific."""
        config = {"default": {}}
        assert is_arch_specific_config(config)

    def test_macho_key_is_arch_specific(self):
        """Config with 'macho' key should be arch-specific."""
        config = {"macho": {"allow_executable_readonly": True}}
        assert is_arch_specific_config(config)

    def test_elf_key_is_arch_specific(self):
        """Config with 'elf' key should be arch-specific."""
        config = {"elf": {}}
        assert is_arch_specific_config(config)

    def test_pe_key_is_arch_specific(self):
        """Config with 'pe' key should be arch-specific."""
        config = {"pe": {}}
        assert is_arch_specific_config(config)

    def test_darwin_key_is_arch_specific(self):
        """Config with 'darwin' key should be arch-specific."""
        config = {"darwin": {}}
        assert is_arch_specific_config(config)

    def test_linux_key_is_arch_specific(self):
        """Config with 'linux' key should be arch-specific."""
        config = {"linux": {}}
        assert is_arch_specific_config(config)

    def test_windows_key_is_arch_specific(self):
        """Config with 'windows' key should be arch-specific."""
        config = {"windows": {}}
        assert is_arch_specific_config(config)

    def test_mixed_keys_is_arch_specific(self):
        """Config mixing arch keys with regular keys should be arch-specific."""
        config = {"default": {"min_size": 4}, "macho": {"extra": True}, "other_key": 1}
        assert is_arch_specific_config(config)


class TestGetFormatConfigKeys:
    """Tests for get_format_config_keys function."""

    def test_macho_keys(self):
        """Mach-O format should return macho, darwin, default keys."""
        keys = get_format_config_keys(FileFormat.MACHO)
        assert keys == ["macho", "darwin", "default"]

    def test_elf_keys(self):
        """ELF format should return elf, linux, default keys."""
        keys = get_format_config_keys(FileFormat.ELF)
        assert keys == ["elf", "linux", "default"]

    def test_pe_keys(self):
        """PE format should return pe, windows, default keys."""
        keys = get_format_config_keys(FileFormat.PE)
        assert keys == ["pe", "windows", "default"]

    def test_unknown_keys(self):
        """Unknown format should return only default key."""
        keys = get_format_config_keys(FileFormat.UNKNOWN)
        assert keys == ["default"]

    def test_raw_keys(self):
        """Raw format should return only default key."""
        keys = get_format_config_keys(FileFormat.RAW)
        assert keys == ["default"]


class TestResolveArchConfig:
    """Tests for resolve_arch_config function."""

    def test_plain_config_unchanged(self):
        """Plain config without arch keys should be returned unchanged."""
        config = {"min_size": 4, "allow_executable_readonly": True}
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == config

    def test_empty_config_unchanged(self):
        """Empty config should be returned unchanged."""
        config = {}
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {}

    def test_default_only_returns_default(self):
        """Config with only default should return default contents."""
        config = {"default": {"min_size": 4}}
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"min_size": 4}

    def test_macho_override_applied(self):
        """Mach-O specific config should be merged with default."""
        config = {
            "default": {"min_size": 4},
            "macho": {"allow_executable_readonly": True},
        }
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"min_size": 4, "allow_executable_readonly": True}

    def test_darwin_override_applied_for_macho(self):
        """Darwin config should apply to Mach-O format."""
        config = {
            "default": {"min_size": 4},
            "darwin": {"allow_executable_readonly": True},
        }
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"min_size": 4, "allow_executable_readonly": True}

    def test_macho_takes_precedence_over_darwin(self):
        """macho key should take precedence over darwin key."""
        config = {
            "default": {"min_size": 4},
            "darwin": {"setting": "darwin_value"},
            "macho": {"setting": "macho_value"},
        }
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"min_size": 4, "setting": "macho_value"}

    def test_elf_override_applied(self):
        """ELF specific config should be merged with default."""
        config = {
            "default": {"min_size": 4},
            "elf": {"strict_perms": True},
        }
        result = resolve_arch_config(config, FileFormat.ELF)
        assert result == {"min_size": 4, "strict_perms": True}

    def test_linux_override_applied_for_elf(self):
        """Linux config should apply to ELF format."""
        config = {
            "default": {"min_size": 4},
            "linux": {"strict_perms": True},
        }
        result = resolve_arch_config(config, FileFormat.ELF)
        assert result == {"min_size": 4, "strict_perms": True}

    def test_pe_override_applied(self):
        """PE specific config should be merged with default."""
        config = {
            "default": {"min_size": 4},
            "pe": {"check_signatures": True},
        }
        result = resolve_arch_config(config, FileFormat.PE)
        assert result == {"min_size": 4, "check_signatures": True}

    def test_windows_override_applied_for_pe(self):
        """Windows config should apply to PE format."""
        config = {
            "default": {"min_size": 4},
            "windows": {"check_signatures": True},
        }
        result = resolve_arch_config(config, FileFormat.PE)
        assert result == {"min_size": 4, "check_signatures": True}

    def test_no_matching_override_uses_default(self):
        """When no matching arch key exists, only default is used."""
        config = {
            "default": {"min_size": 4},
            "macho": {"allow_executable_readonly": True},
        }
        result = resolve_arch_config(config, FileFormat.ELF)
        assert result == {"min_size": 4}

    def test_override_can_overwrite_default_values(self):
        """Arch-specific values should override default values."""
        config = {
            "default": {"min_size": 4, "strict": False},
            "macho": {"min_size": 8},
        }
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"min_size": 8, "strict": False}

    def test_unknown_format_uses_only_default(self):
        """Unknown format should only use default config."""
        config = {
            "default": {"min_size": 4},
            "macho": {"extra": True},
            "elf": {"extra": True},
            "pe": {"extra": True},
        }
        result = resolve_arch_config(config, FileFormat.UNKNOWN)
        assert result == {"min_size": 4}

    def test_missing_default_with_matching_arch(self):
        """Config without default but with matching arch should work."""
        config = {"macho": {"allow_executable_readonly": True}}
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"allow_executable_readonly": True}

    def test_missing_default_with_no_matching_arch(self):
        """Config without default and no matching arch returns empty."""
        config = {"macho": {"allow_executable_readonly": True}}
        result = resolve_arch_config(config, FileFormat.ELF)
        assert result == {}

    def test_real_world_fold_readonly_config(self):
        """Test the real-world FoldReadonlyDataRule config pattern."""
        # This matches the pattern in example_libobfuscated.json
        config = {"default": {}, "macho": {"allow_executable_readonly": True}}

        # On Mach-O binary
        result = resolve_arch_config(config, FileFormat.MACHO)
        assert result == {"allow_executable_readonly": True}

        # On ELF binary
        result = resolve_arch_config(config, FileFormat.ELF)
        assert result == {}

        # On PE binary
        result = resolve_arch_config(config, FileFormat.PE)
        assert result == {}
