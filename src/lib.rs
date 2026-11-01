#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Конфигурационный API и протокольная основа WireGuard / AmneziaWG.
//!
//! Криптографическое ядро WireGuard предоставляется закреплённой зависимостью
//! Cloudflare BoringTun. Собственный AWG packet transformation пока не реализован.

/// Прямой доступ к проверенному протокольному движку Cloudflare BoringTun.
#[cfg(feature = "wireguard")]
pub mod wireguard {
    pub use boringtun::noise::{Packet, Tunn, TunnResult};
    pub use boringtun::x25519;
}

/// Режим протокола, который должен использовать будущий движок.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolMode {
    /// Стандартный WireGuard без модификаций пакетов.
    #[default]
    WireGuard,
    /// AmneziaWG поколения 3.0.
    AmneziaWg30,
    /// AmneziaWG поколения 3.1.
    AmneziaWg31,
}

/// Диапазон целочисленного параметра AWG. Границы включительные.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueRange {
    /// Нижняя включительная граница.
    pub min: u32,
    /// Верхняя включительная граница.
    pub max: u32,
}

impl ValueRange {
    /// Создаёт диапазон, отклоняя обратные границы.
    pub fn new(min: u32, max: u32) -> Result<Self, ConfigError> {
        if min > max {
            return Err(ConfigError::InvalidRange { min, max });
        }
        Ok(Self { min, max })
    }

    /// Проверяет, входит ли значение в диапазон.
    pub fn contains(self, value: u32) -> bool {
        (self.min..=self.max).contains(&value)
    }
}

/// Параметры маскирования заголовков AWG 3+.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderObfuscation {
    /// Значение H1 — тип заголовка handshake initiation.
    pub h1: Option<ValueRange>,
    /// Значение H2 — тип заголовка handshake response.
    pub h2: Option<ValueRange>,
    /// Значение H3 — тип заголовка cookie reply.
    pub h3: Option<ValueRange>,
    /// Значение H4 — тип заголовка transport data.
    pub h4: Option<ValueRange>,
    /// Ключ защиты заголовков. Секрет не должен попадать в логи.
    pub header_protection_key: Option<[u8; 32]>,
}

/// Дополнение пакетов AWG.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacketPadding {
    /// Дополнение handshake initiation (S1).
    pub s1: Option<u16>,
    /// Дополнение handshake response (S2).
    pub s2: Option<u16>,
    /// Дополнение cookie reply (S3).
    pub s3: Option<u16>,
    /// Дополнение transport data (S4).
    pub s4: Option<u16>,
    /// Диапазон дополнительного content padding.
    pub content_padding: Option<ValueRange>,
}

/// Конфигурация AWG, общая для поколений 3.0 и 3.1 на уровне типов.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmneziaConfig {
    /// Настройки H1-H4 и header protection.
    pub headers: HeaderObfuscation,
    /// Настройки S1-S4 и content padding.
    pub padding: PacketPadding,
}

/// Конфигурация выбранного режима протокола.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineConfig {
    /// Выбранный режим.
    pub mode: ProtocolMode,
    /// Дополнительные параметры AmneziaWG. Для WireGuard поле должно быть пустым.
    pub amnezia: Option<AmneziaConfig>,
}

impl EngineConfig {
    /// Проверяет согласованность режима и дополнительных параметров.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match (self.mode, self.amnezia.as_ref()) {
            (ProtocolMode::WireGuard, Some(_)) => Err(ConfigError::AmneziaOptionsForWireGuard),
            (ProtocolMode::WireGuard, None) => Ok(()),
            (ProtocolMode::AmneziaWg30 | ProtocolMode::AmneziaWg31, None) => {
                Err(ConfigError::MissingAmneziaOptions)
            }
            (ProtocolMode::AmneziaWg30 | ProtocolMode::AmneziaWg31, Some(config)) => {
                for range in [
                    config.headers.h1,
                    config.headers.h2,
                    config.headers.h3,
                    config.headers.h4,
                    config.padding.content_padding,
                ].into_iter().flatten() {
                    if range.min > range.max {
                        return Err(ConfigError::InvalidRange { min: range.min, max: range.max });
                    }
                }
                // AmneziaWG documents a minimum padding requirement for header
                // protection. Keep this check explicit until per-version rules
                // are verified against the matching upstream source revision.
                if config.headers.header_protection_key.is_some()
                    && [config.padding.s1, config.padding.s2, config.padding.s3, config.padding.s4]
                        .into_iter()
                        .flatten()
                        .any(|padding| padding < 12)
                {
                    return Err(ConfigError::HeaderProtectionRequiresPaddingAtLeast12);
                }
                Ok(())
            }
        }
    }
}

/// Ошибки проверки конфигурации.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Нижняя граница диапазона больше верхней.
    InvalidRange { min: u32, max: u32 },
    /// Для AWG-режима не переданы AWG-параметры.
    MissingAmneziaOptions,
    /// Для чистого WireGuard переданы параметры AWG.
    AmneziaOptionsForWireGuard,
    /// Защита заголовков требует padding не меньше 12 байт.
    HeaderProtectionRequiresPaddingAtLeast12,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRange { min, max } => write!(f, "некорректный диапазон: минимум {min} больше максимума {max}"),
            Self::MissingAmneziaOptions => f.write_str("для режима AmneziaWG необходима конфигурация AWG"),
            Self::AmneziaOptionsForWireGuard => f.write_str("параметры AmneziaWG нельзя передавать в режиме WireGuard"),
            Self::HeaderProtectionRequiresPaddingAtLeast12 => f.write_str("защита заголовков требует padding не меньше 12 байт"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_range_accepts_fixed_and_inclusive_values() {
        let fixed = ValueRange::new(7, 7).expect("fixed range is valid");
        assert!(fixed.contains(7));
        assert!(!fixed.contains(6));
        let range = ValueRange::new(2, 5).expect("ordered range is valid");
        assert!(range.contains(2));
        assert!(range.contains(5));
        assert!(!range.contains(1));
        assert!(!range.contains(6));
    }

    #[test]
    fn value_range_rejects_reversed_bounds() {
        assert_eq!(ValueRange::new(9, 3), Err(ConfigError::InvalidRange { min: 9, max: 3 }));
    }

    #[test]
    fn plain_wireguard_rejects_amnezia_options() {
        let config = EngineConfig { mode: ProtocolMode::WireGuard, amnezia: Some(AmneziaConfig::default()) };
        assert_eq!(config.validate(), Err(ConfigError::AmneziaOptionsForWireGuard));
    }

    #[test]
    fn awg_modes_require_explicit_configuration() {
        for mode in [ProtocolMode::AmneziaWg30, ProtocolMode::AmneziaWg31] {
            let config = EngineConfig { mode, amnezia: None };
            assert_eq!(config.validate(), Err(ConfigError::MissingAmneziaOptions));
        }
    }

    #[test]
    fn header_protection_rejects_any_configured_padding_below_twelve() {
        for (s1, s2, s3, s4) in [
            (Some(11), None, None, None),
            (None, Some(11), None, None),
            (None, None, Some(11), None),
            (None, None, None, Some(11)),
        ] {
            let mut awg = AmneziaConfig::default();
            awg.headers.header_protection_key = Some([0x42; 32]);
            awg.padding = PacketPadding { s1, s2, s3, s4, content_padding: None };
            let config = EngineConfig { mode: ProtocolMode::AmneziaWg30, amnezia: Some(awg) };
            assert_eq!(config.validate(), Err(ConfigError::HeaderProtectionRequiresPaddingAtLeast12));
        }
    }

    #[test]
    fn header_protection_accepts_configured_padding_of_twelve() {
        let mut awg = AmneziaConfig::default();
        awg.headers.header_protection_key = Some([0x42; 32]);
        awg.padding.s1 = Some(12);
        let config = EngineConfig { mode: ProtocolMode::AmneziaWg31, amnezia: Some(awg) };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn awg_accepts_empty_optional_obfuscation_settings() {
        let config = EngineConfig { mode: ProtocolMode::AmneziaWg30, amnezia: Some(AmneziaConfig::default()) };
        assert_eq!(config.validate(), Ok(()));
    }
}
