#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Конфигурационный API и протокольная основа WireGuard / AmneziaWG.
//!
//! Криптографическое ядро WireGuard предоставляется закреплённой зависимостью
//! Cloudflare BoringTun. AWG framing реализован отдельными модулями с явными
//! ограничениями по неподдерживаемым расширениям.

/// Прямой доступ к протокольному движку Cloudflare BoringTun.
#[cfg(feature = "wireguard")]
pub mod wireguard {
    pub use boringtun::noise::{Packet, Tunn, TunnResult};
    pub use boringtun::x25519;
}

/// Кодек базового AWG packet framing (S1-S4 и header protection).
#[cfg(feature = "amneziawg")]
pub mod awg;

/// CPS-парсер и генератор сигнатурных пакетов AmneziaWG.
#[cfg(feature = "amneziawg")]
pub mod signature;

/// Основные типы CPS-шаблонов, доступные из корня crate.
#[cfg(feature = "amneziawg")]
pub use signature::{SignatureError, SignatureTemplate};

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

/// Диапазон целочисленного параметра AWG.
///
/// Верхняя граница исключительная, кроме фиксированного значения min == max.
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

    /// Проверяет, входит ли значение в полуоткрытый диапазон.
    ///
    /// При min == max диапазон представляет единственное фиксированное значение.
    pub fn contains(self, value: u32) -> bool {
        if self.min == self.max {
            value == self.min
        } else {
            (self.min..self.max).contains(&value)
        }
    }
}

/// Разбирает AWG-значение диапазона: число, диапазон или явное отключение.
pub fn parse_optional_range(value: &str) -> Result<Option<ValueRange>, ConfigError> {
    let value = value.trim();
    if value == "(off)" || value.eq_ignore_ascii_case("off") {
        return Ok(None);
    }

    let parse_number = |part: &str| {
        part.trim()
            .parse::<u32>()
            .map_err(|_| ConfigError::InvalidRangeSyntax(value.to_owned()))
    };

    if let Some((min, max)) = value.split_once('-') {
        if max.contains('-') {
            return Err(ConfigError::InvalidRangeSyntax(value.to_owned()));
        }
        return ValueRange::new(parse_number(min)?, parse_number(max)?).map(Some);
    }

    let fixed = parse_number(value)?;
    Ok(Some(ValueRange {
        min: fixed,
        max: fixed,
    }))
}

/// Параметры маскирования заголовков AWG 3+.
#[derive(Clone, PartialEq, Eq, Default)]
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

impl Drop for HeaderObfuscation {
    fn drop(&mut self) {
        if let Some(key) = self.header_protection_key.as_mut() {
            key.zeroize();
        }
    }
}

impl core::fmt::Debug for HeaderObfuscation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeaderObfuscation")
            .field("h1", &self.h1)
            .field("h2", &self.h2)
            .field("h3", &self.h3)
            .field("h4", &self.h4)
            // Never expose key material through derived configuration Debug output.
            .field(
                "header_protection_key",
                &self.header_protection_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
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

/// Настройки junk-пакетов, отправляемых перед handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JunkConfig {
    /// Количество junk-пакетов.
    pub count: u32,
    /// Минимальный размер junk-пакета в байтах.
    pub min_size: u32,
    /// Максимальный размер junk-пакета в байтах.
    pub max_size: u32,
}

/// Настройки рандомизируемых таймеров AWG 3+.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimingConfig {
    /// Интервал до инициирования повторного handshake.
    pub rekey_after_time: Option<ValueRange>,
    /// Таймаут повторной отправки handshake.
    pub rekey_timeout: Option<ValueRange>,
    /// Время отклонения устаревших ключей.
    pub reject_after_time: Option<ValueRange>,
    /// Таймаут отправки keepalive.
    pub keepalive_timeout: Option<ValueRange>,
    /// Максимальное число попыток handshake.
    pub max_handshake_attempts: Option<ValueRange>,
}

/// Конфигурация AWG, общая для поколений 3.0 и 3.1 на уровне типов.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmneziaConfig {
    /// Настройки H1-H4 и header protection.
    pub headers: HeaderObfuscation,
    /// Настройки S1-S4 и content padding.
    pub padding: PacketPadding,
    /// Настройки junk-пакетов.
    pub junk: JunkConfig,
    /// Рандомизируемые таймеры AWG 3+.
    pub timings: TimingConfig,
    /// AWG 3.1: случайные trailer-данные для транспортных пакетов.
    pub random_trailers: bool,
    /// AWG 3.1: отключение cookie-механизма.
    pub disable_cookies: bool,
    /// До пяти шаблонов сигнатурных пакетов I1-I5.
    pub signature_packets: [Option<crate::signature::SignatureTemplate>; 5],
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
                let ranges = [
                    config.headers.h1,
                    config.headers.h2,
                    config.headers.h3,
                    config.headers.h4,
                    config.padding.content_padding,
                    config.timings.rekey_after_time,
                    config.timings.rekey_timeout,
                    config.timings.reject_after_time,
                    config.timings.keepalive_timeout,
                    config.timings.max_handshake_attempts,
                ];
                for range in ranges.into_iter().flatten() {
                    if range.min > range.max {
                        return Err(ConfigError::InvalidRange {
                            min: range.min,
                            max: range.max,
                        });
                    }
                }

                let header_ranges = [
                    config.headers.h1.unwrap_or(ValueRange { min: 1, max: 1 }),
                    config.headers.h2.unwrap_or(ValueRange { min: 2, max: 2 }),
                    config.headers.h3.unwrap_or(ValueRange { min: 3, max: 3 }),
                    config.headers.h4.unwrap_or(ValueRange { min: 4, max: 4 }),
                ];
                for left_index in 0..header_ranges.len() {
                    for right_index in (left_index + 1)..header_ranges.len() {
                        let left = header_ranges[left_index];
                        let right = header_ranges[right_index];
                        let left_start = u64::from(left.min);
                        let left_end = if left.min == left.max {
                            left_start + 1
                        } else {
                            u64::from(left.max)
                        };
                        let right_start = u64::from(right.min);
                        let right_end = if right.min == right.max {
                            right_start + 1
                        } else {
                            u64::from(right.max)
                        };
                        if left_start < right_end && right_start < left_end {
                            return Err(ConfigError::OverlappingHeaderRanges);
                        }
                    }
                }

                if config.junk.count > 64 {
                    return Err(ConfigError::JunkPacketCountTooLarge {
                        count: config.junk.count,
                        max: 64,
                    });
                }

                if config.junk.count > 0
                    && (config.junk.min_size > config.junk.max_size
                        || config.junk.max_size > 65_507)
                {
                    return Err(ConfigError::InvalidJunkPacketBounds {
                        min: config.junk.min_size,
                        max: config.junk.max_size,
                    });
                }

                // The upstream UAPI requires every S1-S4 value to be at least
                // HeaderCipherNonceSize when header protection is enabled.
                // Missing values are treated as zero, not as "not applicable".
                let header_protection_enabled = config
                    .headers
                    .header_protection_key
                    .is_some_and(|key| key.iter().any(|byte| *byte != 0));
                if header_protection_enabled
                    && [
                        config.padding.s1,
                        config.padding.s2,
                        config.padding.s3,
                        config.padding.s4,
                    ]
                    .into_iter()
                    .any(|padding| padding.unwrap_or(0) < 12)
                {
                    return Err(ConfigError::HeaderProtectionRequiresAllPaddingAtLeast12);
                }

                if self.mode == ProtocolMode::AmneziaWg30
                    && (config.random_trailers || config.disable_cookies)
                {
                    return Err(ConfigError::FeatureRequiresAmneziaWg31);
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
    InvalidRange {
        /// Запрошенная нижняя граница.
        min: u32,
        /// Запрошенная верхняя граница.
        max: u32,
    },
    /// Строка диапазона не соответствует формату AWG.
    InvalidRangeSyntax(String),
    /// Диапазоны H1-H4 пересекаются.
    OverlappingHeaderRanges,
    /// Для AWG-режима не переданы AWG-параметры.
    MissingAmneziaOptions,
    /// Для чистого WireGuard переданы параметры AWG.
    AmneziaOptionsForWireGuard,
    /// Number of junk packets exceeds the implementation safety limit.
    JunkPacketCountTooLarge {
        /// Requested number of packets.
        count: u32,
        /// Maximum supported number of packets per handshake.
        max: u32,
    },
    /// Junk packet size range is invalid or exceeds the UDP payload ceiling.
    InvalidJunkPacketBounds {
        /// Минимальный запрошенный размер.
        min: u32,
        /// Максимальный запрошенный размер.
        max: u32,
    },
    /// Header protection requires all four S1-S4 paddings to be at least 12 bytes.
    HeaderProtectionRequiresAllPaddingAtLeast12,
    /// Параметр доступен только в режиме AmneziaWG 3.1.
    FeatureRequiresAmneziaWg31,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRange { min, max } => write!(
                f,
                "некорректный диапазон: минимум {min} больше максимума {max}"
            ),
            Self::InvalidRangeSyntax(value) => {
                write!(f, "неверный формат диапазона: {value}")
            }
            Self::OverlappingHeaderRanges => f.write_str("диапазоны H1-H4 не должны пересекаться"),
            Self::MissingAmneziaOptions => {
                f.write_str("для режима AmneziaWG необходима конфигурация AWG")
            }
            Self::AmneziaOptionsForWireGuard => {
                f.write_str("параметры AmneziaWG нельзя передавать в режиме WireGuard")
            }
            Self::JunkPacketCountTooLarge { count, max } => {
                write!(f, "количество junk-пакетов {count} превышает лимит {max}")
            }
            Self::InvalidJunkPacketBounds { min, max } => {
                write!(f, "некорректный размер junk-пакетов: {min}..{max}")
            }
            Self::HeaderProtectionRequiresAllPaddingAtLeast12 => {
                f.write_str("защита заголовков требует S1, S2, S3 и S4 не меньше 12 байт")
            }
            Self::FeatureRequiresAmneziaWg31 => {
                f.write_str("random_trailers и disable_cookies доступны только в AmneziaWG 3.1")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_range_accepts_fixed_and_half_open_values() {
        let fixed = ValueRange::new(7, 7).expect("fixed range is valid");
        assert!(fixed.contains(7));
        assert!(!fixed.contains(6));
        let range = ValueRange::new(2, 5).expect("ordered range is valid");
        assert!(range.contains(2));
        assert!(range.contains(4));
        assert!(!range.contains(1));
        assert!(!range.contains(5));
    }

    #[test]
    fn parses_fixed_ranges_ranges_and_off_values() {
        assert_eq!(
            parse_optional_range("12"),
            Ok(Some(ValueRange { min: 12, max: 12 }))
        );
        assert_eq!(
            parse_optional_range("10-20"),
            Ok(Some(ValueRange { min: 10, max: 20 }))
        );
        assert_eq!(parse_optional_range("(off)"), Ok(None));
        assert_eq!(parse_optional_range("off"), Ok(None));
        assert!(parse_optional_range("20-10").is_err());
        assert!(parse_optional_range("1-2-3").is_err());
    }

    #[test]
    fn value_range_rejects_reversed_bounds() {
        assert_eq!(
            ValueRange::new(9, 3),
            Err(ConfigError::InvalidRange { min: 9, max: 3 })
        );
    }

    #[test]
    fn plain_wireguard_rejects_amnezia_options() {
        let config = EngineConfig {
            mode: ProtocolMode::WireGuard,
            amnezia: Some(AmneziaConfig::default()),
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::AmneziaOptionsForWireGuard)
        );
    }

    #[test]
    fn awg_modes_require_explicit_configuration() {
        for mode in [ProtocolMode::AmneziaWg30, ProtocolMode::AmneziaWg31] {
            let config = EngineConfig {
                mode,
                amnezia: None,
            };
            assert_eq!(config.validate(), Err(ConfigError::MissingAmneziaOptions));
        }
    }

    #[test]
    fn header_protection_requires_all_four_paddings() {
        for missing_index in 0..4 {
            let mut values = [Some(12); 4];
            values[missing_index] = None;
            let mut awg = AmneziaConfig::default();
            awg.headers.header_protection_key = Some([0x42; 32]);
            awg.padding = PacketPadding {
                s1: values[0],
                s2: values[1],
                s3: values[2],
                s4: values[3],
                content_padding: None,
            };
            let config = EngineConfig {
                mode: ProtocolMode::AmneziaWg30,
                amnezia: Some(awg),
            };
            assert_eq!(
                config.validate(),
                Err(ConfigError::HeaderProtectionRequiresAllPaddingAtLeast12)
            );
        }
    }

    #[test]
    fn header_protection_rejects_each_padding_below_twelve() {
        for index in 0..4 {
            let mut values = [Some(12); 4];
            values[index] = Some(11);
            let mut awg = AmneziaConfig::default();
            awg.headers.header_protection_key = Some([0x42; 32]);
            awg.padding = PacketPadding {
                s1: values[0],
                s2: values[1],
                s3: values[2],
                s4: values[3],
                content_padding: None,
            };
            let config = EngineConfig {
                mode: ProtocolMode::AmneziaWg30,
                amnezia: Some(awg),
            };
            assert_eq!(
                config.validate(),
                Err(ConfigError::HeaderProtectionRequiresAllPaddingAtLeast12)
            );
        }
    }

    #[test]
    fn header_protection_key_is_redacted_from_configuration_debug() {
        let mut config = AmneziaConfig::default();
        config.headers.header_protection_key = Some([0xab; 32]);

        let rendered = format!("{config:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("abababab"));
    }

    #[test]
    fn all_zero_header_protection_key_is_treated_as_disabled() {
        let mut awg = AmneziaConfig::default();
        awg.headers.header_protection_key = Some([0; 32]);
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(awg),
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn header_protection_accepts_all_four_paddings_of_twelve() {
        let mut awg = AmneziaConfig::default();
        awg.headers.header_protection_key = Some([0x42; 32]);
        awg.padding = PacketPadding {
            s1: Some(12),
            s2: Some(12),
            s3: Some(12),
            s4: Some(12),
            content_padding: None,
        };
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg31,
            amnezia: Some(awg),
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn awg_31_flags_are_rejected_in_awg_30() {
        for (random_trailers, disable_cookies) in [(true, false), (false, true), (true, true)] {
            let awg = AmneziaConfig {
                random_trailers,
                disable_cookies,
                ..AmneziaConfig::default()
            };
            let config = EngineConfig {
                mode: ProtocolMode::AmneziaWg30,
                amnezia: Some(awg),
            };
            assert_eq!(
                config.validate(),
                Err(ConfigError::FeatureRequiresAmneziaWg31)
            );
        }
    }

    #[test]
    fn awg_31_flags_are_accepted_in_awg_31() {
        let awg = AmneziaConfig {
            random_trailers: true,
            disable_cookies: true,
            ..AmneziaConfig::default()
        };
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg31,
            amnezia: Some(awg),
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn overlapping_header_ranges_are_rejected() {
        let mut awg = AmneziaConfig::default();
        awg.headers.h1 = Some(ValueRange { min: 1, max: 5 });
        awg.headers.h2 = Some(ValueRange { min: 4, max: 9 });
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(awg),
        };
        assert_eq!(config.validate(), Err(ConfigError::OverlappingHeaderRanges));
    }

    #[test]
    fn header_ranges_cannot_overlap_implicit_standard_type_ids() {
        let mut awg = AmneziaConfig::default();
        awg.headers.h1 = Some(ValueRange { min: 1, max: 3 });
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(awg),
        };
        assert_eq!(config.validate(), Err(ConfigError::OverlappingHeaderRanges));
    }

    #[test]
    fn adjacent_header_ranges_are_accepted() {
        let mut awg = AmneziaConfig::default();
        // Keep the test ranges clear of the implicit default H3=3 and H4=4.
        // Ranges use the upstream half-open [min, max) semantics.
        awg.headers.h1 = Some(ValueRange { min: 10, max: 14 });
        awg.headers.h2 = Some(ValueRange { min: 14, max: 18 });
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(awg),
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn junk_packet_count_is_bounded() {
        let awg = AmneziaConfig {
            junk: JunkConfig {
                count: 65,
                min_size: 10,
                max_size: 20,
            },
            ..AmneziaConfig::default()
        };
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(awg),
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::JunkPacketCountTooLarge { count: 65, max: 64 })
        );
    }

    #[test]
    fn junk_packet_bounds_are_validated() {
        let awg = AmneziaConfig {
            junk: JunkConfig {
                count: 3,
                min_size: 80,
                max_size: 40,
            },
            ..AmneziaConfig::default()
        };
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(awg),
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidJunkPacketBounds { min: 80, max: 40 })
        );
    }

    #[test]
    fn awg_accepts_empty_optional_obfuscation_settings() {
        let config = EngineConfig {
            mode: ProtocolMode::AmneziaWg30,
            amnezia: Some(AmneziaConfig::default()),
        };
        assert_eq!(config.validate(), Ok(()));
    }
}
