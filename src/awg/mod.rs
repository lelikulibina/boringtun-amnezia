//! Модули преобразования AmneziaWG поверх канонических WireGuard-пакетов.

/// Кодек S1-S4 и header protection.
pub mod packet_codec;

/// Высокоуровневая обёртка BoringTun с AWG framing.
pub mod tunnel;
