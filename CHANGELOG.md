# Changelog

We will attempt to document all significant changes to the FidoVault project in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). We try to follow some, but not all, of the rules and recommendations of [Common Changelog](https://common-changelog.org).

This project attempts to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-28

### Changed

 - **Breaking:** Switch from PBKDF2HMAC to Argon2id for key derivation   ([a3ee9f2](https://github.com/tmo1/fidovault/commit/a3ee9f21f8d9d58a53498f69a9f8b0780c8b35f8))
 - **Breaking:** Store KDF algorithm and parameters in vault ([277ac6e](https://github.com/tmo1/fidovault/commit/277ac6eddcfc6427abcbb8c02df66d195f5f81c8))
 - **Breaking:** Switch from hex (Base16) to Base64 for storing binary data ([277ac6e](https://github.com/tmo1/fidovault/commit/277ac6eddcfc6427abcbb8c02df66d195f5f81c8))
 
### Added

 - Implement memory security on Linux ([3bf9683](https://github.com/tmo1/fidovault/commit/3bf9683c1d60088cbddd99c6c9e8caaceadc5b6a))
 - Add secret generation option ([f870fc3](https://github.com/tmo1/fidovault/commit/f870fc350992ac9f477cf641e78f8657f5d533d3))
 - Allow user specification of KDF parameters ([b376950](https://github.com/tmo1/fidovault/commit/b376950771f9ff3cd58e7005d329917a07d0bb41))

## [0.1.0] - 2026-01-09

_Initial release_

[0.1.0]: https://github.com/tmo1/fidovault/releases/tag/v0.1.0
[0.2.0]: https://github.com/tmo1/fidovault/releases/tag/v0.2.0
[Unreleased]: https://github.com/tmo1/fidovault/compare/v0.2.0...HEAD
