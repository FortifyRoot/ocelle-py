"""Internal constants for FortifyRoot SDK."""

# Attribute prefix for renaming traceloop.* -> fortifyroot.*
ATTRIBUTE_PREFIX_TRACELOOP = "traceloop."
ATTRIBUTE_PREFIX_FORTIFYROOT = "fortifyroot."

# Resource attribute keys for FR SDK metadata
FORTIFYROOT_SDK_VERSION_ATTRIBUTE = "fortifyroot.sdk.version"

# SDK metadata headers attached to FortifyRoot-owned backend calls.
FORTIFYROOT_SDK_VERSION_HEADER = "X-FortifyRoot-SDK-Version"
FORTIFYROOT_SDK_LANGUAGE_HEADER = "X-FortifyRoot-SDK-Language"
FORTIFYROOT_SDK_LANGUAGE_VERSION_HEADER = "X-FortifyRoot-SDK-Language-Version"
FORTIFYROOT_SDK_LANGUAGE = "python"
