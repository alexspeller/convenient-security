#ifndef CSEC_SECRET_HEURISTICS_H
#define CSEC_SECRET_HEURISTICS_H

#include <stddef.h>
#include <stdint.h>

/// Shared, value-free secret-shape heuristics. These functions inspect bytes
/// in place and return only a verdict or aggregate entropy; they never retain
/// or emit the supplied value.
int32_t cs_secret_name_looks_secret_like(
    const uint8_t *name, size_t name_length
);
int32_t cs_secret_value_looks_secret_like(
    const uint8_t *value, size_t value_length
);
double cs_secret_shannon_entropy_bits_per_byte(
    const uint8_t *value, size_t value_length
);

#endif /* CSEC_SECRET_HEURISTICS_H */
