package com.crypto.crypto.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(@NotBlank String username,
    @NotBlank String password){}
