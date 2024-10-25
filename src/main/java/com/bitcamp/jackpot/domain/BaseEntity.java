package com.bitcamp.jackpot.domain;

import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;

@MappedSuperclass
@EntityListeners(value = {AutoCloseable.class})
@Getter
abstract class BaseEntity {
}
