package com.bitcamp.jackpot.util;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RedisUtil {
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisTemplate<String, Object> redisBlackListTemplate;

    // Serializer 설정을 별도의 메서드로 분리하여 한 번만 설정
    private void setSerializer(RedisTemplate<String, Object> template, Class<?> clazz) {
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(clazz));
    }

    public void set(String key, Object o, int minutes) {
        if (o != null) {
            setSerializer(redisTemplate, o.getClass());
            redisTemplate.opsForValue().set(key, o, minutes, TimeUnit.MINUTES);
        }
    }

    public Object get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public boolean delete(String key) {
        return redisTemplate.delete(key);
    }

    public boolean hasKey(String key) {
        return redisTemplate.hasKey(key);
    }

    public void setBlackList(String key, Object o, long milliSeconds) {
        if (o != null) {
            setSerializer(redisBlackListTemplate, o.getClass());
            redisBlackListTemplate.opsForValue().set(key, o, milliSeconds, TimeUnit.MILLISECONDS);
        }
    }

    public Object getBlackList(String key) {
        return redisBlackListTemplate.opsForValue().get(key);
    }

    public boolean isValueEqual(String key, Object expectedValue) {
        Object storedValue = get(key);
        if (storedValue == null) {
            return false;
        }
        return storedValue.equals(expectedValue);
    }


    public boolean hasKeyBlackList(String key) {

        return redisBlackListTemplate.hasKey(key);
    }

}
