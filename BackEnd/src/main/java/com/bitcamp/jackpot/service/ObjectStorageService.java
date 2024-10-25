package com.bitcamp.jackpot.service;

import org.springframework.web.multipart.MultipartFile;

public interface ObjectStorageService {
    String uploadFile(String directoryPath, MultipartFile file);
}
